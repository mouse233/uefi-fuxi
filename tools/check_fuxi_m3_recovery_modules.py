#!/usr/bin/env python3
"""Check module compilation/source binding without claiming a bootable image."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--llvm", type=Path, default=Path("/opt/homebrew/opt/llvm/bin"))
    parser.add_argument("--keymint-backend", action="store_true", help="also qualify the compiled wire backend")
    parser.add_argument("--secret-exchange", action="store_true", help="qualify off/query/enabled transport objects and import whitelist")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    rows = []
    modes=[("modules-no-smc-final",False,False),("modules-scm-query",True,False)]
    if args.secret_exchange:modes.append(("modules-secret-exchange",False,True))
    transport_objects=[]
    for mode, query, secret in modes:
        base = args.output / mode
        report = json.loads((base / "build.json").read_text())
        if (report["exit_code"] != 0 or report["target_architecture"] != "AARCH64" or
                report["scm_queries_enabled"] != query or report["boot_image"]):
            raise ValueError("unexpected module qualification mode")
        if report.get("secret_exchange_compiled",False)!=secret:raise ValueError("unexpected secret exchange gate")
        for source, digest in report["sources"].items():
            if hashlib.sha256((root / source).read_bytes()).hexdigest() != digest:
                raise ValueError("module source changed: " + source)
        for name, module in report["modules"].items():
            binary = base / (name + ".efi")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            if digest != module["sha256"]:
                raise ValueError("module binary changed")
            asm = subprocess.check_output([str(args.llvm / "llvm-objdump"), "-d", str(binary)], text=True)
            smc = len(re.findall(r"\bsmc\s", asm))
            expected = int(query and name == "FuxiDataProbeDxe")
            if smc != expected:
                raise ValueError("unexpected SMC instruction count")
            rows.append(dict(mode=mode, module=name, sha256=digest, smc_instructions=smc))
        if args.secret_exchange:
            bound=report["secret_exchange_object"];obj=base/bound["file"]
            if hashlib.sha256(obj.read_bytes()).hexdigest()!=bound["sha256"]:raise ValueError("exchange object changed")
            nm=subprocess.check_output([str(args.llvm/"llvm-nm"),str(obj)],text=True)
            for symbol in ("FseInitialize","FseExchange","FsePermitCleanup"):
                if not re.search(r"\bT "+symbol+r"$",nm,re.M):raise ValueError("exchange definition absent")
            imports=set(re.findall(r"\bU (\S+)$",nm,re.M))
            expected={"ArmCallSmc","WriteBackInvalidateDataCacheRange","InvalidateDataCacheRange"} if secret else set()
            if imports!=expected:raise ValueError("exchange import/gate mismatch: "+repr(imports))
            transport_objects.append(dict(mode=mode,enabled=secret,sha256=bound["sha256"],undefined_symbols=sorted(imports)))
    objbase = root / "Build/FuxiDataPort/DEBUG_CLANGPDB/AARCH64/fuxiPkg/Drivers/FuxiNativeUfsDxe/FuxiNativeUfsDxe/OUTPUT/FuxiDataProbeDxe"
    symbols = {"M3KeyRecovery": ["FkrPrepare", "FkrRecoverExisting", "FkrGetRecovered", "FkrReset"],
               "M3Secdiscardable": ["FkrHashSecdiscardable"],
               "M3KeyRecoveryF2fs": ["FkrReadF2fsFile"]}
    imports = {"M3KeyRecovery": {"FkrHashSecdiscardable"}, "M3Secdiscardable": set(),
               "M3KeyRecoveryF2fs": {"F2rLookup", "F2rReadFile"}}
    if args.keymint_backend:
        symbols["M3KeyMintBackend"] = ["FkmEncode", "FkmDecode", "FkmInitialize"]
        imports["M3KeyMintBackend"] = set()
    object_rows = []
    for name, names in symbols.items():
        path = objbase / (name + ".obj")
        nm = subprocess.check_output([str(args.llvm / "llvm-nm"), str(path)], text=True)
        for symbol in names:
            if not re.search(r"\bT " + symbol + r"$", nm, re.MULTILINE):
                raise ValueError("recovery function not compiled: " + symbol)
        undefined = set(re.findall(r"\bU (\S+)$", nm, re.MULTILINE))
        if undefined != imports[name]:
            raise ValueError("unexpected library dependency: " + name + " " + repr(undefined))
        object_rows.append(dict(object=str(path.relative_to(root)),
                                sha256=hashlib.sha256(path.read_bytes()).hexdigest(), definitions=names,
                                undefined_symbols=sorted(undefined)))
    report = dict(result="passed", modules=rows, compiled_objects=object_rows,
                  keymint_backend_compiled=args.keymint_backend,
                  secret_exchange_objects=transport_objects,
                  scope="AARCH64 library/object compilation only. No live recovery entrypoint, registered app/bridge session or phone test.",
                  checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (args.output / "module-checks.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": "passed", "modules": len(rows), "compiled_objects": len(object_rows)}, indent=2))


if __name__ == "__main__":
    main()
