#!/usr/bin/env python3
"""Compile the default-off data-port module in the Linux cross-build container.

This produces an EFI driver and source binding, not a boot image. No firmware
submodule, shared platform build, phone, or device partition is modified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edk2", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scm-query", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in ("aarch64", "arm64", "x86_64", "AMD64"):
        parser.error("UEFI compilation must run in unixnu-fuxi-build-arm64")
    workspace = Path(__file__).resolve().parents[1]
    edk2 = args.edk2.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    conf = out / "conf"
    conf.mkdir(exist_ok=True)
    tools = edk2 / "BaseTools"
    if not (tools / "Source/C/bin/GenFw").is_file():
        raise SystemExit("Expected already-built Linux BaseTools; shared dependencies are read-only")
    for name in ("target", "tools_def", "build_rule"):
        shutil.copyfile(tools / "Conf" / (name + ".template"), conf / (name + ".txt"))
    env = dict(os.environ)
    env.update(WORKSPACE=str(workspace), EDK_TOOLS_PATH=str(tools),
               CONF_PATH=str(conf), PYTHON_COMMAND="python3",
               PACKAGES_PATH=":".join(map(str, (workspace, workspace / "Platforms/Xiaomi",
                                                workspace / "Silicon/Qualcomm", edk2))),
               PATH=":".join((str(tools / "BinWrappers/PosixLike"),
                              str(tools / "Source/C/bin"), env["PATH"])))
    env.setdefault("CLANG_BIN", str(Path(shutil.which("clang")).parent) + "/")
    env.setdefault("SOURCE_DATE_EPOCH", subprocess.check_output(
        ["git", "-c", f"safe.directory={workspace}", "-C", str(workspace),
         "log", "-1", "--format=%ct"], text=True).strip())
    command = ["build", "-p", "Platforms/Xiaomi/fuxiPkg/DataPort.dsc", "-a", "AARCH64",
               "-b", "DEBUG", "-t", "CLANGPDB", "-n", "4",
               "-D", f"FUXI_DATA_SCM_QUERY={int(args.scm_query)}"]
    with (out / "build.log").open("w") as log:
        result = subprocess.run(command, cwd=workspace, env=env,
                                stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        print((out / "build.log").read_text()[-16000:])
        raise SystemExit(result.returncode)
    artifact = workspace / "Build/FuxiDataPort/DEBUG_CLANGPDB/AARCH64/FuxiDataProbeDxe.efi"
    destination = out / artifact.name
    shutil.copyfile(artifact, destination)
    modules = {}
    for name in ("FuxiDataProbeDxe", "FuxiNativeUfsDxe"):
        source = artifact.with_name(name + ".efi")
        target = out / source.name
        shutil.copyfile(source, target)
        modules[name] = dict(path=str(target), bytes=target.stat().st_size,
                             sha256=hashlib.sha256(target.read_bytes()).hexdigest())
    source_paths = [workspace / "Platforms/Xiaomi/fuxiPkg/DataPort.dsc", Path(__file__),
                    workspace / "Platforms/Xiaomi/fuxiPkg/Include/Protocol/FuxiUfsReport.h",
                    *sorted((workspace / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe").glob("*")),
                    *sorted((workspace / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe").glob("*"))]
    report = dict(host_architecture=platform.machine(), target_architecture="AARCH64",

        modules=modules, module=str(destination), sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
        bytes=destination.stat().st_size, scm_queries_enabled=args.scm_query,
        hardware_result="not tested", boot_image=False, native_ufs_takeover=False,
        data_decryption=False, data_file_read=False,
        sources={str(path.relative_to(workspace)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in source_paths if path.is_file()},
        command=command, exit_code=result.returncode,
    )
    (out / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
