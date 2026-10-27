#!/usr/bin/env python3
"""Bind the cached UFS report and its actual EFI to the delivered boot image."""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import re
import shutil
import struct
import subprocess
import uuid

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    candidate = json.loads((out / "candidate.json").read_text())
    verified = json.loads((out / "verification.json").read_text())
    image = out / "Mu-fuxi-ufs-m1.img"
    assert sha(image) == candidate["sha256"] == verified["boot_sha256"]
    park=bool(candidate.get("diagnostic_park_before_usb"))
    assert candidate["ufs_report_cached"]
    assert candidate["ufs_report_replay_at_receiver_park"] == (not park)
    assert not candidate["kernel_handoff"]
    assert candidate["receiver_only"] == (not park)
    if park:
        assert candidate["diagnostic_only"] and candidate["m2_metadata_files"]
        assert not candidate["receiver_runtime_enabled"]
        assert candidate["m2_target_path"] == "/aconfig/maps/system.package.map"
        assert candidate["m2_reference_bytes"] == 10527
        assert candidate["m2_reference_sha256"] == "14f3d8675423917e383a71c936f4d9a81a29480f34ae3c550e0f4c34e53a0991"
    assert 0 <= candidate["ufs_report_hold_seconds"] <= 60
    sources = verified["source_sha256"]
    for name, digest in sources.items():
        assert sha(root / name) == digest, name
    for filename in ("report-cache-tests.json", "ufs-core-tests.json", "data-port-tests.json"):
        report = json.loads((out / filename).read_text())
        assert report["result"] == "passed"
        for name, digest in report["sources"].items():
            assert sha(root / name) == digest, name
            if name in sources:
                assert sources[name] == digest
    fd = (out / "SILICIUM_UEFI.fd").read_bytes()
    assert hashlib.sha256(fd).hexdigest() == verified["fd_sha256"]
    guid = uuid.UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf").bytes_le
    at, inner = 0, None
    while True:
        at = fd.find(guid, at)
        if at < 0:
            break
        start = at - 4
        length = int.from_bytes(fd[start:start + 3], "little")
        offset = struct.unpack_from("<H", fd, at + 16)[0]
        at += 16
        if fd[start + 3] == 2 and 24 <= offset < length and start + length <= len(fd):
            try:
                inner = lzma.decompress(fd[start + offset:start + length])
                break
            except lzma.LZMAError:
                pass
    assert inner is not None
    ufs = (out / "FuxiNativeUfsDxe.efi").read_bytes()
    receiver = (out / "FuxiUsbRamDxe.efi").read_bytes()
    assert ufs in inner and receiver in inner
    for marker in ("FUXIUFS CACHED REPORT BEGIN (no new UFS IO)", "FUXIUFS REPORT INCOMPLETE dropped=%u truncated=%u"):
        assert marker.encode("utf-16-le") in ufs
    if park:
        assert candidate["m2_target_path"].encode("ascii") in ufs
        for marker in ("FUXIM2 PARK: no USB receiver; no handoff", "FUXIM2 file-sha256=%s", "FUXIM2 prepare=%r"):
            assert marker.encode("utf-16-le") in ufs
        order=(root/"Platforms/Xiaomi/fuxiPkg/Include/APRIORI.inc").read_text()
        assert "FuxiNativeUfsDxe.inf" in order and "UsbfnDwc3Dxe.inf" not in order and "FuxiUsbRamDxe.inf" not in order
        for filename in ("m2-file-tests.json", "m2-tools-tests.json", "m2-draft-tests.json"):
            test=json.loads((out/filename).read_text());assert test["result"]=="passed"
            for name,digest in test["sources"].items():assert sha(root/name)==digest,name
    assert b"USBRAM: cached UFS report unavailable" in receiver
    protocol = uuid.UUID("6d8c0fc1-6c29-4df2-b7d1-845e1b4cf209").bytes_le
    assert protocol in ufs and protocol in receiver
    objdump = shutil.which("llvm-objdump") or shutil.which("llvm-objdump-18")
    assert objdump, "llvm-objdump required for SMC audit"
    smc = {}
    for name in ("FuxiNativeUfsDxe.efi", "modules-no-smc/FuxiNativeUfsDxe.efi", "modules-scm-query/FuxiNativeUfsDxe.efi"):
        disassembly = subprocess.check_output([objdump, "-d", str(out / name)], text=True)
        smc[name] = sum(bool(re.search(r"\bsmc\s+#", line)) for line in disassembly.splitlines())
        assert smc[name] == 0, name
    report = dict(result="passed", boot_sha256=sha(image), ufs_efi_sha256=sha(out/"FuxiNativeUfsDxe.efi"),
                  ufs_efi_in_delivered_fd=True, report_protocol_in_both_modules=True,
                  replay_marker_in_delivered_modules=True, smc_instructions=smc,
                  diagnostic_park_before_usb=park,
                  source_files_checked=len(sources), checker_sha256=sha(Path(__file__)),
                  ufs_report_hold_seconds=candidate["ufs_report_hold_seconds"], hardware_result="pending")
    (out / "report-image-tests.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
