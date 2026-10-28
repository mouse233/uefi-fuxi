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
    extra = ("m3-transport-tests.json",) if (candidate.get("m3_bridge_call") or
                                            candidate.get("m3_metadata_key")) else ()
    if candidate.get("m3_bridge_blob"):
        extra += ("m3-blob-tests.json",)
    if candidate.get("m3_smci_root"):
        extra += ("m3-smci-tests.json",)
    for filename in ("report-cache-tests.json", "ufs-core-tests.json", "data-port-tests.json") + extra:
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
    if candidate.get("m3_bridge_call") and not candidate.get("m3_smci_root"):
        assert candidate["m3_scm_info"] and candidate["diagnostic_park_before_usb"]
        assert candidate["m3_bridge_ops"] == ["enable", "create", "delete"]
        for marker in ("FUXIM3 BRIDGE page phys=%lx bytes=%x",
                       "FUXIM3 BRIDGE enable begin x0=%lx x1=%lx (no hardware timeout)",
                       "FUXIM3 BRIDGE enable return a0=%lx a1=%lx a2=%lx a3=%lx",
                       "FUXIM3 BRIDGE create begin x0=%lx arg0=%lx arg1=%lx arg2=%lx arg3=%lx",
                       "FUXIM3 BRIDGE create return a0=%lx a1=%lx a2=%lx a3=%lx",
                       "FUXIM3 BRIDGE delete begin handle=%x",
                       "FUXIM3 BRIDGE delete return a0=%lx a1=%lx a2=%lx a3=%lx",
                       "FUXIM3 BRIDGE retained: create/delete unresolved handle=%x bytes=%x",
                       "FUXIM3 BRIDGE released bytes=%x"):
            assert marker.encode("utf-16-le") in ufs, marker
    if candidate.get("m3_bridge_blob"):
        assert candidate["m3_bridge_call"] and candidate["m3_bridge_bytes"] == 8192
        assert candidate["m3_blob_bytes"] == 208 and candidate["m3_blob_prefix_bytes"] == 32
        assert candidate["m3_blob_sha256"] == "9a57f01af0b8c9836cdf04f9abc2f83ad21baf94527b2c80b18b06f04ab2321e"
        assert "/vold/metadata_encryption/key/keymaster_key_blob".encode() in ufs
        for marker in ("FUXIM3 BLOB page-sha256=%s bytes=%u match=1",
                       "FUXIM3 BLOB prefix32=%s",
                       "FUXIM3 BLOB read=%r; registered page, no TA, no decrypt",
                       "FUXIM3 BLOB result=%r delete=%r handle=%x; no TA, no decrypt"):
            assert marker.encode("utf-16-le") in ufs, marker
    if candidate.get("m3_smci_root"):
        assert candidate["m3_bridge_call"] and candidate["m3_scm_invoke"] and park
        assert candidate["m3_bridge_bytes"] == 8192 and candidate["m3_smci_no_keys"]
        assert not candidate["m3_bridge_blob"] and not candidate["m3_metadata_key"]
        assert candidate["m3_smci_fnid"] == "72000600" and candidate["m3_smci_arginfo"] == "224"
        assert candidate["m3_smci_ops"] == ["root-register-null", "remote-release"]
        for marker in ("FUXIM3 SMCI %a begin x0=%lx x1=%lx in=%lx out=%lx handle=%x op=%x counts=%x",
                       "FUXIM3 SMCI %a return a0=%lx a1=%lx a2=%lx a3=%lx",
                       "FUXIM3 SMCI remote-object=%x; root register only",
                       "FUXIM3 SMCI object-release=Success handle=%x",
                       "FUXIM3 SMCI bridge-delete return a0=%lx a1=%lx",
                       "FUXIM3 SMCI retained bridge=%x object=%x; unknown/error state, no retry",
                       "FUXIM3 SMCI result=%r retained=%u; no TA, no key, no decrypt"):
            assert marker.encode("utf-16-le") in ufs, marker
        assert "FUXIM3 BLOB prefix32=%s".encode("utf-16-le") not in ufs
    if candidate.get("m3_metadata_key"):
        assert candidate["m2_metadata_files"] and park
        assert candidate["m3_key_paths"] == ["/vold", "/vold/metadata_encryption",
                                             "/vold/metadata_encryption/key"]
        assert candidate["m3_key_file_limit"] == 8192
        for marker in ("FUXIM3 KEY prepare=%r pack=%u feature=%08x",
                       "FUXIM3 KEY dir=%a open=%r",
                       "FUXIM3 KEY file=%a mode=%04x bytes=%lu inline=%u",
                       "FUXIM3 KEY sha256=%a %s",
                       "FUXIM3 KEY result=%r hashed=%u total=%u; no key use, no SMC, no decrypt"):
            assert marker.encode("utf-16-le") in ufs, marker
    if candidate.get("m3_crypto_cap"):
        for marker in ("FUXIM3 crypto-cap status=%r ccap=%08x advertised=%u read=%u", "FUXIM3 crypto-cap[%u]=%08x", "FUXIM3 crypto-xts4096 select=%r index=%u"):
            assert marker.encode("utf-16-le") in ufs
    if candidate.get("m3_scm_info"):
        for marker in ("FUXIM3 SCM64 INFO begin (one call; no hardware timeout)", "FUXIM3 SCM64 INFO return a0=%lx a1=%lx decode=%r available=%u"):
            assert marker.encode("utf-16-le") in ufs
    if candidate.get("m3_scm_subjects") or candidate.get("m3_scm_invoke") or candidate.get("m3_scm_bridge"):
        assert candidate.get("m3_scm_info")
        for marker in ("FUXIM3 SCM64 subject=%08x begin", "FUXIM3 SCM64 subject=%08x a0=%lx a1=%lx decode=%r available=%u"):
            assert marker.encode("utf-16-le") in ufs
    assert b"USBRAM: cached UFS report unavailable" in receiver
    protocol = uuid.UUID("6d8c0fc1-6c29-4df2-b7d1-845e1b4cf209").bytes_le
    assert protocol in ufs and protocol in receiver
    objdump = shutil.which("llvm-objdump") or shutil.which("llvm-objdump-18")
    assert objdump, "llvm-objdump required for SMC audit"
    smc = {}
    for name in ("FuxiNativeUfsDxe.efi", "modules-no-smc/FuxiNativeUfsDxe.efi", "modules-scm-query/FuxiNativeUfsDxe.efi"):
        disassembly = subprocess.check_output([objdump, "-d", str(out / name)], text=True)
        smc[name] = sum(bool(re.search(r"\bsmc\s+#", line)) for line in disassembly.splitlines())
        if candidate.get("m3_bridge_call") and name == "FuxiNativeUfsDxe.efi":
            assert smc[name] >= 1, name
        else:
            expected_smc = 1 if candidate.get("m3_scm_info") and name == "FuxiNativeUfsDxe.efi" else 0
            assert smc[name] == expected_smc, name
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
