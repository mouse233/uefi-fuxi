#!/usr/bin/env python3
"""Offline, fixed-binary prerequisites for ONE metadata crypto read.

Only synthetic public CBOR tags/structures are supplied to Unicorn. No real
key/blob, Android command, SMC, keyslot operation or device I/O is accepted.
The TA decoder/version gate runs; export itself is intercepted and STOPPED.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1,
    UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X30,
)

TA_SHA = "2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6"
RECOVERY_SHA = "9aa603b1b2851df9c773c153f7df4520b7c634be0c15bc55f43c2fb83b82e4b0"
MODULES = {
    "hwkm.ko": "abc7af9de664efa1ca2ddda980acf2c58021da9180974153818ecc29dc2a450a",
    "crypto-qti-hwkm.ko": "be67c86de45b02bfc9e00089c6b49899c1d2579e7db2860e684b186cf22e866d",
    "ufshcd-crypto-qti.ko": "02ed3dd34b22ecde458bef3644906ae42b4192be039dbc1dc12e7f0abdbca538",
    "qcom-scm.ko": "8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5",
}
BASE = 0x1000000
SCRATCH = 0x3000000
CONTEXT = SCRATCH + 0x1000
INPUT = SCRATCH + 0x4000
STOP = SCRATCH + 0xF000
MAX_INSTRUCTIONS = 50000


def checked_inputs(partition: Path, modules: Path, recovery: Path) -> bytes:
    raw = partition.read_bytes()
    if len(raw) != 524288 or hashlib.sha256(raw).hexdigest() != TA_SHA:
        raise ValueError("fixed keymaster partition SHA256/length mismatch")
    for name, digest in MODULES.items():
        if hashlib.sha256((modules / name).read_bytes()).hexdigest() != digest:
            raise ValueError("fixed module SHA256 mismatch: " + name)
    if hashlib.sha256(recovery.read_bytes()).hexdigest() != RECOVERY_SHA:
        raise ValueError("fixed recovery SHA256 mismatch")
    return raw


def machine(raw: bytes):
    """Relocate PT_LOAD into private emulator memory, never native execution."""
    if (len(raw) != 524288 or hashlib.sha256(raw).hexdigest() != TA_SHA or
            raw[:7] != b"\x7fELF\x02\x01\x01" or
            struct.unpack_from("<H", raw, 18)[0] != 183):
        raise ValueError("fixed AArch64 TA required")
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    ents, count = struct.unpack_from("<HH", raw, 54)
    if ents != 56 or count > 32 or phoff + ents * count > len(raw):
        raise ValueError("invalid ELF table")
    emu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    emu.mem_map(BASE, 0x80000)
    emu.mem_map(SCRATCH, 0x20000)
    emu.mem_map(0x4000000, 0x20000)
    emu.fuxi_code_ranges = []
    for i in range(count):
        kind, flags, off, va, _pa, size, memsize, _align = struct.unpack_from(
            "<IIQQQQQQ", raw, phoff + ents * i)
        if kind == 1:
            if off + size > len(raw) or size > memsize or va + memsize > 0x80000:
                raise ValueError("invalid ELF segment")
            emu.mem_write(BASE + va, raw[off:off + size])
            if flags & 1:
                emu.fuxi_code_ranges.append((va, va + size))
    # Synthetic stack guard and current-client index for real TA accessors.
    emu.mem_write(BASE + 0x5A2F8, struct.pack("<Q", SCRATCH + 0x100))
    emu.mem_write(BASE + 0x5A308, struct.pack("<Q", SCRATCH + 0x108))
    emu.reg_write(UC_ARM64_REG_SP, 0x401F000)
    emu.reg_write(UC_ARM64_REG_X30, STOP)
    return emu


def execute(emu, entry: int, *, stop_on_export=False):
    observed = {"logs_suppressed": 0, "export_reached": False,
                "instructions": 0, "gate_getters": []}

    def hook(u, address, _size, _unused):
        observed["instructions"] += 1
        pc = address - BASE
        if not any(lo <= pc < hi for lo, hi in u.fuxi_code_ranges):
            raise ValueError("execution outside fixed TA code: " + hex(address))
        if pc == 0x43A30:
            if not stop_on_export:
                raise ValueError("unexpected export call")
            observed["export_reached"] = True
            u.emu_stop()  # NEVER substitute successful key export.
            return
        if pc in (0xB82C, 0xB850, 0xB8AC, 0xB940):
            observed["gate_getters"].append(hex(pc))
        word = struct.unpack("<I", u.mem_read(address, 4))[0]
        if word == 0xDAC107FE:  # PACIB x30,sp: control-flow model only.
            u.reg_write(UC_ARM64_REG_PC, address + 4)
        elif word == 0xD65F0FFF:  # RETAB with untagged synthetic LR.
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_X30))
        elif pc == 0x20:  # Suppress logging; no key or payload is captured.
            observed["logs_suppressed"] += 1
            u.reg_write(UC_ARM64_REG_X0, 0)
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_X30))
        elif word & 0xFFE0001F in (0xD4000001, 0xD4000002, 0xD4000003):
            raise ValueError("SVC/HVC/SMC forbidden in offline audit")

    emu.hook_add(UC_HOOK_CODE, hook)
    emu.emu_start(BASE + entry, STOP, count=MAX_INSTRUCTIONS)
    if not observed["export_reached"] and emu.reg_read(UC_ARM64_REG_PC) != STOP:
        raise ValueError("instruction bound reached without terminal state")
    result = emu.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
    observed["status"] = None if observed["export_reached"] else (
        result - (1 << 32) if result & (1 << 31) else result)
    return observed


def uint(value: int) -> bytes:
    if value < 24:
        return bytes([value])
    if value < 256:
        return b"\x18" + bytes([value])
    return b"\x1a" + value.to_bytes(4, "big")


def decode_synthetic_tag(raw: bytes, tag: int):
    # Synthetic key-authorization map, not a real wrapped key or blob.
    payload = b"\xa2\x01\xa1" + uint(tag) + b"\xf5\x00\xa0"
    emu = machine(raw)
    emu.mem_write(INPUT, payload)
    emu.reg_write(UC_ARM64_REG_X0, INPUT)
    emu.reg_write(UC_ARM64_REG_X1, len(payload))
    emu.reg_write(UC_ARM64_REG_X2, CONTEXT)
    result = execute(emu, 0x304DC)
    result.update(tag=hex(tag), fbe_flag=int(emu.mem_read(CONTEXT + 0x1D4, 1)[0]))
    return result


def version_gate(raw: bytes, fbe: bool, runtime, stored, version=0x400000005):
    emu = machine(raw)
    emu.mem_write(CONTEXT + 0x1D4, bytes([int(fbe)]))
    emu.mem_write(CONTEXT + 8, struct.pack("<Q", version))
    for offset, value in zip((0x144, 0x14C, 0x1C0, 0x1B8), stored):
        emu.mem_write(CONTEXT + offset, struct.pack("<I", value))
    # Real get-OS/get-patch accessors read these synthetic client-0 slots.
    for offset, value in zip((0x5B4F0, 0x5B4F8, 0x5B4F4, 0x5B4FC), runtime):
        emu.mem_write(BASE + offset, struct.pack("<I", value))
    emu.reg_write(UC_ARM64_REG_X0, CONTEXT)
    result = execute(emu, 0x98C0)
    result.update(fbe=fbe, runtime=list(runtime), stored=list(stored),
                  blob_version=hex(version))
    return result


def export_gate(raw: bytes, fbe: bool):
    emu = machine(raw)
    emu.mem_write(CONTEXT + 0x1D4, bytes([int(fbe)]))
    emu.reg_write(UC_ARM64_REG_X0, 3)
    emu.reg_write(UC_ARM64_REG_X1, CONTEXT)
    emu.reg_write(UC_ARM64_REG_X2, INPUT)
    emu.reg_write(UC_ARM64_REG_X3, 0x800)
    emu.reg_write(UC_ARM64_REG_X4, SCRATCH + 0x200)
    result = execute(emu, 0x1FFC, stop_on_export=True)
    result["fbe"] = fbe
    return result


def disassemble(objdump: str, path: Path, start: int, end: int):
    proc = subprocess.run([objdump, "-dr", f"--start-address={start}",
                           f"--stop-address={end}", str(path)],
                          check=True, capture_output=True, text=True)
    return proc.stdout


def audit(partition: Path, modules: Path, recovery: Path, output: Path, objdump: str):
    raw = checked_inputs(partition, modules, recovery)
    output.mkdir(parents=True, exist_ok=True)
    ranges = {
        "convert": (partition, 0x29DF0, 0x29F78, [r"bl 0x36620", r"bl 0x1ffc"]),
        "convert-decode": (partition, 0x36620, 0x367AC, [r"bl 0x310a8"]),
        "unpack-wrapper": (partition, 0x31040, 0x310BC, [r"bl 0x30d9c"]),
        "unpack": (partition, 0x30D9C, 0x31040, [r"bl 0x304dc", r"bl 0x98c0"]),
        "version-gate": (partition, 0x98C0, 0x9A5C, [r"ldrb w8, \[x0, #0x1d4\]", r"bl 0xb82c"]),
        "fbe-tag": (partition, 0x308AC, 0x308CC, [r"mov w8, #0x2d2", r"b.eq 0x30a3c"]),
        "fbe-flag": (partition, 0x30A3C, 0x30A44, [r"strb w26, \[x19, #0x1d4\]"]),
        "request-fbe-name": (partition, 0x32D14, 0x32D40, [
            r"mov w9, #0x3f49", r"add x1, x1, #0x846", r"strb w8, \[x20, #0x1d4\]"]),
        "export-gate": (partition, 0x1FFC, 0x2088, [r"ldrb w8, \[x1, #0x1d4\]", r"bl 0x43a30"]),
        "hwkm-init": (modules / "hwkm.ko", 0x1D4, 0x4FC, [
            r"mov w9, #0x1004", r"tbz w0, #0x9", r"tbz w0, #0x7",
            r"tbz w0, #0x2", r"tbz w0, #0x1", r"tbz w0, #0x0",
            r"mov w0, #0x18c", r"R_AARCH64_CALL26 qti_hwkm_handle_cmd"]),
        "ice-program": (modules / "crypto-qti-hwkm.ko", 0x23C, 0x45C, [
            r"qti_hwkm_init", r"lsl w24, w22, #1", r"qcom_scm_config_set_ice_key"]),
        "ice-clear": (modules / "crypto-qti-hwkm.ko", 0x4D8, 0x56C, [
            r"cmp w8, #0x1", r"qcom_scm_clear_ice_key"]),
        "scm-set": (modules / "qcom-scm.ko", 0x5518, 0x5610, [r"mov w8, #0x86"]),
        "scm-extended": (modules / "qcom-scm.ko", 0x89E8, 0x8AF0, [
            r"qtee_shmbridge_allocate_shm", r"mov w0, #0x38", r"str x9, \[x8, #0x10\]"]),
        # Names on anonymous functions are nearest dynamic symbol labels,
        # NOT reliable identities. Bind addresses, strings and actual calls.
        "metadata-retrieve": (recovery, 0x253354, 0x2533B4, [
            r"add x4, sp, #0x30", r"bl 0x24f434", r"add x2, sp, #0x30", r"bl 0x253d78"]),
        "metadata-export": (recovery, 0x253D78, 0x253E40, [
            r"mov x24, x2", r"mov x0, x24", r"bl 0x248458"]),
        "retrieve-existing": (recovery, 0x24F434, 0x24F4E0, [
            r"bl 0x24aef4", r"bl 0x24d608", r"bl 0x24a1ac"]),
        "retrieve-key": (recovery, 0x24AEF4, 0x24BA0C, [
            r"bl 0x248948", r"add x1, x1, #0x874", r"bl 0x24ba0c"]),
        "keymaster-decrypt": (recovery, 0x24BA0C, 0x24BE50, [
            r"bl 0x24c750", r"bl 0x24fae8"]),
        "keymaster-read-begin-write": (recovery, 0x24C984, 0x24CCC0, [
            r"add x22, x22, #0x9dd", r"bl 0x250ee4", r"bl 0x25d890"]),
        "wrapped-export": (recovery, 0x248458, 0x248630, [r"bl 0x250960"]),
    }
    evidence = {}
    for name, (path, start, end, patterns) in ranges.items():
        asm = disassemble(objdump, path, start, end)
        normalized = re.sub(r"[\t ]+", " ", asm)
        for pattern in patterns:
            if not re.search(pattern, normalized):
                raise ValueError(name + " missing fixed instruction: " + pattern)
        (output / (name + ".asm")).write_text(asm)
        evidence[name] = dict(start=hex(start), end=hex(end),
                              sha256=hashlib.sha256(asm.encode()).hexdigest())

    tags = [decode_synthetic_tag(raw, t) for t in (0x700002D2, 0x70000007)]
    if [(x["status"], x["fbe_flag"]) for x in tags] != [(0, 1), (0, 0)]:
        raise ValueError("unexpected synthetic authorization decode")
    name = b"KM_TAG_FBE_ICE - using FBE ICE\0"
    if bytes(machine(raw).mem_read(BASE + 0x55846, len(name))) != name:
        raise ValueError("fixed FBE diagnostic string reference changed")
    values = (170000, 202610, 202610, 202610)
    versions = [version_gate(raw, True, (0, 0, 0, 0), values),
                version_gate(raw, False, (0, 0, 0, 0), values),
                version_gate(raw, False, values, values)]
    if [x["status"] for x in versions] != [0, -62, 0]:
        raise ValueError("unexpected real TA version gate")
    exports = [export_gate(raw, f) for f in (False, True)]
    if exports[0]["status"] != -17 or not exports[1]["export_reached"]:
        raise ValueError("unexpected real TA export gate")

    recovery_raw = recovery.read_bytes()
    # For this fixed ELF the containing PT_LOAD has file offset == VA here.
    for va, value in ((0x42874, b"encrypted_key\0"), (0x2C9DD, b"keymaster_key_blob\0")):
        if recovery_raw[va:va + len(value)] != value:
            raise ValueError("fixed recovery filename reference changed")
    root = Path(__file__).resolve().parents[1]
    sources = [Path(__file__),
               root / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/UfsCore.c",
               root / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/M3DefaultKeyPlan.c",
               root / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3BridgeBlob.inc"]
    core = sources[1].read_text()
    submit = core.split("EFI_STATUS FnuSubmit(", 1)[1].split("STATIC EFI_STATUS FnuScsiRun", 1)[0]
    if "FnuFillUtrd(Dev->Dma, Dev->DmaPhys, Direction, DataBytes);" not in submit:
        raise ValueError("UFS submission changed; repeat interface analysis")
    fill = core.split("VOID FnuFillUtrd(", 1)[1].split("VOID FnuFillCommandUpiu", 1)[0]
    for assignment in ("Words[0] = 0x10000000U | (Direction << 25);",
                       "Words[1] = 0;", "Words[3] = 0;"):
        if assignment not in fill:
            raise ValueError("UTRD rebuild changed; repeat crypto-context analysis")
    report = dict(
        result="passed", partition_sha256=TA_SHA, modules_sha256=MODULES,
        recovery_sha256=RECOVERY_SHA,
        evidence=evidence, synthetic_authorization_decode=tags,
        synthetic_version_gate=versions, synthetic_export_gate=exports,
        configure_dependency="not established for whole flow; FBE branch bypasses local version gate",
        key_recovery=dict(
            wrapped_export_input="retrieveOrGenerateKey output vector at sp+0x30",
            keymaster_key_blob_is_not_established_as_storage_key=True,
            recovery_read_path_includes_file_write=True,
            uefi_unseal_implemented=False,
            required_policy="existing-key only; reject generation, upgrade/persist and unknown errors"),
        ufs_submission=dict(explicit_crypto_context=False,
                            rebuilds_utrd_before_cache_and_doorbell=True,
                            outer_crypto_prefill_would_be_lost=True),
        hardware_read_ready=False, configure_sent=False,
        scope="Fixed TA instructions with synthetic non-secret input. PAC modeled, logs suppressed. "
              "Export intercepted before execution. No real key/blob, device, SMC or hardware decryption.",
        remaining=["retrieveKey/unseal path and actual authenticated blob attributes",
                   "bounded convert exchange and opaque output lifecycle",
                   "HWKM base/clock/readiness and owned slot with confirmed clear",
                   "six-argument SCM registered extended buffer and terminal result",
                   "explicit crypto context through UFS submission; actual format binding",
                   "same-comparable-state raw/plaintext block digest reference"],
        sources={str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
    )
    (output / "audit.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--partition", type=Path, required=True)
    parser.add_argument("--modules", type=Path, required=True)
    parser.add_argument("--recovery", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--objdump", default="llvm-objdump")
    args = parser.parse_args()
    report = audit(args.partition, args.modules, args.recovery, args.output, args.objdump)
    print(json.dumps({k: report[k] for k in ("result", "configure_dependency", "hardware_read_ready")}, indent=2))


if __name__ == "__main__":
    main()
