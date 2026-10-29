#!/usr/bin/env python3
"""Pin recovery input/operation facts for the independent C core; no execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

PINS = {
    "recovery": "9aa603b1b2851df9c773c153f7df4520b7c634be0c15bc55f43c2fb83b82e4b0",
    "keymint": "657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb",
    "partition": "2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6",
}


def checked(paths):
    for name, digest in PINS.items():
        if hashlib.sha256(paths[name].read_bytes()).hexdigest() != digest:
            raise ValueError("fixed input SHA256 mismatch: " + name)


def elf_bytes(raw, va, size):
    if raw[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("ELF64 LE required")
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    ents, count = struct.unpack_from("<HH", raw, 54)
    if ents != 56 or count > 64 or phoff + ents * count > len(raw):
        raise ValueError("invalid ELF program table")
    for i in range(count):
        kind, _flags, off, base, _pa, filesz, _memsz, _align = struct.unpack_from("<IIQQQQQQ", raw, phoff + ents * i)
        if kind == 1 and base <= va and size <= filesz and va - base <= filesz - size:
            pos = off + va - base
            if pos + size <= len(raw):
                return raw[pos:pos + size]
    raise ValueError("requested bytes outside file-backed PT_LOAD")


def audit(paths, output, objdump):
    checked(paths)
    recovery = paths["recovery"].read_bytes()
    for va, text in ((0x32AB6, b"version\0"), (0x35F42, b"secdiscardable\0"),
                     (0x42874, b"encrypted_key\0"), (0x2C9DD, b"keymaster_key_blob\0"),
                     (0x34349, b"Android secdiscardable SHA512\0")):
        if elf_bytes(recovery, va, len(text)) != text:
            raise ValueError("fixed filename/personalization mismatch")
    readelf = str(Path(objdump).with_name("llvm-readelf")) if "/" in objdump else "llvm-readelf"
    relocations = subprocess.check_output([readelf, "-r", "--dyn-syms", str(paths["recovery"])], text=True)
    if not re.search(r"0000000000270470\s+.*R_AARCH64_RELATIVE\s+274380", relocations):
        raise ValueError("metadata empty-auth pointer relocation changed")
    if not any("274380" in line and "kEmptyAuthentication" in line for line in relocations.splitlines()):
        raise ValueError("metadata empty-auth dynamic symbol changed")
    ranges = {
        "security-level-constructor": ("keymint", 0x183F0, 0x184D0, [
            r"AndroidKeyMintDeviceC2ENS3_13SecurityLevelE", r"mov w20, w1",
            r"mov x21, x0", r"str w20, \[x21, #0x8\]"]),
        "personalized-sha512": ("recovery", 0x2487AC, 0x248948, [
            r"bl 0x26b6c0", r"mov w1, #0x80", r"bl 0x26b6d0", r"bl 0x26b6e0"]),
        "secdiscardable": ("recovery", 0x248948, 0x248A10, [r"bl 0x2487ac", r"add x0, x0, #0x349"]),
        "binding-context": ("recovery", 0x24B1C4, 0x24B358, [r"bl 0x1043f8", r"ldr x8, \[x23, #0x398\]", r"add x22, x8, #0x1c"]),
        "empty-auth-caller": ("recovery", 0x253354, 0x253374, [r"ldr x2, \[x2, #0x470\]", r"bl 0x24f434"]),
        "gcm-authorization": ("recovery", 0x268A24, 0x268CBC, [
            r"mov w24, #0x4", r"mov w8, #0x20", r"add w8, w24, #0x2", r"mov w8, #0x3eb"]),
        "application-id-tag": ("recovery", 0x24C610, 0x24C644, [r"mov w8, #0x259", r"movk w8, #0x9000"]),
        "nonce-tag": ("recovery", 0x24D1C8, 0x24D1FC, [r"mov w8, #0x3e9", r"movk w8, #0x9000"]),
        "nonce-split": ("recovery", 0x24BA40, 0x24BA9C, [r"mov w3, #0xc", r"mov w2, #0xc"]),
        "decrypt-finish": ("recovery", 0x24BD64, 0x24BD88, [r"bl 0x24ff14", r"bl 0x24fa30"]),
        "write-branch": ("recovery", 0x24C984, 0x24CC50, [r"bl 0x250ee4", r"bl 0x25d890"]),
        "begin": ("keymint", 0x2F6E0, 0x2F950, [r"mov w8, #0x210f", r"mov w9, #0x250f", r"serializeClientBegin", r"deserializeClientBegin"]),
        "update": ("keymint", 0x2F950, 0x2FBC4, [r"mov w8, #0x2111", r"mov w9, #0x2511", r"serializeClientUpdate", r"deserializeClientUpdate"]),
        "finish": ("keymint", 0x2FBC4, 0x2FE28, [r"mov w8, #0x2112", r"mov w9, #0x2512", r"serializeClientFinish", r"deserializeClientFinish"]),
        "abort": ("keymint", 0x2FE28, 0x30000, [r"mov w8, #0x2113", r"mov w9, #0x2513", r"serializeClientAbort"]),
    }
    output.mkdir(parents=True, exist_ok=True)
    evidence = {}
    for name, (source, lo, hi, patterns) in ranges.items():
        proc = subprocess.run([objdump, "-d", f"--start-address={lo}", f"--stop-address={hi}", str(paths[source])],
                              check=True, capture_output=True, text=True)
        normalized = re.sub(r"[\t ]+", " ", proc.stdout)
        for pattern in patterns:
            if not re.search(pattern, normalized):
                raise ValueError(name + " missing instruction " + pattern)
        (output / (name + ".asm")).write_text(proc.stdout)
        evidence[name] = dict(input=source, start=hex(lo), end=hex(hi), sha256=hashlib.sha256(proc.stdout.encode()).hexdigest())
    ta = paths["partition"].read_bytes()
    table = elf_bytes(ta, 0x5A5E0, 89 * 16)
    commands = {struct.unpack_from("<IIQ", table, i * 16)[0] for i in range(89)}
    command_presence = {hex(c): c in commands for c in (0x210F, 0x250F, 0x2111, 0x2511, 0x2112, 0x2512, 0x2113, 0x2513)}
    if list(command_presence.values()) != [True, False] * 4:
        raise ValueError("fixed TA recovery command table changed")
    root = Path(__file__).resolve().parents[1]
    source = root / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe"
    source_paths = [Path(__file__), *(source / n for n in ("M3KeyRecovery.c", "M3KeyRecovery.h", "M3Secdiscardable.c", "M3KeyRecoveryF2fs.c", "M3KeyRecoveryF2fs.h"))]
    report = dict(result="passed", inputs=PINS, evidence=evidence,
                  command_table_presence=command_presence, command_selection_verified=False,
                  command_selector="HalDevice+8 stores SecurityLevel constructor argument; begin also branches through isLegacy. Runtime selection and wire format remain unverified.",
                  empty_auth_pointer_relocation=dict(address="0x270470", target="0x274380", symbol="kEmptyAuthentication"),
                  recovery_contract=dict(personalization_padded_bytes=128, secdiscardable_bytes=16384,
                                         purpose=1, block_mode=32, padding=1, mac_bits=128, nonce_bytes=12,
                                         application_id_tag="0x90000259", nonce_tag="0x900003e9",
                                         application_id="personalized SHA512(secdiscardable) + auth secret + binding seed",
                                         core_subset="metadata empty authentication, explicit independently checked seed, present 16KiB secdiscardable"),
                  hardware_result="not tested", keymint_backend=False, configure_sent=False,
                  scope="Fixed local instructions/strings only. No vendor execution, real key files, phone, SMC or KeyMint decryption. Command-table membership does not authorize/validate calls.",
                  sources={str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths})
    (output / "audit.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in PINS:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--objdump", default="llvm-objdump")
    args = parser.parse_args()
    report = audit({name: getattr(args, name) for name in PINS}, args.output, args.objdump)
    print(json.dumps(dict(result=report["result"], command_table_presence=report["command_table_presence"],
                          hardware_result=report["hardware_result"]), indent=2))


if __name__ == "__main__":
    main()
