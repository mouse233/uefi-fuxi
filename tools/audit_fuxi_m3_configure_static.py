#!/usr/bin/env python3
"""Static, read-only map of KeyMint configure (0x2116): HAL packing + TA acceptance.

No device calls, no SMC, no Unicorn execution of vendor code. Does not encode a
live request for transmission and does not claim decryption readiness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct

OTA_QTI = "368b34db8efee95d1713cee10d823e8572f6668ef559867c67e292dc3b9e8c52"
TA_PIN = "2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6"
TAGS = {
    "OS_VERSION": 0x300002C1,
    "OS_PATCHLEVEL": 0x300002C2,
    "VENDOR_PATCHLEVEL": 0x300002CE,
}


def aosp_os_version(release: str) -> int:
    parts = [int(x) for x in release.split(".")]
    while len(parts) < 3:
        parts.append(0)
    major, minor, sub = parts[:3]
    return major * 10000 + minor * 100 + sub


def aosp_patchlevel(ymd: str) -> int:
    year, month, _day = ymd.split("-")
    return int(year) * 100 + int(month)


def load_segments(blob: bytes):
    if blob[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("expected ELF64 LE")
    phoff = struct.unpack_from("<Q", blob, 32)[0]
    ents, count = struct.unpack_from("<HH", blob, 54)
    segs = []
    for i in range(count):
        kind, _flags, off, va, _p, fsz, msz, _a = struct.unpack_from("<IIQQQQQQ", blob, phoff + i * ents)
        if kind == 1:
            segs.append((off, va, fsz, msz))
    return segs


def va_to_off(segs, va: int) -> int:
    for off, base, fsz, _msz in segs:
        if base <= va < base + fsz:
            return off + (va - base)
    raise KeyError(hex(va))


def u32(blob: bytes, off: int) -> int:
    return struct.unpack_from("<I", blob, off)[0]


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--library", type=pathlib.Path, required=True, help="pinned OTA/runtime libqtikeymint.so")
    p.add_argument("--partition", type=pathlib.Path, required=True, help="pinned keymaster_a image")
    p.add_argument("--context", type=pathlib.Path, required=True, help="android-context JSON")
    p.add_argument("--report", type=pathlib.Path, required=True)
    a = p.parse_args()

    lib = a.library.read_bytes()
    if hashlib.sha256(lib).hexdigest() != OTA_QTI:
        raise SystemExit("libqtikeymint hash mismatch")
    part = a.partition.read_bytes()
    if hashlib.sha256(part).hexdigest() != TA_PIN:
        raise SystemExit("keymaster partition hash mismatch")
    ctx = json.loads(a.context.read_text())
    props = ctx["props"]
    release = props["ro.build.version.release"]
    os_patch = props["ro.build.version.security_patch"]
    vendor_patch = props["ro.vendor.build.security_patch"]

    # HAL: configure() non-legacy path uses command 0x2116 + serializeClientParams.
    configure = lib[0x2E3C0:0x2E588]
    if b"\x81\x22\x84\x52" not in configure:  # mov w1, #0x2116 little-endian encoding fragment
        # 528422c1 = mov w1, #0x2116
        if struct.pack("<I", 0x528422C1) not in configure:
            raise SystemExit("configure() missing mov w1,#0x2116")
    if struct.pack("<I", 0x528002C2) not in lib[0x35178:0x35290]:
        # mov w2, #0x16 inside serializeClientParams (CBOR map key 22 / count)
        raise SystemExit("serializeClientParams missing map-key 0x16 immediate")

    segs = load_segments(part)
    table = va_to_off(segs, 0x5A5E0)
    entries = {}
    for i in range(89):
        cmd = u32(part, table + i * 16)
        handler = u32(part, table + i * 16 + 8)
        if cmd in (0x200, 0x215, 0x2116, 0x311D, 0x3120, 0x3121):
            entries[cmd] = {"index": i, "handler_va": handler}
    if 0x3121 in entries:
        raise SystemExit("unexpected 0x3121 table hit")
    if entries.get(0x2116, {}).get("handler_va") != 0xB7B4:
        raise SystemExit("0x2116 handler VA changed")
    if entries.get(0x215, {}).get("handler_va") != 0xDCF8:
        raise SystemExit("0x215 handler VA changed")
    if entries.get(0x311D, {}).get("handler_va") != 0x29DF0:
        raise SystemExit("0x311D convert handler VA changed")

    core = part[va_to_off(segs, 0x37F28) : va_to_off(segs, 0x38260)]
    # mov w24,#0x2ce / w26,#0x2c2 / w27,#0x2c1 then movk #0x3000,lsl#16
    for imm, enc in (
        (0x2CE, 0x528059D8),
        (0x2C2, 0x5280585A),
        (0x2C1, 0x5280583B),
        (0x3000, 0x72A60018),  # movk w24
    ):
        if struct.pack("<I", enc) not in core and imm != 0x3000:
            raise SystemExit(f"configure core missing tag imm {hex(imm)}")
    if struct.pack("<I", 0x528002C1) not in core:  # mov w1,#0x16 count key
        raise SystemExit("configure core missing CBOR key 0x16 fetch")
    for marker in (
        b"!!! The OS Version / Security or Vendor Patch Level not provided !!!",
        b"KM_TAG_OS_VERSION: %u",
        b"KM_TAG_OS_PATCHLEVEL: %lu",
        b"KM_VENDOR_PATCHLEVEL: %lu",
        b"parseConfigureInputs",
        b"deserializeConvertStorageKeyToEphemeral",
        b"KM_TAG_FBE_ICE - using FBE ICE",
    ):
        if marker not in part:
            raise SystemExit("missing TA string " + marker.decode())

    packed = {
        "OS_VERSION": aosp_os_version(release),
        "OS_PATCHLEVEL": aosp_patchlevel(os_patch),
        "VENDOR_PATCHLEVEL": aosp_patchlevel(vendor_patch),
    }
    ota_contrast = {
        "OS_VERSION": aosp_os_version("17"),
        "OS_PATCHLEVEL": aosp_patchlevel("2026-10-01"),
        "VENDOR_PATCHLEVEL": aosp_patchlevel("2026-08-01"),
    }

    report = {
        "result": "passed",
        "scope": (
            "Static HAL/TA map of configure 0x2116 only. No device, no SMC, no live "
            "serialization. Packed integers follow AOSP major*10000+minor*100+sub and "
            "YYYYMM patch encoding; not proven byte-identical to a phone-side encode."
        ),
        "library_sha256": OTA_QTI,
        "partition_sha256": TA_PIN,
        "runtime_props": {
            "release": release,
            "os_patch": os_patch,
            "vendor_patch": vendor_patch,
            "slot": props.get("ro.boot.slot_suffix"),
        },
        "tags": {k: hex(v) for k, v in TAGS.items()},
        "packed_runtime_aosp_model": packed,
        "packed_ota_static_contrast": ota_contrast,
        "runtime_vs_ota_static_differs": packed != ota_contrast,
        "hal": {
            "configure_va": "0x2e3c0",
            "configure_command": "0x2116",
            "serializeClientParams_va": "0x35178",
            "cbor_count_map_key": 22,
            "setVersion_still_called_before_configure": True,
            "setVersion_command_absent_from_ta_table": True,
        },
        "ta": {
            "command_0x2116": {
                "index": entries[0x2116]["index"],
                "handler_va": hex(entries[0x2116]["handler_va"]),
            },
            "wrapper_calls_core_va": "0x37f28",
            "required_tags": [hex(v) for v in TAGS.values()],
            "required_all_three_or_fail": True,
            "fail_incomplete_status": -38,
            "fail_unknown_tag_status": -40,
            "in_ta_ram_writers": {
                "OS_VERSION": {"store_va": "0xb808", "slot_array_va": "0x5b4f0"},
                "OS_PATCHLEVEL": {"store_va": "0xb864", "slot_array_va": "0x5b4f8"},
                "VENDOR_PATCHLEVEL": {"store_va": "0xb91c", "slot_array_va": "0x5b4fc"},
            },
            "persistence_beyond_ta_ram": "unproven",
            "related_commands_present": {
                "getVersion": {
                    "index": entries[0x200]["index"],
                    "handler_va": hex(entries[0x200]["handler_va"]),
                },
                "date_support": {
                    "index": entries[0x215]["index"],
                    "handler_va": hex(entries[0x215]["handler_va"]),
                },
                "convert_storage_key": {
                    "index": entries[0x311D]["index"],
                    "handler_va": hex(entries[0x311D]["handler_va"]),
                },
                "setVersion_0x3121": None,
            },
        },
        "decrypt_readiness": {
            "configure_necessary": "unknown",
            "configure_sufficient": False,
            "still_needed_examples": [
                "storage-key convert (0x311d) inputs and outputs",
                "metadata keymaster_key_blob handling",
                "FBE/ICE key install path",
            ],
            "not_authorized": "Do not send 0x2116 without an explicit write-side-effect decision.",
        },
    }
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
