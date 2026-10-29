#!/usr/bin/env python3
"""Negative controls for the offline metadata prerequisite audit, no secrets."""
import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import tempfile

import audit_fuxi_m3_metadata_read as audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--partition", type=Path, required=True)
    parser.add_argument("--modules", type=Path, required=True)
    parser.add_argument("--recovery", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    raw = audit.checked_inputs(args.partition, args.modules, args.recovery)
    rejected = []
    with tempfile.TemporaryDirectory(prefix="fuxi-metadata-inputs-") as tmp:
        temp = Path(tmp)
        partition, modules, recovery = temp / "ta", temp / "modules", temp / "recovery"
        modules.mkdir()
        shutil.copyfile(args.partition, partition)
        shutil.copyfile(args.recovery, recovery)
        for name in audit.MODULES:
            shutil.copyfile(args.modules / name, modules / name)
        for target in [partition, recovery, *(modules / name for name in audit.MODULES)]:
            original = target.read_bytes()
            changed = bytearray(original)
            changed[-1] ^= 1
            target.write_bytes(changed)
            try:
                audit.checked_inputs(partition, modules, recovery)
            except ValueError:
                rejected.append(target.name)
            else:
                raise AssertionError("modified binary accepted")
            target.write_bytes(original)

    # Counterfactuals use the real instructions/accessors, not a Python model
    # of the expected result. No configure or key operation is substituted.
    values = (170000, 202610, 202610, 202610)
    controls = []
    for index, name in enumerate(("os", "os-patch", "boot-patch", "vendor-patch")):
        changed = list(values)
        changed[index] -= 1
        result = audit.version_gate(raw, False, tuple(changed), values)
        assert result["status"] == -62 and len(result["gate_getters"]) == 4
        controls.append(name + "-mismatch-rejected")
    for version in (0, 0x400000001, 0x400000004):
        result = audit.version_gate(raw, False, values, values, version=version)
        assert result["status"] == -62 and result["gate_getters"] == []
        result = audit.version_gate(raw, True, (0, 0, 0, 0), values, version=version)
        assert result["status"] == 0 and result["gate_getters"] == []
        controls.append("synthetic-fbe-early-return-" + hex(version))
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        result = audit.decode_synthetic_tag(raw, 0x700002D3)  # unknown adjacent tag
    # This fixed parser ignores the unknown tag; do not invent an error.
    assert result["status"] == 0 and result["fbe_flag"] == 0
    assert captured.getvalue() == ""
    controls.append("unknown-authorization-tag-does-not-set-fbe")
    emu = audit.machine(raw)
    truncated = b"\xa1\x01\xa1" + audit.uint(0x700002D2) + b"\xf5"
    emu.mem_write(audit.INPUT, truncated)
    for reg, value in ((audit.UC_ARM64_REG_X0, audit.INPUT),
                       (audit.UC_ARM64_REG_X1, len(truncated)),
                       (audit.UC_ARM64_REG_X2, audit.CONTEXT)):
        emu.reg_write(reg, value)
    result = audit.execute(emu, 0x304DC)
    assert result["status"] == -33
    assert emu.mem_read(audit.CONTEXT + 0x1D4, 1)[0] == 1
    controls.append("partial-fbe-flag-is-not-successful-authorization-decode")
    for fbe in (False, True):
        result = audit.export_gate(raw, fbe)
        assert result["export_reached"] == fbe
        assert result["status"] == (None if fbe else -17)
        controls.append("export-stopped-before-service" if fbe else "non-fbe-export-rejected")

    # Test the emulator boundary itself using a synthetic instruction in a
    # private copy; neither input binary nor production firmware is modified.
    emu = audit.machine(raw)
    emu.mem_write(audit.BASE + 0x98C0, struct.pack("<I", 0xD4000003))  # SMC #0
    try:
        audit.execute(emu, 0x98C0)
    except ValueError as exc:
        assert "forbidden" in str(exc)
    else:
        raise AssertionError("offline SMC boundary not enforced")
    controls.append("synthetic-smc-trapped")
    emu = audit.machine(raw)
    emu.mem_write(audit.BASE + 0x98C0, struct.pack("<I", 0x14000000))  # B .
    try:
        audit.execute(emu, 0x98C0)
    except ValueError as exc:
        assert "bound reached" in str(exc)
    else:
        raise AssertionError("instruction bound not enforced")
    controls.append("synthetic-loop-bounded")

    root = Path(__file__).resolve().parents[1]
    report = dict(result="passed", modified_inputs_rejected=rejected,
                  controls=controls, control_count=len(controls),
                  scope="Actual TA instructions with synthetic non-secret input only; "
                        "export stopped, logs suppressed, no device or key operation.",
                  sources={str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in (Path(__file__), Path(audit.__file__))})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": "passed", "modified_inputs_rejected": len(rejected),
                      "control_count": len(controls)}, indent=2))


if __name__ == "__main__":
    main()
