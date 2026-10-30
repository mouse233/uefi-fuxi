#!/usr/bin/env python3
"""Pin recovery/KeyMint context facts; never execute a real key or device call."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from audit_fuxi_m3_key_recovery import PINS, elf_bytes


def verify(name, raw):
    if hashlib.sha256(raw).hexdigest() != PINS[name]:
        raise ValueError('fixed input SHA256 mismatch: ' + name)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in PINS:
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--objdump', default='llvm-objdump')
    p.add_argument('--version-controls', action='store_true',
                   help='execute the existing bounded TA version gate on public synthetic fields only')
    a = p.parse_args()
    paths = {name: getattr(a, name) for name in PINS}
    raw = {name: path.read_bytes() for name, path in paths.items()}
    for name, data in raw.items():
        verify(name, data)
        changed = bytearray(data); changed[-1] ^= 1
        try:
            verify(name, changed)
        except ValueError:
            pass
        else:
            raise AssertionError('mutated input accepted: ' + name)
    a.output.mkdir(parents=True, exist_ok=True)
    ranges = {
        'recovery-keystore-constructor': ('recovery', 0x2501B8, 0x250224,
            ['AServiceManager_waitForService', 'IKeystoreService10fromBinder',
             'mov w1, #0x1', 'ldr x9, [x8, #0x30]', 'blr x9']),
        'aidl-begin': ('keymint', 0x1B100, 0x1B140, ['keymint_begin_operation']),
        'keymint-begin-command': ('keymint', 0x31DAC, 0x31EE0,
            ['spu_init', 'mov w1, #0x310f', 'serializeClientBegin', 'sendCmd']),
        'configure-sequence': ('keymint', 0x2E3C0, 0x2E4E4,
            ['isLegacy', 'legacy_configure', 'keymint_set_version', 'mov w1, #0x2116']),
        'set-version-command': ('keymint', 0x2E26C, 0x2E310,
            ['mov w1, #0x3121', 'mov w1, #0xc8', 'serializeInteger', 'sendCmd']),
        'date-properties': ('keymint', 0x18590, 0x187A4,
            ['legacy_get_date_support', 'property_get', 'bl 0x189a0', 'bl 0x18b34']),
        'generate-command': ('keymint', 0x2E588, 0x2E65C,
            ['generate_key', 'mov w8, #0x2108', 'mov w9, #0x2508']),
        'upgrade-command': ('keymint', 0x2F458, 0x2F574,
            ['upgrade_key', 'mov w8, #0x2114', 'mov w9, #0x2514']),
        'version-gate': ('partition', 0x98C0, 0x9A38,
            ['bl 0xdde0', 'bl 0xb82c', 'bl 0xb850', 'bl 0xb8ac', 'bl 0xb940', '#-0x3e']),
        'indirect-call-trampoline': ('partition', 0x2480, 0x248C, ['br x16']),
    }
    evidence = {}
    for name, (kind, lo, hi, patterns) in ranges.items():
        text = subprocess.check_output([a.objdump, '-d', '--start-address=' + hex(lo),
                                       '--stop-address=' + hex(hi), str(paths[kind])], text=True,
                                      stderr=subprocess.PIPE)
        normalized = re.sub(r'[\t ]+', ' ', text)
        for pattern in patterns:
            if pattern not in normalized:
                raise ValueError(name + ' missing: ' + pattern)
        (a.output / (name + '.asm')).write_text(text)
        evidence[name] = dict(input=kind, start=hex(lo), end=hex(hi),
                             code_sha256=hashlib.sha256(elf_bytes(raw[kind], lo, hi-lo)).hexdigest())
    table = elf_bytes(raw['partition'], 0x5A5E0, 89*16)
    handlers = {command: handler for command, _flags, handler in
                (struct.unpack_from('<IIQ', table, i*16) for i in range(89))}
    if handlers[0x310F] != handlers[0x210F] or handlers[0x2109] != handlers[0x3109]:
        raise ValueError('fixed handler aliases changed')
    controls = []
    if a.version_controls:
        from audit_fuxi_m3_metadata_read import version_gate
        # Four *effective* accessor values, not raw YYYYMMDD configure slots.
        values = (170000, 202610, 0, 20261005)
        for name, version, stored, expected in [
            ('matching', 0x400000005, values, 0),
            ('old-format', 0x400000004, values, -62),
            ('os-mismatch', 0x400000005, (170001, *values[1:]), -62),
            ('os-patch-mismatch', 0x400000005, (values[0], 202609, *values[2:]), -62),
            ('boot-patch-mismatch', 0x400000005, (*values[:2], 20261005, values[3]), -62),
            ('vendor-patch-mismatch', 0x400000005, (*values[:3], 20261004), -62),
        ]:
            # version_gate installs raw slots. b8ac normalizes OS patch YYYYMMDD
            # to YYYYMM; supply its raw input while comparing the stored value.
            result = version_gate(raw['partition'], False, (170000, 20261005, 0, 20261005), stored, version)
            if result['status'] != expected:
                raise ValueError('synthetic control failed: ' + name)
            controls.append(dict(name=name, expected_status=expected, **result))
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__), Path(__file__).with_name('audit_fuxi_m3_key_recovery.py')]
    if a.version_controls:
        files.append(Path(__file__).with_name('audit_fuxi_m3_metadata_read.py'))
    report = dict(result='passed', inputs=PINS, mutated_inputs_rejected=len(raw), evidence=evidence,
                  command_semantics={'0x2108': 'generate_key in pinned non-legacy TEE HAL',
                                     '0x2114': 'upgrade_key in pinned non-legacy TEE HAL'},
                  version_controls=controls,
                  limits=['Recovery reaches keystore2 through Binder; no live route trace was captured.',
                          'Direct call graphs omit br/blr, imported callbacks and propagated errors.',
                          'A -33 result does not establish a live key-id-table miss or old blob format.',
                          '-62 covers old format and four version mismatches; two version tags do not discriminate them.',
                          'No real key, generate/upgrade/setVersion command, secure service or phone was executed.'],
                  sources={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    (a.output / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(evidence), 'fixed code ranges;', len(controls), 'synthetic version controls; no device')


if __name__ == '__main__':
    main()
