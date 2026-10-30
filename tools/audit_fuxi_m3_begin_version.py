#!/usr/bin/env python3
"""Fixed begin -> public envelope decode -> version gate, synthetic inputs only.

Decode stops BEFORE algorithm lookup/authentication. Re-entering the version
gate on that unauthenticated synthetic context is a separate counterfactual,
never a successful key operation or a trace of the phone's actual branch.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path
import audit_fuxi_m3_metadata_read as ta
from audit_fuxi_m3_key_recovery import elf_bytes
from audit_fuxi_m3_configure_gate import encode
from collect_fuxi_m3_blob_public import inspect_public
from unicorn import UC_HOOK_CODE
from unicorn import arm64_const as r

TAGS = (0x300002c1, 0x300002c2, 0x300002cf, 0x300002ce)
OFFSETS = (0x144, 0x14c, 0x1c0, 0x1b8)
MAGIC = 0x4b4d4b44
VERSION = 0x400000005


def cbor(value):
    def head(major, n):
        for limit, ai, width in ((24, 0, 0), (256, 24, 1), (65536, 25, 2), (1 << 32, 26, 4), (1 << 64, 27, 8)):
            if n < limit:
                return bytes([(major << 5) | (n if not width else ai)]) + (n.to_bytes(width, 'big') if width else b'')
        raise ValueError('integer bound')
    if isinstance(value, bool):
        return b'\xf5' if value else b'\xf4'
    if isinstance(value, bytes):
        return head(2, len(value))+value
    if isinstance(value, list):
        return head(4, len(value))+b''.join(map(cbor, value))
    if isinstance(value, dict):
        return head(5, len(value))+b''.join(cbor(k)+cbor(v) for k, v in value.items())
    return head(int(value < 0), value if value >= 0 else -1-value)


def envelope(values, version=VERSION, fbe=False, magic=MAGIC):
    hardware = {0x10000002: 32, **dict(zip(TAGS, values))}
    if fbe:
        hardware[0x700002d2] = True
    # Four public fields only; no encrypted key, nonce, MAC or real blob.
    return cbor([magic, version, 0, cbor({1: hardware, 0: {}})])


def run(u, entry, stop_at=None, preserve_frame=False):
    result = dict(instructions=0, logs_suppressed=0, branches=[], getters={}, first_mismatch=None)
    stops = set(stop_at or ())
    forbidden = {0x292d8, 0x43a30, 0x43fb4, 0x18e38, 0x192f8, 0x19344}
    getter_returns = {0x9928: 'os', 0x9930: 'boot_patch', 0x9938: 'os_patch', 0x9940: 'vendor_patch'}
    def hook(m, pc, _size, _context):
        result['instructions'] += 1
        va = pc-ta.BASE
        if va in stops:
            result['stopped_before'] = hex(va)
            m.emu_stop()
            return
        if va in forbidden:
            raise ValueError('forbidden allocator/authentication/export boundary: '+hex(va))
        if not any(lo <= va < hi for lo, hi in u.fuxi_code_ranges):
            raise ValueError('execution outside fixed code')
        word = struct.unpack('<I', m.mem_read(pc, 4))[0]
        if va in (0x9908, 0x9a1c):
            result['branches'].append(hex(va))
        comparisons = {0x9944: 'os_patch', 0x994c: 'os', 0x9968: 'boot_patch', 0x9970: 'vendor_patch'}
        if va in comparisons and not (m.reg_read(r.UC_ARM64_REG_NZCV) & (1 << 30)) and result['first_mismatch'] is None:
            result['first_mismatch'] = dict(field=comparisons[va], comparison_branch=hex(va))
        if va in getter_returns:
            result['getters'][getter_returns[va]] = m.reg_read(r.UC_ARM64_REG_X0) & 0xffffffff
        if word == 0xdac107fe:
            m.reg_write(r.UC_ARM64_REG_PC, pc+4)
        elif word == 0xd65f0fff:
            m.reg_write(r.UC_ARM64_REG_PC, m.reg_read(r.UC_ARM64_REG_X30))
        elif va == 0x20:
            result['logs_suppressed'] += 1
            m.reg_write(r.UC_ARM64_REG_X0, 0)
            m.reg_write(r.UC_ARM64_REG_PC, m.reg_read(r.UC_ARM64_REG_X30))
        elif word & 0xffe0001f in (0xd4000001, 0xd4000002, 0xd4000003):
            raise ValueError('SVC/HVC/SMC forbidden')
    hook_id = u.hook_add(UC_HOOK_CODE, hook)
    try:
        if not preserve_frame:
            u.reg_write(r.UC_ARM64_REG_SP, 0x401f000)
            u.reg_write(r.UC_ARM64_REG_X30, ta.STOP)
        u.emu_start(ta.BASE+entry, ta.STOP, count=ta.MAX_INSTRUCTIONS)
        if 'stopped_before' not in result and u.reg_read(r.UC_ARM64_REG_PC) != ta.STOP:
            raise ValueError('instruction bound reached')
    finally:
        u.hook_del(hook_id)
    status = u.reg_read(r.UC_ARM64_REG_X0) & 0xffffffff
    result['status'] = None if 'stopped_before' in result else status-(1 << 32) if status & (1 << 31) else status
    return result


def decode_prefix(raw, payload, patch):
    u = ta.machine(raw)
    # Execute the same PUBLIC configure parser in the same synthetic client 0
    # before decoding. No service or configure-success hook is substituted.
    config = encode([(TAGS[0], 170000), (TAGS[1], patch), (TAGS[3], patch)])
    u.mem_write(ta.INPUT, config)
    u.reg_write(r.UC_ARM64_REG_X0, ta.INPUT)
    u.reg_write(r.UC_ARM64_REG_X1, len(config))
    configured = run(u, 0x37f28)
    assert configured['status'] == 0
    u.mem_write(ta.INPUT, payload)
    for reg, value in ((r.UC_ARM64_REG_X0, ta.INPUT), (r.UC_ARM64_REG_X1, len(payload)),
                       (r.UC_ARM64_REG_X2, ta.CONTEXT), (r.UC_ARM64_REG_X3, 1)):
        u.reg_write(reg, value)
    result = run(u, 0x30d9c, {0x25d4})
    if 'stopped_before' in result:
        result['public'] = dict(magic=hex(struct.unpack('<Q', u.mem_read(ta.CONTEXT, 8))[0]),
                                format_version=hex(struct.unpack('<Q', u.mem_read(ta.CONTEXT+8, 8))[0]),
                                values=[struct.unpack('<I', u.mem_read(ta.CONTEXT+offset, 4))[0] for offset in OFFSETS],
                                fbe=bool(u.mem_read(ta.CONTEXT+0x1d4, 1)[0]))
    return u, result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--partition', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--public-evidence', type=Path, help='sanitized current public metadata; replayed fields only, never a real blob')
    p.add_argument('--objdump', default='/opt/homebrew/opt/llvm/bin/llvm-objdump')
    a = p.parse_args()
    raw = a.partition.read_bytes()
    ta.machine(raw)  # exact input validation before disassembly/emulation
    a.output.mkdir(parents=True, exist_ok=True)
    ranges = {
        'begin': (0x8984, 0x8bc8), 'begin-decode': (0x35154, 0x3533c),
        'unpack-tail': (0x310a8, 0x310b8), 'unpack-wrapper': (0x31040, 0x310a8),
        'public-envelope': (0x30d9c, 0x31040), 'public-auth': (0x304dc, 0x30d9c),
        'version-gate': (0x98c0, 0x9a5c), 'required-format': (0xdde0, 0xddf4),
        'version-accessors': (0xb808, 0xb960), 'boot-context-handler': (0xbb7c, 0xbedc),
        'public-configure': (0x37f28, 0x38288),
    }
    evidence = {}
    for name, (lo, hi) in ranges.items():
        asm = subprocess.check_output([a.objdump, '-d', '--start-address='+hex(lo), '--stop-address='+hex(hi), str(a.partition)], text=True, stderr=subprocess.PIPE)
        (a.output/(name+'.asm')).write_text(asm)
        evidence[name] = dict(start=hex(lo), end=hex(hi), code_sha256=hashlib.sha256(elf_bytes(raw, lo, hi-lo)).hexdigest())
    edges = [(0x89e0, 0x35154, False), (0x352d8, 0x310a8, False),
             (0x310b4, 0x31040, True), (0x31068, 0x30d9c, False),
             (0x30e74, 0x304dc, False), (0x31010, 0x98c0, False)]
    for pc, target, tail in edges:
        word = struct.unpack('<I', elf_bytes(raw, pc, 4))[0]
        assert word >> 26 == (0x5 if tail else 0x25)
        imm = word & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        assert pc+imm*4 == target
    controls = []
    for patch in (20261005, 20991231):
        values = [170000, patch//100, 0, patch]
        tests = [('matching', VERSION, values, False, 0, []),
                 ('old-format', VERSION-1, values, False, -62, ['0x9908'])]
        for index, name in enumerate(('os', 'os-patch', 'boot-patch', 'vendor-patch')):
            bad = values.copy(); bad[index] += 1
            tests.append((name+'-mismatch', VERSION, bad, False, -62, ['0x9a1c']))
        tests.append(('fbe-bypass-control-only', VERSION-1, [0, 0, 0, 0], True, 0, []))
        for name, version, stored, fbe, expected, branches in tests:
            payload = envelope(stored, version, fbe)
            u, decoded = decode_prefix(raw, payload, patch)
            assert decoded['stopped_before'] == '0x25d4'
            assert decoded['public']['values'] == stored and decoded['public']['format_version'] == hex(version)
            assert decoded['public']['fbe'] == fbe
            public = inspect_public(lambda offset, count: payload[offset:offset+count], len(payload))
            assert public['format_version'] == decoded['public']['format_version']
            assert [public['hardware'][key] for key in ('os_version','os_patch','boot_patch','vendor_patch')] == stored
            assert public['hardware'].get('fbe_tag_present',False) == fbe
            u.reg_write(r.UC_ARM64_REG_X0, ta.CONTEXT)
            result = run(u, 0x98c0)
            assert result['status'] == expected and result['branches'] == branches, (name, result)
            controls.append(dict(name=name, patch=patch, public_decode=decoded, counterfactual_gate=result))
    pairs = []
    for name, version, stored in [
        ('fixed-old-format', VERSION-1, [170000, 202610, 0, 20261005]),
        ('fixed-wrong-os', VERSION, [170001, 202610, 0, 20261005]),
        ('fixed-A-values', VERSION, [170000, 202610, 0, 20261005]),
        ('fixed-B-values', VERSION, [170000, 209912, 0, 20991231]),
    ]:
        payload = envelope(stored, version)
        rows = []
        for patch in (20261005, 20991231):
            u, decoded = decode_prefix(raw, payload, patch)
            assert decoded['stopped_before'] == '0x25d4'
            u.reg_write(r.UC_ARM64_REG_X0, ta.CONTEXT)
            rows.append(dict(patch=patch, **run(u, 0x98c0)))
        expected = [0, -62] if name == 'fixed-A-values' else [-62, 0] if name == 'fixed-B-values' else [-62, -62]
        assert [x['status'] for x in rows] == expected
        pairs.append(dict(name=name, same_synthetic_envelope=True, rows=rows))
    # Reject malformed public input using real parser instructions, not a model.
    rejected = []
    for name, payload in [('bad-magic', envelope([0]*4, magic=0)), ('truncated', envelope([0]*4)[:-1])]:
        _, result = decode_prefix(raw, payload, 20261005)
        assert result['status'] == -33 and 'stopped_before' not in result
        rejected.append(dict(name=name, result=result))
    suffix_controls = []
    for status in (-62, -33, -38):
        for pc in (0x30efc, 0x30f58):
            u, decoded = decode_prefix(raw, envelope([170000, 202610, 0, 20261005]), 20261005)
            assert decoded['stopped_before'] == '0x25d4'
            # Counterfactual return-site error only. No callback is executed or
            # claimed to have produced this status; retain the real unpack frame.
            u.reg_write(r.UC_ARM64_REG_X0, status & 0xffffffff)
            result = run(u, pc, preserve_frame=True)
            assert result['status'] == status and not result['branches']
            suffix_controls.append(dict(return_site=hex(pc), injected_synthetic_status=status, result=result))
    boundary_checks = []
    for entry in (0x292d8, 0x43a30, 0x18e38):
        try:
            run(ta.machine(raw), entry)
        except ValueError as error:
            assert 'forbidden' in str(error)
            boundary_checks.append(hex(entry))
        else:
            raise AssertionError('offline service boundary accepted')
    for word in (0xd4000003, 0x14000000):
        u = ta.machine(raw)
        u.mem_write(ta.BASE+0x98c0, struct.pack('<I', word))
        try:
            run(u, 0x98c0)
        except ValueError as error:
            assert ('forbidden' if word == 0xd4000003 else 'bound reached') in str(error)
            boundary_checks.append('smc' if word == 0xd4000003 else 'loop')
        else:
            raise AssertionError('offline instruction boundary accepted')
    changed = bytearray(raw); changed[-1] ^= 1
    try:
        ta.machine(changed)
    except ValueError:
        boundary_checks.append('mutated-input')
    else:
        raise AssertionError('untrusted TA accepted')
    captured_replay = None
    if a.public_evidence:
        e = json.loads(a.public_evidence.read_text())
        assert e['result'] == 'captured' and e['serial'] == 'fcde91e' and e['stable_snapshots'] == 2 and e['blob_bytes'] == 208
        assert e['collector_sha256'] == hashlib.sha256(Path(__file__).with_name('collect_fuxi_m3_blob_public.py').read_bytes()).hexdigest()
        assert not e['public']['authenticated'] and 'outer_flags' not in e['public']
        hardware = e['public']['hardware']
        assert hardware['algorithm'] == 32 and not hardware.get('fbe_tag_present', False)
        stored = [hardware[k] for k in ('os_version','os_patch','boot_patch','vendor_patch')]
        version = int(e['public']['format_version'], 16)
        rows = []
        for patch, boot, vendor, name in [
            (20261005, 0, 20261005, 'A-fresh-global-boot-zero'),
            (20991231, 0, 20991231, 'B-fresh-global-boot-zero'),
            (20261005, stored[2], 20261005, 'A-assume-boot-aligned'),
            (20261005, 0, stored[3], 'A-assume-vendor-aligned'),
            (20261005, stored[2], stored[3], 'A-assume-both-aligned'),
        ]:
            u, decoded = decode_prefix(raw, envelope(stored, version), patch)
            assert decoded['stopped_before'] == '0x25d4'
            # Local counterfactual global/client slots, never a device command.
            u.mem_write(ta.BASE+0x5b4f4, struct.pack('<I', boot))
            u.mem_write(ta.BASE+0x5b4fc, struct.pack('<I', vendor))
            u.reg_write(r.UC_ARM64_REG_X0, ta.CONTEXT)
            result = run(u, 0x98c0)
            rows.append(dict(name=name, raw_configure_patch=patch, assumed_global_boot=boot,
                             assumed_client_vendor=vendor, **result))
        assert [row['status'] for row in rows] == [-62, -62, -62, -62, 0]
        assert [row['first_mismatch']['field'] if row['first_mismatch'] else None for row in rows] == ['boot_patch','os_patch','vendor_patch','boot_patch',None]
        captured_replay = dict(collected_utc=e['collected_utc'], public=e['public'], rows=rows,
            limits='Public fields copied into a synthetic envelope/context. Boot/client slots are explicit assumptions, not captured TA runtime. No real blob/authentication. No equality proof with previous UEFI attempts.')
    table = elf_bytes(raw, 0x5a5e0, 89*16)
    assert any(struct.unpack_from('<IIQ', table, i*16)[::2] == (0x208, 0xbb7c) for i in range(89))
    assert any(struct.unpack_from('<IIQ', table, i*16)[::2] == (0x310f, 0x8984) for i in range(89))
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__), Path(ta.__file__), root/'tools/audit_fuxi_m3_configure_gate.py', root/'tools/audit_fuxi_m3_key_recovery.py', root/'tools/collect_fuxi_m3_blob_public.py']
    report = dict(result='passed', partition_sha256=ta.TA_SHA, evidence=evidence,
                  direct_edges=[dict(callsite=hex(pc), target=hex(t), tail=tail) for pc, t, tail in edges],
                  public_evidence_sha256=hashlib.sha256(a.public_evidence.read_bytes()).hexdigest() if a.public_evidence else None,
                  captured_public_replay=captured_replay, boot_context_command_static_only='0x208 -> 0xbb7c; not sent',
                  controls=controls, paired_controls=pairs, malformed=rejected, error_suffix_controls=suffix_controls, boundary_checks=boundary_checks,
                  limits=['Prefix stops before algorithm lookup/authentication; gate re-entry is a separate synthetic counterfactual.',
                          'No real blob, material, phone, KeyMint service, generate/upgrade, SMC or persistence.',
                          'A/B screen status/lengths do not identify which gate branch executed on the phone.',
                          'Authentication callback return sites also propagate injected -62 unchanged; this does not prove those callees can actually originate -62.',
                          'Earlier claim that begin reaches the gate only through operation function pointers is incorrect.'],
                  sources={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    (a.output/'audit.json').write_text(json.dumps(report, indent=2)+'\n')
    print('PASS six direct edges, 14 decoded-public version controls, four paired controls, two malformed controls; no phone/authentication')


if __name__ == '__main__':
    main()
