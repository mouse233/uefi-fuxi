#!/usr/bin/env python3
"""Offline ROT request/codec/failure contract; no successful crypto stub.

Run the handler only to a PRNG/HMAC boundary or along injected FAILURE returns.
Run post-MAC serialization separately on explicitly synthetic data. Neither is
successful authentication, a full successful query or a trace of the phone.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as r
import audit_fuxi_m3_metadata_read as ta
import audit_fuxi_m3_boot_client as boot
from audit_fuxi_m3_begin_version import cbor
from audit_fuxi_m3_key_recovery import elf_bytes
from audit_fuxi_m3_effective_context import branch


def execute(u, entry, stops=(), failures=None):
    failures = failures or {}
    result = dict(instructions=0, failure_services=[], global_writes=[], cleanup_reached=False)
    def code(m, pc, _size, _ctx):
        result['instructions'] += 1
        va = pc-ta.BASE
        if va in stops:
            result['stopped_before'] = hex(va)
            m.emu_stop()
            return
        if va == 0x31e28:
            result['cleanup_reached'] = True
        if va in failures:
            # Only failure returns, never fake a successful random/MAC service.
            assert (va == 0x80 and failures[va] == 0) or (va == 0x1c0 and failures[va] == -1)
            result['failure_services'].append(hex(va))
            m.reg_write(r.UC_ARM64_REG_X0, failures[va] & 0xffffffffffffffff)
            m.reg_write(r.UC_ARM64_REG_PC, m.reg_read(r.UC_ARM64_REG_X30))
            return
        if va == 0x20:  # logging suppressed, not an authentication function
            m.reg_write(r.UC_ARM64_REG_PC, m.reg_read(r.UC_ARM64_REG_X30))
            return
        if va < 0x600 or va in (0x18e38, 0x43fb4, 0x43a30):
            raise ValueError('unmodeled service/allocation/export boundary '+hex(va))
        if not any(lo <= va < hi for lo, hi in m.fuxi_code_ranges):
            raise ValueError('outside fixed code')
        word = struct.unpack('<I', m.mem_read(pc, 4))[0]
        if word == 0xdac107fe:
            m.reg_write(r.UC_ARM64_REG_PC, pc+4)
        elif word == 0xd65f0fff:
            m.reg_write(r.UC_ARM64_REG_PC, m.reg_read(r.UC_ARM64_REG_X30))
        elif word & 0xffe0001f in (0xd4000001, 0xd4000002, 0xd4000003):
            raise ValueError('SVC/HVC/SMC forbidden')
    def write(_m, _access, address, size, _value, _ctx):
        if ta.BASE+0x5b000 <= address < ta.BASE+0x5d000:
            result['global_writes'].append(dict(va=hex(address-ta.BASE), bytes=size))
    handles = [u.hook_add(UC_HOOK_CODE, code), u.hook_add(UC_HOOK_MEM_WRITE, write)]
    try:
        u.emu_start(ta.BASE+entry, ta.STOP, count=100000)
        assert 'stopped_before' in result or u.reg_read(r.UC_ARM64_REG_PC) == ta.STOP
    finally:
        for handle in handles:
            u.hook_del(handle)
    status = u.reg_read(r.UC_ARM64_REG_X0) & 0xffffffff
    result['status'] = None if 'stopped_before' in result else status-(1 << 32) if status >> 31 else status
    return result


def prepared(raw, value, boot_flag=1, init_flag=1, cached=0):
    u = boot.machine(raw)
    # Public synthetic ROT/VBH values, not copied from phone or firmware state.
    record = bytes(4)+bytes([0x31])*32+bytes(12)
    for va, data in ((0x5ba58, bytes([boot_flag])), (0x5b520, bytes([init_flag])),
                     (0x5b4f4, struct.pack('<I', value)), (0x5ba7c, record),
                     (0x5ba38, bytes([0x11])*32), (0x5b500, bytes([0x22])*32),
                     (0x5b4e8, bytes([cached])), (0x5b488, bytes([0x6d])*32)):
        u.mem_write(ta.BASE+va, data)
    payload = cbor({4: bytes(range(16))})
    u.mem_write(ta.INPUT, payload)
    desc, buf = ta.SCRATCH+0x8000, ta.SCRATCH+0x9000
    u.mem_write(desc, struct.pack('<QQ', buf, 4096))
    u.reg_write(r.UC_ARM64_REG_X0, ta.INPUT)
    u.reg_write(r.UC_ARM64_REG_X1, len(payload))
    u.reg_write(r.UC_ARM64_REG_X2, desc)
    return u, u.reg_read(r.UC_ARM64_REG_SP)-0x6a0, desc


def serialize(raw, payload, capacity=4096, cose_capacity=130):
    # Explicit independent post-MAC fragment; there is no service-success hook.
    u = boot.machine(raw)
    sp, desc, buf = 0x401e000, ta.SCRATCH+0x8000, ta.SCRATCH+0x9000
    u.reg_write(r.UC_ARM64_REG_SP, sp)
    u.reg_write(r.UC_ARM64_REG_X29, sp+0x660)
    u.reg_write(r.UC_ARM64_REG_X19, desc)
    u.mem_write(desc, struct.pack('<QQ', buf, capacity))
    u.mem_write(sp+0x1f0, payload)
    u.mem_write(sp+0x40, struct.pack('<Q', len(payload)))
    u.mem_write(sp+0x80, bytes([0x5d])*32)  # test tag, never a valid generated MAC
    u.mem_write(sp+0x7c, bytes.fromhex('a10105'))
    u.mem_write(sp+0x30, struct.pack('<QQ', sp+0x7c, 3))
    u.mem_write(sp+0x48, struct.pack('<QQ', sp+0x10c, cose_capacity))
    result = execute(u, 0x31ddc, {0x31e28})
    status = u.reg_read(r.UC_ARM64_REG_X20) & 0xffffffff
    status = status-(1 << 32) if status >> 31 else status
    ptr, n = struct.unpack('<QQ', u.mem_read(desc, 16))
    wire = bytes(u.mem_read(ptr, n)) if status == 0 else b''
    return wire, status, result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--partition', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    raw = a.partition.read_bytes()
    assert len(raw) == 524288 and hashlib.sha256(raw).hexdigest() == ta.TA_SHA
    a.output.mkdir(parents=True, exist_ok=True)
    dyn = boot.dynamic(raw)
    strings = elf_bytes(raw, dyn[5], dyn[10])
    imports = {}
    for off, info, _add in boot.relocations(raw, dyn, 23, 2):
        symbol = elf_bytes(raw, dyn[6]+(info >> 32)*24, 24)
        at = struct.unpack_from('<I', symbol)[0]
        if off in (0x5a048, 0x5a0e8):
            imports[hex(off)] = strings[at:].split(b'\0', 1)[0].decode()
    assert imports == {'0x5a048': 'qsee_prng_getdata', '0x5a0e8': 'qsee_SW_Hmac'}
    table = elf_bytes(raw, 0x4b8d0, 10)
    assert 0x8040+table[4]*4 == 0x80a4
    edges = [branch(raw, *x) for x in (
        (0x31d74, 0x7fd0, False), (0x8238, 0x12bdc, False), (0x12be0, 0x80, True),
        (0x31db8, 0x16b80, False), (0x16bf4, 0x1c0, False),
        (0x31eb4, 0x49204, False), (0x31ee4, 0x39bcc, False),
        (0x31e34, 0x4474c, False), (0x31e44, 0x4474c, False), (0x31e54, 0x4474c, False))]
    vectors, codecs = [], []
    for value in (0, 23, 24, 255, 256, 65535, 65536, 202607, 202610, 20261005, 0xffffffff):
        u, sp, _desc = prepared(raw, value)
        result = execute(u, 0x31a68, {0x31d68})
        assert result['stopped_before'] == '0x31d68' and not result['global_writes']
        n = struct.unpack('<Q', u.mem_read(sp+0x40, 8))[0]
        payload = bytes(u.mem_read(sp+0x1f0, n))
        expected = b'\xd9\x9c\x41'+cbor([bytes([0x31])*32, True, 0, bytes([0x22])*32, value])
        assert payload == expected
        ptr, size = struct.unpack('<QQ', u.mem_read(sp+0x20, 16))
        structure = bytes(u.mem_read(ptr, size))
        assert structure == cbor(['MAC0'.encode(), b'\xa1\x01\x05', bytes(range(16)), payload]).replace(b'\x44MAC0', b'\x64MAC0', 1)
        wire, status, encoded = serialize(raw, payload)
        expected_wire = cbor({36: b'\xd1'+cbor([b'\xa1\x01\x05', {}, payload, bytes([0x5d])*32])})
        assert status == 0 and wire == expected_wire and not encoded['global_writes']
        # Out-only fixture file contains SYNTHETIC bytes for host parser tests.
        vectors.append(dict(boot=value, response_hex=wire.hex(), synthetic=True, authenticated=False))
        codecs.append(dict(boot=value, payload_bytes=n, mac_structure_bytes=size, response_bytes=len(wire), authenticated=False))
    assert codecs[8]['payload_bytes'] == 79 and codecs[8]['mac_structure_bytes'] == 108 and codecs[8]['response_bytes'] == 127
    failures = []
    for name, flag, init, cached, stop, inject in (
        ('boot-flag-missing', 0, 1, 0, (), {}),
        ('init-flag-missing', 1, 0, 0, (), {}),
        ('cache-miss-boundary', 1, 1, 0, (0x80,), {}),
        ('cache-hit-boundary', 1, 1, 1, (0x1c0,), {}),
        ('prng-short-failure', 1, 1, 0, (), {0x80: 0}),
        ('hmac-service-failure', 1, 1, 1, (), {0x1c0: -1}),
    ):
        u, sp, _desc = prepared(raw, 202610, flag, init, cached)
        result = execute(u, 0x31a68, stop, inject)
        assert all(int(x['va'], 16) == 0x5b4c8 and x['bytes'] == 8 for x in result['global_writes'])
        if not stop:
            assert result['status'] < 0 and result['cleanup_reached']
            assert bytes(u.mem_read(sp+0x190, 96)) == bytes(96)
            assert bytes(u.mem_read(sp+0x1f0, 128)) == bytes(128)
        else:
            assert result['stopped_before'] == hex(stop[0])
        failures.append(dict(name=name, **result))
    assert failures[0]['status'] == failures[1]['status'] == -30
    assert failures[4]['status'] == -49 and failures[5]['status'] == -1
    capacity = []
    payload = b'\xd9\x9c\x41'+cbor([bytes(32), False, 3, bytes(32), 202610])
    for out_cap, cose_cap in ((4096, 130), (126, 130), (0, 130), (4096, 121), (4096, 0)):
        wire, status, _result = serialize(raw, payload, out_cap, cose_cap)
        assert (status == 0) == (out_cap >= 127 and cose_cap >= 122)
        capacity.append(dict(output_capacity=out_cap, cose_capacity=cose_cap, status=status, bytes=len(wire)))
    files = [Path(__file__)]+[Path(__file__).parent/n for n in (
        'audit_fuxi_m3_metadata_read.py', 'audit_fuxi_m3_boot_client.py',
        'audit_fuxi_m3_begin_version.py', 'audit_fuxi_m3_key_recovery.py',
        'audit_fuxi_m3_effective_context.py', 'audit_fuxi_m3_configure_gate.py', 'collect_fuxi_m3_blob_public.py')]
    root = Path(__file__).resolve().parents[1]
    report = dict(result='passed', partition_sha256=ta.TA_SHA, service_imports=imports,
                  checked_edges=edges, codec_controls=codecs, failure_controls=failures, capacity_controls=capacity,
                  schema='map{36:bstr(tag17 array[protected=a10105,map{},payload=bstr(tag40001 array[bstr32,bool,uint0..3,bstr32,boot:uint32]),tag:bstr32])}',
                  cache=dict(type_selector=4, miss_target='0x80a4', storage='TA private RAM', bytes=32,
                             flag='0x5b4e8', buffer='0x5b488', metadata_length='0x5b4c8',
                             initialized_only_after_exact_prng_count=True),
                  limits=['No device/SMC/full successful method or successful PRNG/HMAC stub.',
                          'Pre-crypto handler and independent post-MAC codec are separate synthetic controls, not an authenticated end-to-end result.',
                          'Fixed TA local RAM writes and failure propagation checked; external SDK implementation and all callbacks/persistence not executed.',
                          'COSE MAC is unverified; public boot may be structurally parsed only and is not attestation.',
                          'No real ROT/VBH/MAC cache/output bytes or material digest read or logged.'],
                  sources={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    (a.output/'synthetic-codec-vectors.json').write_text(json.dumps(vectors, indent=2)+'\n')
    (a.output/'audit.json').write_text(json.dumps(report, indent=2)+'\n')
    print('PASS 11 paired codec, 6 boundary/failure, 5 capacity controls; 10 raw edges; no crypto success stub')


if __name__ == '__main__':
    main()
