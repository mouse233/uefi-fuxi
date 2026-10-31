#!/usr/bin/env python3
"""Fixed command identities and boot output dataflow, offline public controls.

No phone access or full KeyMint handler is executed. Only command-name lookup, a public request parser,
and a getter-to-encoder-argument fragment run in private Unicorn memory. The
fragment stops BEFORE encoding, crypto, authentication or service dispatch.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path
from unicorn import UC_HOOK_MEM_WRITE
from unicorn import arm64_const as r
import audit_fuxi_m3_metadata_read as ta
import audit_fuxi_m3_boot_client as boot
from audit_fuxi_m3_key_recovery import elf_bytes
from audit_fuxi_m3_begin_version import run, cbor


def branch(raw, pc, target, tail=False):
    word = struct.unpack('<I', elf_bytes(raw, pc, 4))[0]
    assert word >> 26 == (5 if tail else 37), hex(pc)
    imm = word & 0x3ffffff
    if imm & 0x2000000:
        imm -= 0x4000000
    assert pc+4*imm == target, hex(pc)
    return dict(pc=hex(pc), target=hex(target), kind='B' if tail else 'BL', word=hex(word))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--partition', type=Path, required=True)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--objdump', default='/opt/homebrew/opt/llvm/bin/llvm-objdump')
    a = p.parse_args()
    raw = a.partition.read_bytes()
    assert len(raw) == 524288 and hashlib.sha256(raw).hexdigest() == ta.TA_SHA
    runtime = a.runtime.read_bytes()
    runtime_sha = hashlib.sha256(runtime).hexdigest()
    assert runtime_sha == '657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb'
    a.output.mkdir(parents=True, exist_ok=True)
    names = []
    table = elf_bytes(raw, 0x5a5e0, 89*16)
    # Preserve duplicate command entries and individual flags/order.
    for i in range(89):
        cmd, flags, handler = struct.unpack_from('<IIQ', table, i*16)
        u = boot.machine(raw)
        u.reg_write(r.UC_ARM64_REG_X0, cmd)
        run(u, 0xd01c)
        ptr = u.reg_read(r.UC_ARM64_REG_X0)
        assert ta.BASE+0x49000 <= ptr < ta.BASE+0x59000
        text = bytes(u.mem_read(ptr, 160)).split(b'\0', 1)[0].decode('ascii')
        assert 0 < len(text) < 160
        names.append(dict(index=i, command=hex(cmd), flags=hex(flags), handler=hex(handler), name=text))
    expected = {
        0x200: (0xddf4, 'GET_VERSION'),
        0x207: (0xdeec, 'SET_VERSION'),
        0x208: (0xbb7c, 'SET_BOOT_STATE'),
        0x211: (0xc3a8, 'KEYMASTER_SET_VBH'),
        0x214: (0x2fe14, 'KEYMASTER_PROVISION_ATTEST_KEY_NEW'),
        0x218: (0xc038, 'FBE_SET_SEED'),
        0x311e: (0x3dbec, 'KEYMINT_GENERATE_CSR'),
        0x311f: (0x31a68, 'KEYMINT_GET_ROOT_OF_TRUST'),
    }
    for cmd, (handler, name) in expected.items():
        rows = [x for x in names if x['command'] == hex(cmd)]
        assert rows and all(x['handler'] == hex(handler) and x['name'] == name for x in rows)
    rot = next(x for x in names if x['command'] == '0x311f')
    assert rot['flags'] == '0x1'  # configured gate, not an initialization substitute

    edges = [
        (0x31af0, 0x39a88, False),  # request parser
        (0x31b44, 0xbb10, False),   # requires boot-state flag before copying hash
        (0x31b6c, 0xb9f4, False),   # requires initialization flag
        (0x31ba8, 0xb9ac, False),   # selected 32-byte VBH copy
        (0x31c40, 0x47aa8, False),  # other response byte field, not a version
        (0x31c44, 0xb850, False),
        (0x31c5c, 0x47fd8, False), # boot value -> integer encoder
        (0x31d44, 0x490b4, False), # later packaging
        (0x31d74, 0x7fd0, False),
        (0x31db8, 0x16b80, False),
        (0x16bf4, 0x1c0, False),   # imported service PLT, not executed
        (0xc458, 0x446b4, False),  # SET_VBH writes global destination
        (0x2fe20, 0x2f7f0, True),
    ]
    checked_edges = [branch(raw, *edge) for edge in edges]
    words = {
        0xb858: 0xb944f500,  # independent boot global +4f4
        0xb950: 0xf9418508,  # vendor reads relocated selector pointer
        0xb954: 0xb9400108,
        0xb958: 0xb8687920,
        0x31c48: 0x2a0003e4,  # encoder arg w4=w0
        0xdf6c: 0xb828794b,    # SET_VERSION slot write
        0xe008: 0x3828692b,    # SET_VERSION once flag write
        0xc448: 0x91140273,   # SET_VBH destination +500
        0xbb34: 0x39696108,   # boot-state set flag at5ba58
        0xba10: 0x39548108,   # initialization flag at5b520
    }
    word_rows = []
    for pc, word in words.items():
        actual = struct.unpack('<I', elf_bytes(raw, pc, 4))[0]
        assert actual == word, (hex(pc), hex(actual), hex(word))
        word_rows.append(dict(pc=hex(pc), word=hex(word)))
    rel = boot.relocations(raw, boot.dynamic(raw))
    assert [x for x in rel if x[0] == 0x5a308] == [(0x5a308, 1027, 0x4c544)]
    assert elf_bytes(raw, 0x4c544, 4) == bytes(4)

    controls = []
    for value in (0, 202607, 202610, 20261005, 0xffffffff):
        u = boot.machine(raw)
        u.mem_write(ta.BASE+0x5b4f4, struct.pack('<I', value))
        sp = u.reg_read(r.UC_ARM64_REG_SP)
        u.reg_write(r.UC_ARM64_REG_X20, 0xffffffffffffffff)
        def forbid_write(_u, _access, address, size, _value, _ctx):
            raise AssertionError(f'getter fragment wrote memory {address:x}/{size}')
        hook = u.hook_add(UC_HOOK_MEM_WRITE, forbid_write)
        result = run(u, 0x31c44, {0x31c5c}, preserve_frame=True)
        u.hook_del(hook)
        assert result['stopped_before'] == '0x31c5c'
        assert u.reg_read(r.UC_ARM64_REG_X4) == value
        assert u.reg_read(r.UC_ARM64_REG_X0) == sp+0x300
        assert u.reg_read(r.UC_ARM64_REG_X1) == 0
        assert u.reg_read(r.UC_ARM64_REG_X2) == 0x7fffffffffffffff
        assert u.reg_read(r.UC_ARM64_REG_X3) == 0xffffffffffffffff
        assert boot.selector(u) == 0
        controls.append(dict(synthetic_boot=value, encoder_uint_argument=value,
                             memory_writes=0, stopped_before='0x31c5c', selector_default=0))

    # Check the matching HAL's command and serializer labels, without executing
    # Android .so code. The challenge API stub is a service error, not TA311e.
    vendor_words = {0x32a9c: 0x528623e1, 0x3a70c: 0x52800082, 0x1ba28: 0x12800c60}
    for pc, word in vendor_words.items():
        assert struct.unpack('<I', elf_bytes(runtime, pc, 4))[0] == word
    vendor_edges = [branch(runtime, *edge) for edge in (
        (0x32ab0, 0x3d988, False), (0x32aec, 0x3d5b0, False),
        (0x3a71c, 0x3de08, False))]
    parser_controls = []
    for label, payload in (
        ('challenge16', cbor({4: bytes(range(16))})),
        ('challenge0', cbor({4: b''})),
        ('challenge15', cbor({4: bytes(15)})),
        ('challenge17', cbor({4: bytes(17)})),
        ('challenge130', cbor({4: bytes(130)})),
        ('challenge131', cbor({4: bytes(131)})),
        ('missing', cbor({})), ('wrong-type', cbor({4: 1})),
    ):
        u = boot.machine(raw)
        u.mem_write(ta.INPUT, payload)
        desc, buf = ta.SCRATCH+0x8000, ta.SCRATCH+0x9000
        u.mem_write(desc, struct.pack('<QQ', buf, 130))
        u.reg_write(r.UC_ARM64_REG_X0, ta.INPUT)
        u.reg_write(r.UC_ARM64_REG_X1, len(payload))
        u.reg_write(r.UC_ARM64_REG_X2, desc)
        result = run(u, 0x39a88)
        ptr, n = struct.unpack('<QQ', u.mem_read(desc, 16))
        if result['status'] == 0:
            assert n <= len(payload), label
            assert ta.SCRATCH <= ptr < ta.SCRATCH+0x20000
        parser_controls.append(dict(name=label, status=result['status'],
                                    decoded_length=n if result['status'] == 0 else None))
    assert parser_controls[0]['status'] == 0 and parser_controls[0]['decoded_length'] == 16
    assert parser_controls[5]['status'] == 0 and parser_controls[5]['decoded_length'] == 131
    assert parser_controls[7]['status'] != 0

    # Complete fixed-image direct B/BL caller census, not an indirect call graph.
    asm = subprocess.check_output([a.objdump, '-d', str(a.partition)], text=True)
    (a.output/'ta-full.asm').write_text(asm)
    callers = {hex(x): [] for x in (0xb82c, 0xb8ac, 0xb850, 0xb940)}
    for line in asm.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(b|bl)\s+0x([0-9a-f]+)\b', line)
        if m and hex(int(m[4], 16)) in callers:
            pc, target = int(m[1], 16), int(m[4], 16)
            callers[hex(target)].append(branch(raw, pc, target, m[3] == 'b'))
    assert any(x['pc'] == '0x31c44' for x in callers['0xb850'])
    assert not any(0x31a68 <= int(x['pc'], 16) < 0x31f10 for x in callers['0xb940'])
    ranges = {'root-of-trust': (0x31a68, 0x31f10), 'prerequisites': (0xb9ac, 0xbb7c),
              'set-vbh': (0xc3a8, 0xc690), 'set-version': (0xdeec, 0xe098),
              'set-seed': (0xc038, 0xc1b0), 'crypto-service': (0x16b80, 0x16c2c),
              'version-accessors': (0xb808, 0xb964)}
    disassembly = {}
    for name, (lo, hi) in ranges.items():
        text = '\n'.join(line for line in asm.splitlines()
                         if (m := re.match(r'\s*([0-9a-f]+):', line)) and lo <= int(m[1], 16) < hi)+'\n'
        (a.output/(name+'.asm')).write_text(text)
        disassembly[name] = dict(start=hex(lo), end=hex(hi), code_sha256=hashlib.sha256(elf_bytes(raw, lo, hi-lo)).hexdigest())
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__)]+[root/'tools'/n for n in (
        'audit_fuxi_m3_boot_client.py', 'audit_fuxi_m3_metadata_read.py',
        'audit_fuxi_m3_key_recovery.py', 'audit_fuxi_m3_begin_version.py',
        'audit_fuxi_m3_configure_gate.py', 'collect_fuxi_m3_blob_public.py')]
    report = dict(result='passed', partition_sha256=ta.TA_SHA, runtime_sha256=runtime_sha, command_entries=names,
                  command_count=89, checked_command_identities=len(expected),
                  raw_edges=checked_edges, raw_words=word_rows, direct_getter_callers=callers,
                  boot_output_controls=controls, disassembly=disassembly,
                  vendor_words={hex(k): hex(v) for k,v in vendor_words.items()},
                  vendor_edges=vendor_edges, public_request_parser_controls=parser_controls,
                  findings=dict(boot_query_route='0x311f -> 0x31a68 -> 0x31c44 -> 0xb850 -> w4 -> 0x47fd8',
                                root_of_trust_configured_gate=True,
                                prerequisites=['5ba58 boot-state flag / bb10', '5b520 initialized flag / b9f4', 'selected VBH / b9ac'],
                                vendor_direct_getter_in_root_handler=False,
                                selector_runtime_query_identified_in_checked_routes=False,
                                full_handler_readonly_contract_proven=False,
                                firmware_candidate_built=False, phone_accessed=False),
                  limits=['Direct callers are not an exhaustive indirect/inlined dataflow proof.',
                          'No claim that every possible external route is absent; only named routes checked.',
                          'Synthetic boot values are injected into private emulator memory, never phone or firmware.',
                          'Boot fragment stops before encoding. Isolated public request parsing tested, but full handler, response packaging, MAC/crypto service and failure cleanup not validated.',
                          'No raw ROT/VBH/seed/crypto payload or digest is obtained or logged.',
                          'No authentication success, live selector/boot/vendor, TA return PC or M3/M4/M5 proof.'],
                  sources={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    (a.output/'audit.json').write_text(json.dumps(report, indent=2)+'\n')
    print('PASS 89 command names, 8 identities, 16 branch edges, 13 words, 5 boot-output and 8 public parser controls')


if __name__ == '__main__':
    main()
