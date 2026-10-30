#!/usr/bin/env python3
"""Fixed ELF selector and boot-context dataflow; no device or secure operation.

Only RELATIVE relocations are applied. Unresolved SDK initialization remains a
boundary. The boot fragment starts AFTER input processing on a synthetic public
record, stops before completion, and never authenticates/installs real boot data.
"""
import argparse
import hashlib
import json
import struct
import subprocess
from collections import Counter
from pathlib import Path
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC, UcError
from unicorn import arm64_const as r
import audit_fuxi_m3_metadata_read as ta
from audit_fuxi_m3_key_recovery import elf_bytes
from audit_fuxi_m3_configure_gate import encode
from audit_fuxi_m3_begin_version import run


def segments(raw):
    ph = struct.unpack_from('<Q', raw, 32)[0]
    size, count = struct.unpack_from('<HH', raw, 54)
    assert size == 56 and count <= 32
    return [struct.unpack_from('<IIQQQQQQ', raw, ph+i*size) for i in range(count)]


def dynamic(raw):
    rows = [x for x in segments(raw) if x[0] == 2]
    assert len(rows) == 1
    _, _, offset, _va, _, size, _, _ = rows[0]
    assert size <= 4096 and size % 16 == 0
    result = {}
    for at in range(offset, offset+size, 16):
        tag, value = struct.unpack_from('<QQ', raw, at)
        if not tag:
            break
        result[tag] = value
    return result


def relocations(raw, dyn, address_tag=7, size_tag=8):
    assert dyn[9] == 24 and dyn[size_tag] % 24 == 0 and dyn[size_tag] <= 0x10000
    data = elf_bytes(raw, dyn[address_tag], dyn[size_tag])
    return [struct.unpack_from('<QQq', data, i) for i in range(0, len(data), 24)]


def machine(raw, *, patch_instruction=None):
    u = ta.machine(raw)
    for offset, info, addend in relocations(raw, dynamic(raw)):
        if info & 0xffffffff == 1027:  # R_AARCH64_RELATIVE
            assert info >> 32 == 0 and 0 <= offset <= 0x80000-8 and 0 <= addend < 0x80000
            u.mem_write(ta.BASE+offset, struct.pack('<Q', ta.BASE+addend))
    if patch_instruction is not None:
        u.mem_write(ta.BASE+0xb808, struct.pack('<II', patch_instruction, 0xd65f03c0))
    # Honor the RX segment containing the selector. No writable synthetic
    # replacement for the selector or guard GOT is installed here.
    u.mem_protect(ta.BASE, 0x59000, UC_PROT_READ | UC_PROT_EXEC)
    return u


def word(u, va):
    return struct.unpack('<I', u.mem_read(ta.BASE+va, 4))[0]


def selector(u):
    pointer = struct.unpack('<Q', u.mem_read(ta.BASE+0x5a308, 8))[0]
    assert pointer == ta.BASE+0x4c544
    return struct.unpack('<I', u.mem_read(pointer, 4))[0]


def init_configure(raw, patch):
    u = machine(raw)
    writes = []
    def on_write(_u, _access, address, size, _value, _unused):
        if ta.BASE+0x5b4ec <= address < ta.BASE+0x5b500:
            writes.append(dict(va=hex(address-ta.BASE), bytes=size))
    u.hook_add(UC_HOOK_MEM_WRITE, on_write)
    assert selector(u) == 0 and word(u, 0x5b4f4) == 0
    initialized = run(u, 0xb490)
    assert u.reg_read(r.UC_ARM64_REG_PC) == ta.STOP and u.mem_read(ta.BASE+0x5b4ec, 1)[0] == 1 and word(u, 0x5b4f4) == 0
    payload = encode([(0x300002c1, 170000), (0x300002c2, patch), (0x300002ce, patch)])
    u.mem_write(ta.INPUT, payload)
    u.reg_write(r.UC_ARM64_REG_X0, ta.INPUT)
    u.reg_write(r.UC_ARM64_REG_X1, len(payload))
    result = run(u, 0x37f28)
    assert result['status'] == 0 and selector(u) == 0
    getters = []
    for entry in (0xb82c, 0xb8ac, 0xb940, 0xb850):
        run(u, entry)
        getters.append(u.reg_read(r.UC_ARM64_REG_X0) & 0xffffffff)
    assert getters == [170000, patch//100, patch, 0]
    assert not any(x['va'] == '0x5b4f4' for x in writes)
    return dict(patch=patch, selector=selector(u), b490_flag_after=1, b490_entry_completed=True,
                configure_status=result['status'], effective_getters=getters, writes=writes,
                scope='Relocated fixed image + b490 init + public configure. SDK initializers not run; boot0 remains a model value.')


def get_version(raw, capacity):
    u = machine(raw)
    out, desc = ta.SCRATCH+0x8000, ta.SCRATCH+0x9000
    u.mem_write(desc, struct.pack('<QQ', out, capacity))
    u.reg_write(r.UC_ARM64_REG_X0, ta.INPUT)
    u.reg_write(r.UC_ARM64_REG_X1, 0)
    u.reg_write(r.UC_ARM64_REG_X2, desc)
    result = run(u, 0xddf4)
    assert selector(u) == 0 and word(u, 0x5b4f4) == 0
    if capacity >= 20:
        values = list(struct.unpack('<IIII', u.mem_read(out+4, 16)))
        assert result['status'] == 0 and values == [4, 1, 4, 1012]
    else:
        values = []
        assert result['status'] < 0
    return dict(capacity=capacity, status=result['status'], public_version_fields=values,
                selector_after=selector(u), boot_after=word(u, 0x5b4f4))


def boot_fragment(raw, os_parts, year, month, day, offset=0x6000):
    assert all(0 <= x < 128 for x in os_parts) and 2000 <= year <= 2127 and 0 <= month < 16 and 0 <= day < 32
    u = machine(raw)
    record = ta.SCRATCH+offset
    frame = 0x401e000
    data = bytearray(48)
    packed_os = (os_parts[0] << 14) | (os_parts[1] << 7) | os_parts[2]
    packed_patch = (year-2000) << 4 | month | day << 11
    struct.pack_into('<II', data, 40, packed_os, packed_patch)
    u.mem_write(record, bytes(data))
    u.mem_write(frame-0x18, struct.pack('<Q', record))
    u.reg_write(r.UC_ARM64_REG_X29, frame)
    u.reg_write(r.UC_ARM64_REG_SP, frame-0x40)
    u.reg_write(r.UC_ARM64_REG_X21, ta.BASE+0x5b000)
    copied = []
    def copy(m, pc, _size, _context):
        if pc != ta.BASE+0x446b4:
            return
        dst, cap, src, n = [m.reg_read(getattr(r, 'UC_ARM64_REG_X'+str(i))) for i in range(4)]
        assert (dst, cap, src, n) == (ta.BASE+0x5ba7c, 48, record, 48)
        m.mem_write(dst, bytes(m.mem_read(src, n)))
        m.reg_write(r.UC_ARM64_REG_X0, n)
        m.reg_write(r.UC_ARM64_REG_PC, m.reg_read(r.UC_ARM64_REG_X30))
        copied.append(n)
    u.hook_add(UC_HOOK_CODE, copy)
    result = run(u, 0xbcf8, {0xbdf8}, preserve_frame=True)
    assert result['stopped_before'] == '0xbdf8' and copied == [48]
    expected_os = os_parts[0]*10000+os_parts[1]*100+os_parts[2]
    expected_patch = year*10000+month*100+day if day else year*100+month
    assert word(u, 0x5baa4) == expected_os
    assert word(u, 0x5baa8) == word(u, 0x5b4f4) == expected_patch
    assert u.mem_read(ta.BASE+0x5ba58, 1)[0] == 1
    return dict(os_parts=list(os_parts), year=year, month=month, day=day,
                normalized_os=expected_os, normalized_boot_patch=expected_patch,
                stopped_before_completion_call='0x404b4', boot_flag_already_written=True,
                scope='Synthetic 48-byte post-parse record; bounded memcpy modeled. Input processing/authorization/SDK/completion not executed.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--partition', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--deviceutils', type=Path, required=True)
    p.add_argument('--ramdisk-reference', type=Path, required=True, help='existing extraction; qcom init must match A17 pinned hash')
    p.add_argument('--objdump', default='/opt/homebrew/opt/llvm/bin/llvm-objdump')
    a = p.parse_args()
    raw = a.partition.read_bytes(); ta.machine(raw)
    utils = a.deviceutils.read_bytes()
    assert hashlib.sha256(utils).hexdigest() == '1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2'
    dyn = dynamic(raw); rel = relocations(raw, dyn)
    select = [x for x in rel if x[0] == 0x5a308]
    assert select == [(0x5a308, 1027, 0x4c544)]
    segment = [x for x in segments(raw) if x[0] == 1 and x[3] <= 0x4c544 < x[3]+x[6]]
    assert len(segment) == 1 and segment[0][1] == 5
    assert elf_bytes(raw, 0x4c544, 4) == bytes(4)
    ctors = [struct.unpack('<Q', elf_bytes(raw, va, 8))[0] for va in (0x5a3b8, 0x5a3c0)]
    assert ctors == [0x5ab70, 0x5ab70]
    strings = elf_bytes(raw, dyn[5], dyn[10])
    imports = {}
    for off, info, _add in relocations(raw, dyn, 23, 2):
        if off in (0x5a2c0, 0x5a2c8, 0x5a2d0):
            symbol = elf_bytes(raw, dyn[6]+(info >> 32)*24, 24)
            at = struct.unpack_from('<I', symbol)[0]
            imports[hex(off)] = strings[at:].split(b'\0', 1)[0].decode()
    assert imports == {'0x5a2c0': 'cmnlib_init', '0x5a2c8': 'GPAppLib_init', '0x5a2d0': 'GPAppLib_appInit'}
    # The named userspace initialize is a no-op here; don't infer behavior from its name.
    assert elf_bytes(utils, 0x66c0, 12) == bytes.fromhex('5f2403d5e0031f2ac0035fd6')
    rc = a.ramdisk_reference/'init.recovery.qcom.rc'
    assert hashlib.sha256(rc.read_bytes()).hexdigest() == 'ea0049522493a2f2175d9f1c93a8ebaffea1f650da6ae4c9c54da041f2a10f1c'
    text = rc.read_text()
    assert text.index('start vendor.qseecomd') < text.index('on property:vendor.sys.listeners.registered=true') < text.index('start vendor.keymint-qti')
    for va, value in ((0x2acf,b'vendor.sys.listeners.registered'), (0x2a15,b'/vendor/firmware_mnt/image'), (0x2d95,b'keymaster64'), (0x2e8b,b'keymaster')):
        assert elf_bytes(utils,va,len(value)+1) == value+b'\0'
    configs = [init_configure(raw, patch) for patch in (20261005, 20991231)]
    versions = [get_version(raw, cap) for cap in (19, 20, 64)]
    boots = [boot_fragment(raw, os, y, m, d, offset) for os, y, m, d, offset in [
        ((17, 0, 0), 2026, 10, 0, 0x6000), ((17, 0, 0), 2026, 10, 5, 0x6000),
        ((16, 1, 2), 2026, 10, 0, 0x6000), ((17, 0, 0), 2000, 1, 0, 0x6000),
        ((17, 0, 0), 2127, 12, 31, 0x6000), ((17, 0, 0), 2026, 0, 0, 0x6000),
        ((17, 0, 0), 2026, 10, 0, 0x7000),
    ]]
    guard_controls = []
    for flag in (0, 1):
        u = machine(raw)
        u.mem_write(ta.BASE+0x5ba58, bytes([flag]))
        u.reg_write(r.UC_ARM64_REG_X21, ta.BASE+0x5b000)
        guarded = run(u, 0xbbc8, {0xbc00, 0xbbd0})
        assert guarded['stopped_before'] == ('0xbc00' if flag == 0 else '0xbbd0')
        guard_controls.append(dict(already_set=flag, stopped_before=guarded['stopped_before'],
                                  scope='Guard fragment only, after an unexecuted platform-state query.'))
    table = elf_bytes(raw, 0x5a5e0, 89*16)
    handlers = {struct.unpack_from('<IIQ',table,i*16)[0]:struct.unpack_from('<IIQ',table,i*16)[2] for i in range(89)}
    assert handlers[0x200] == 0xddf4 and handlers[0x208] == 0xbb7c
    assert 0x3121 not in handlers and 0xc8 not in handlers
    boundary_controls = []
    for word_value, label in ((0xd4000003,'smc'),(0x14000000,'bounded-loop')):
        u = machine(raw, patch_instruction=word_value)
        try:
            run(u,0xb808)
        except ValueError as error:
            assert ('forbidden' if label == 'smc' else 'bound reached') in str(error)
            boundary_controls.append(label)
        else:
            raise AssertionError('execution boundary accepted')
    changed = bytearray(raw);changed[-1]^=1
    try:
        machine(changed)
    except ValueError:
        boundary_controls.append('modified-TA')
    else:
        raise AssertionError('modified TA accepted')
    # Actual instruction attempts to modify the RX selector are rejected.
    u = machine(raw, patch_instruction=0xb9000020)  # STR W0,[X1]
    u.reg_write(r.UC_ARM64_REG_X0, 1)
    u.reg_write(r.UC_ARM64_REG_X1, ta.BASE+0x4c544)
    try:
        run(u, 0xb808)
    except UcError as error:
        assert 'WRITE_PROT' in str(error)
    else:
        raise AssertionError('RX selector writable')
    assert selector(u) == 0
    a.output.mkdir(parents=True, exist_ok=True)
    ranges = {'selector-getters': (0xb808, 0xb960), 'app-init': (0xb490, 0xb4b8),
              'boot-handler': (0xbb7c, 0xbedc), 'elf-load-entry': (0x44034, 0x44314),
              'get-version': (0xddf4, 0xdef0)}
    evidence = {}
    for name, (lo, hi) in ranges.items():
        asm = subprocess.check_output([a.objdump, '-d', '--start-address='+hex(lo), '--stop-address='+hex(hi), str(a.partition)], text=True, stderr=subprocess.PIPE)
        (a.output/(name+'.asm')).write_text(asm)
        evidence[name] = dict(start=hex(lo), end=hex(hi), sha256=hashlib.sha256(elf_bytes(raw, lo, hi-lo)).hexdigest())
    for name,lo,hi in [('deviceutils-constructor',0x61c8,0x6400),('deviceutils-initialize',0x66c0,0x66cc)]:
        asm=subprocess.check_output([a.objdump,'-d','--start-address='+hex(lo),'--stop-address='+hex(hi),str(a.deviceutils)],text=True,stderr=subprocess.PIPE)
        (a.output/(name+'.asm')).write_text(asm)
        evidence[name]=dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(elf_bytes(utils,lo,hi-lo)).hexdigest())
    root = Path(__file__).resolve().parents[1]
    files = [Path(__file__), Path(ta.__file__), root/'tools/audit_fuxi_m3_begin_version.py',
             root/'tools/audit_fuxi_m3_configure_gate.py', root/'tools/audit_fuxi_m3_key_recovery.py']
    result = dict(result='passed', partition_sha256=ta.TA_SHA,
        deviceutils_sha256=hashlib.sha256(utils).hexdigest(), evidence=evidence,
        command_table={'0x200':'0xddf4 version query','0x208':'0xbb7c boot context handler; not sent','0x3121':'absent','0xc8':'absent'},
        boundary_controls=boundary_controls,
        selector=dict(got='0x5a308', relocation='R_AARCH64_RELATIVE', target='0x4c544',
                      initial_value=0, target_segment='R E', write_protection_control=True),
        relocation_types=dict(Counter(str(info & 0xffffffff) for _, info, _ in rel)),
        constructor_array=dict(begin=hex(ctors[0]), end=hex(ctors[1]), empty=True),
        unresolved_initialization_imports=imports, public_configure_controls=configs,
        get_version_controls=versions, boot_fragment_controls=boots, one_time_guard_controls=guard_controls,
        twrp_reference=dict(qcom_init_sha256=hashlib.sha256(rc.read_bytes()).hexdigest(),
            listeners_before_keymint=True, constructor_waits_for_listeners=True,
            loader='keymaster64 then keymaster from /vendor/firmware_mnt/image',
            named_initialize='0x66c0 returns immediately; no boot setup',
            boot_parameter_provider_proven=False),
        limits=['Relocated image default selector is zero; actual secure loader protections/relocations were not read back.',
                'cmnlib_init/GPAppLib_init/GPAppLib_appInit not executed or modeled as successful.',
                'Image boot0 + b490/public configure do not establish real post-SDK runtime boot0.',
                'Post-parse boot fragment is partial and may write ready state before completion; not an authorized command sender.',
                'TWRP init ordering/library constructor is not a trace of boot parameter provenance.',
                'No phone, real boot record/blob, KeyMint command, generation, upgrade, SMC or persistence.'],
        sources={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    (a.output/'audit.json').write_text(json.dumps(result, indent=2)+'\n')
    print('PASS selector RELA/RX proof, 2 configure controls, 3 version controls, 7 partial boot conversions; no device')


if __name__ == '__main__':
    main()
