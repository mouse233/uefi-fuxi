#!/usr/bin/env python3
"""Emulate pinned vendor serializeInteger/QCBOR only; no device or TA calls."""
import argparse
import hashlib
import json
import pathlib
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from audit_fuxi_m3_ta_contract import build_send_request
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X30)

PINS = {'libqtikeymint.so':'657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb',
        'libqcbor.so':'bda86553e45dce1da186830619909b3bae95ff9a91ce3a5df94fa0801c8b2500',
        'libkeymasterdeviceutils.so':'1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2'}
ROOT = pathlib.Path(__file__).resolve().parents[1]

def verify(name, data):
    if hashlib.sha256(data).hexdigest() != PINS[name]:
        raise ValueError('fixed binary hash mismatch: '+name)

def run(libs):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    qt, qc = 0x1000000, 0x2000000
    for name, base in [('libqtikeymint.so', qt), ('libqcbor.so', qc)]:
        data = (libs / name).read_bytes(); verify(name, data)
        mutated = bytearray(data); mutated[-1] ^= 1
        try: verify(name, mutated)
        except ValueError: pass
        else: raise AssertionError('mutated binary accepted')
        if data[:7] != b'\x7fELF\x02\x01\x01': raise ValueError('expected ELF64 little endian')
        phoff = struct.unpack_from('<Q', data, 32)[0]
        ents, count = struct.unpack_from('<HH', data, 54)
        if ents != 56 or count > 32 or phoff + ents * count > len(data): raise ValueError('bad program table')
        u.mem_map(base, 0x80000)
        for i in range(count):
            kind, flags, offset, va, _, size, memsize, _ = struct.unpack_from('<IIQQQQQQ', data, phoff+i*ents)
            if kind == 1:
                if offset + size > len(data) or va + memsize > 0x80000 or size > memsize: raise ValueError('segment outside bound')
                u.mem_write(base+va, data[offset:offset+size])
    u.mem_map(0x3000000, 0x20000); u.mem_map(0x4000000, 0x20000)
    blob, buf, stop = 0x3000000, 0x3010000, 0x300f000
    u.mem_write(blob, struct.pack('<QQ', buf, 4096))
    u.reg_write(UC_ARM64_REG_SP, 0x401f000); u.reg_write(UC_ARM64_REG_TPIDR_EL0, 0x4001000)
    u.reg_write(UC_ARM64_REG_X0, 0); u.reg_write(UC_ARM64_REG_X1, 200)
    u.reg_write(UC_ARM64_REG_X2, blob); u.reg_write(UC_ARM64_REG_X30, stop)
    redirect = {qt+0x3de38:qc+0x3fd0, qt+0x3dee0:qc+0x4020,
                qt+0x3de50:qc+0x4040, qt+0x3de68:qc+0x4030,
                qt+0x3de80:qc+0x4090, qc+0x4198:qc+0x3fe0, qc+0x41b0:qc+0x4120}
    reached = []
    def hook(emu, address, size, unused):
        if address in redirect:
            reached.append(address); emu.reg_write(UC_ARM64_REG_PC, redirect[address]); return
        if address in (qc+0x41f8, qc+0x4240, qc+0x4258):
            dst=emu.reg_read(UC_ARM64_REG_X0); src=emu.reg_read(UC_ARM64_REG_X1); length=emu.reg_read(UC_ARM64_REG_X2)
            if length > 4096: raise ValueError('libc operation exceeds bound')
            if length:
                data=bytes([src & 255])*length if address==qc+0x4258 else bytes(emu.mem_read(src,length))
                emu.mem_write(dst,data)
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_X30)); return
        if address in (qc+0x4270, qc+0x4228, qt+0x3df88): raise RuntimeError('vendor abort/stack failure')
    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(qt+0x386fc, stop, count=1000000)
    if u.reg_read(UC_ARM64_REG_PC)!=stop or u.reg_read(UC_ARM64_REG_X0)!=0: raise ValueError('encoder did not return successfully')
    length=struct.unpack('<Q',u.mem_read(blob+8,8))[0]
    if length>4096: raise ValueError('encoder output length exceeds buffer')
    raw=bytes(u.mem_read(buf,length))
    if raw != bytes.fromhex('a10b18c8'): raise ValueError('unexpected vendor output: '+raw.hex())
    if not {qt+0x3de38,qt+0x3dee0,qt+0x3de50,qt+0x3de68,qt+0x3de80}.issubset(reached): raise ValueError('expected encoder calls missing')
    source=ROOT/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3SmciDiagnostic.inc'
    if 'SmciPut32(Page+0x64,0xc8180ba1U)' not in source.read_text(): raise ValueError('production candidate encoding differs')
    model=build_send_request(4,bytes.fromhex('21310000')+raw,0x9ff8,True)
    expected_desc=[(0x60,8),(0x68,0x9ff8),(0xa060,0),(0xa060,4),(0xa068,8),(0xa070,0x9ff8)]
    if model['counts']!=0x424 or model['page_bytes']!=0x15000 or [(d['offset'],d['size']) for d in model['descriptors']]!=expected_desc:
        raise ValueError('reference request layout mismatch')
    for token in ('SmciPut32(Page+12,0x60); SmciPut32(Page+16,8)',
                  'SmciPut32(Page+20,0x68); SmciPut32(Page+24,0x9ff8)',
                  'SmciPut32(Page+28,0xa060); SmciPut32(Page+32,0)',
                  'SmciPut32(Page+36,0xa060); SmciPut32(Page+40,4)',
                  'SmciPut32(Page+44,0xa068); SmciPut32(Page+48,8)',
                  'SmciPut32(Page+52,0xa070); SmciPut32(Page+56,0x9ff8)',
                  'SmciPut32(Page+0x60,0x3121)', 'SmciPut32(Page+0xa060,1)'):
        if token not in source.read_text(): raise ValueError('production layout mismatch: '+token)
    # Reproduce isLegacy with the fields printed by the getVersion diagnostic.
    # The vendor constructor stores response word 0 in state+4 and word 1 in state+8.
    data=(libs/'libkeymasterdeviceutils.so').read_bytes(); verify('libkeymasterdeviceutils.so', data)
    mutated=bytearray(data); mutated[-1]^=1
    try: verify('libkeymasterdeviceutils.so',mutated)
    except ValueError: pass
    else: raise AssertionError('mutated deviceutils accepted')
    v=Uc(UC_ARCH_ARM64,UC_MODE_ARM); v.mem_map(0x5000000,0x80000); v.mem_map(0x6000000,0x10000)
    phoff=struct.unpack_from('<Q',data,32)[0]; ents,count=struct.unpack_from('<HH',data,54)
    if ents != 56 or count > 32 or phoff + ents*count > len(data): raise ValueError('bad deviceutils program table')
    for i in range(count):
        kind,flags,offset,va,_,size,memsize,_=struct.unpack_from('<IIQQQQQQ',data,phoff+i*ents)
        if kind==1:
            if offset+size>len(data) or va+memsize>0x80000 or size>memsize: raise ValueError('deviceutils segment outside bound')
            v.mem_write(0x5000000+va,data[offset:offset+size])
    vectors=[(4,1,0),(4,0,1),(3,0,1),(5,0,0)]
    for major,minor,expected in vectors:
        v.mem_write(0x6000000,struct.pack('<QQ',0,0x6001000))
        v.mem_write(0x6001004,struct.pack('<II',major,minor))
        v.reg_write(UC_ARM64_REG_X0,0x6000000);v.reg_write(UC_ARM64_REG_X30,0x600f000)
        v.emu_start(0x5000000+0x6708,0x600f000,count=1000)
        if v.reg_read(UC_ARM64_REG_PC)!=0x600f000 or v.reg_read(UC_ARM64_REG_X0)!=expected: raise ValueError('isLegacy vector failed')
    return {'result':'passed','integer':200,'encoded_hex':raw.hex(),'bytes':length,'input_sha256':PINS,
            'model_counts':'0x424','model_page_bytes':'0x15000','model_descriptors':expected_desc,
            'is_legacy_vectors':vectors,'photographed_get_version_fields':[4,1,4,1012],
            'inferred_is_legacy':False,
            'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'scope':'Isolated Unicorn execution of pinned vendor serializer and QCBOR, with bounded libc hooks; no TA or device. Does not verify request transport or error cause.',
            'mutated_inputs_rejected':True}

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--ramdisk',type=pathlib.Path,required=True);p.add_argument('--report',type=pathlib.Path,required=True); a=p.parse_args()
    result=run(a.ramdisk/'vendor/lib64'); a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
