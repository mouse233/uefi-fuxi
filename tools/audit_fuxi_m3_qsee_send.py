#!/usr/bin/env python3
"""Execute pinned QSEECom_send_cmd in isolated Unicorn with a mock object invoke."""
import argparse, hashlib, json, pathlib, struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X30)
from audit_fuxi_m3_ta_contract import build_send_request

PIN='5c996c509fdab3e5925af52f59d554bf54a7c54743c668017a83ef0d1b4e65ed'

def emulate(binary,elf_class):
    raw=binary.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN: raise ValueError('vendor binary digest mismatch')
    if raw[:7]!=b'\x7fELF\x02\x01\x01': raise ValueError('ELF64 little endian required')
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); base=0x1000000;u.mem_map(base,0x100000)
    off=struct.unpack_from('<Q',raw,32)[0];ents,n=struct.unpack_from('<HH',raw,54)
    if ents!=56 or n>32 or off+ents*n>len(raw): raise ValueError('bad ELF header')
    for i in range(n):
        kind,flags,pos,va,_,size,memsize,_=struct.unpack_from('<IIQQQQQQ',raw,off+i*ents)
        if kind==1:
            if pos+size>len(raw) or va+memsize>0x100000 or size>memsize: raise ValueError('ELF segment bounds')
            u.mem_write(base+va,raw[pos:pos+size])
    u.mem_map(0x3000000,0x30000);u.mem_map(0x4000000,0x20000)
    obj,data,stop=0x3000000,0x3010000,0x300f000
    u.mem_write(obj+0x18,struct.pack('<QQ',base+0xd2d0,0x3002000))
    u.mem_write(obj+0x38,struct.pack('<I',elf_class))
    u.mem_write(data,bytes.fromhex('21310000a10b18c8'))
    for reg,value in [(UC_ARM64_REG_X0,obj),(UC_ARM64_REG_X1,data),(UC_ARM64_REG_X2,8),
                      (UC_ARM64_REG_X3,data+8),(UC_ARM64_REG_X4,0x9ff8),
                      (UC_ARM64_REG_X30,stop),(UC_ARM64_REG_SP,0x401f000),(UC_ARM64_REG_TPIDR_EL0,0x4001000)]:
        u.reg_write(reg,value)
    calls=[]
    def hook(emu,addr,size,unused):
        if addr==base+0xd2d0:
            ptr=emu.reg_read(UC_ARM64_REG_X2)
            args=[struct.unpack('<QQ',emu.mem_read(ptr+i*16,16)) for i in range(10)]
            op,counts=emu.reg_read(UC_ARM64_REG_X1),emu.reg_read(UC_ARM64_REG_X3)
            expected=[(data,8),(data+8,0x9ff8),(0,0)]
            if op!=0 or counts!=0x424 or args[:3]!=expected or args[3][1]!=4:
                raise ValueError('unexpected invoke inputs')
            if int.from_bytes(emu.mem_read(args[3][0],4),'little') != (elf_class==2): raise ValueError('is64 mismatch')
            if args[4:6]!=expected[:2] or any(x!=(0,0) for x in args[6:]): raise ValueError('unexpected output/object arguments')
            if bytes(emu.mem_read(args[0][0],8))!=bytes.fromhex('21310000a10b18c8'): raise ValueError('unexpected request')
            calls.append({'op':op,'counts':hex(counts),'request_bytes':8,'response_capacity':hex(0x9ff8),
                          'is64':int(elf_class==2),'output_aliases_input':True,'null_input_objects':4})
            emu.reg_write(UC_ARM64_REG_X0,0);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(base+0xd1e0,stop,count=100000)
    if u.reg_read(UC_ARM64_REG_PC)!=stop or u.reg_read(UC_ARM64_REG_X0)!=0 or len(calls)!=1: raise ValueError('vendor function failed')
    return calls[0]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=pathlib.Path,required=True);p.add_argument('--report',type=pathlib.Path,required=True);a=p.parse_args()
    calls=[emulate(a.library,n) for n in (2,1)]
    model=build_send_request(4,bytes.fromhex('21310000a10b18c8'),0x9ff8,True)
    expected=[(0x60,8),(0x68,0x9ff8),(0xa060,0),(0xa060,4),(0xa068,8),(0xa070,0x9ff8)]
    if model['counts']!=0x424 or [(d['offset'],d['size']) for d in model['descriptors']]!=expected:raise ValueError('reference marshaler mismatch')
    report={'result':'passed','library_sha256':PIN,'class2':calls[0],'class1_control':calls[1],
            'model_descriptors':expected,'scope':'Pinned A16 QSEECom function executed in Unicorn with mocked object invoke; no TA, device, kernel marshal, cache or secure-world behavior.'}
    a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
