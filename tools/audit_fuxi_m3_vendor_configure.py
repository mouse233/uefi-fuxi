#!/usr/bin/env python3
"""Bounded emulation of the OTA KeyMint configure control flow; no TA or device."""
import argparse,hashlib,json,pathlib,struct
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_TPIDR_EL0,
 UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X30)
PIN='368b34db8efee95d1713cee10d823e8572f6668ef559867c67e292dc3b9e8c52'

def run(path,set_status,send_status):
 b=path.read_bytes()
 if hashlib.sha256(b).hexdigest()!=PIN:raise ValueError('fixed OTA library hash mismatch')
 if b[:7]!=b'\x7fELF\x02\x01\x01':raise ValueError('expected ELF64')
 base=0x1000000;u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,0x80000);u.mem_map(0x3000000,0x30000);u.mem_map(0x4000000,0x20000)
 off=struct.unpack_from('<Q',b,32)[0];size,count=struct.unpack_from('<HH',b,54)
 if size!=56 or count>32 or off+size*count>len(b):raise ValueError('invalid ELF header')
 for i in range(count):
  kind,flags,pos,va,_,sz,ms,_=struct.unpack_from('<IIQQQQQQ',b,off+i*size)
  if kind==1:
   if pos+sz>len(b) or sz>ms or va+ms>0x80000:raise ValueError('invalid ELF segment')
   u.mem_write(base+va,b[pos:pos+sz])
 u.mem_write(0x3000000,struct.pack('<Q',base+0x3e470));u.mem_write(0x3000010,struct.pack('<Q',0x3001000));u.mem_write(0x3001000,struct.pack('<Q',0x3002000))
 for reg,val in [(UC_ARM64_REG_X0,0x3000000),(UC_ARM64_REG_X1,0x3004000),(UC_ARM64_REG_X30,0x300f000),(UC_ARM64_REG_SP,0x401f000),(UC_ARM64_REG_TPIDR_EL0,0x4001000)]:u.reg_write(reg,val)
 calls=[]; names={0x3c530:'log',0x3c488:'cfi',0x3d5e0:'isLegacy',0x3d568:'setVersion',0x3d580:'init',0x3d5f8:'serialize',0x3d5b0:'send'}
 def hook(emu,addr,size,unused):
  name=names.get(addr-base)
  if name:
   arg=emu.reg_read(UC_ARM64_REG_X1)
   if name=='init' and arg!=0x2116:raise ValueError('unexpected configure command')
   calls.append(name)
   emu.reg_write(UC_ARM64_REG_X0,set_status if name=='setVersion' else send_status if name=='send' else 0)
   emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(base+0x2e3c0,0x300f000,count=10000)
 if u.reg_read(UC_ARM64_REG_PC)!=0x300f000:raise ValueError('did not return')
 result=u.reg_read(UC_ARM64_REG_X0)&0xffffffff
 expected=['cfi','isLegacy','setVersion','cfi','init','serialize','cfi','send']+(['log','log'] if send_status else [])
 if calls!=expected or result!=(send_status & 0xffffffff):raise ValueError('unexpected configure control flow')
 return {'setVersion_status':hex(set_status),'configure_send_status':hex(send_status),'calls':calls,'configure_return':hex(result)}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=pathlib.Path,required=True);p.add_argument('--report',type=pathlib.Path,required=True);a=p.parse_args()
 report={'result':'passed','library_sha256':PIN,'controls':[run(a.library,0,0),run(a.library,0xffffffd8,0),run(a.library,0xffffffd8,0xffffffe4)],
 'scope':'OTA vendor configure control flow executed in Unicorn with mocked isLegacy, setVersion, serialization and send. No device/TA; mock success does not validate configuration or safety. It does not justify ignoring a failure in the UEFI diagnostic.'}
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
