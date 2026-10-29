#!/usr/bin/env python3
"""Emulate the pinned TA dispatcher with bounded stubs, without secure-world calls."""
import argparse, hashlib, json, pathlib, struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0,
 UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X25, UC_ARM64_REG_X30)
PIN='2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6'
BASE=0x1000000

def run(binary, command, expected_found, initialized=True):
 b=binary.read_bytes()
 if len(b)!=524288 or hashlib.sha256(b).hexdigest()!=PIN:raise ValueError('fixed partition mismatch')
 if b[:7]!=b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H',b,18)[0]!=183:raise ValueError('expected AArch64 ELF')
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(BASE,0x80000);u.mem_map(0x3000000,0x30000);u.mem_map(0x4000000,0x20000)
 off=struct.unpack_from('<Q',b,32)[0];ents,n=struct.unpack_from('<HH',b,54)
 if ents!=56 or n>32 or off+ents*n>len(b):raise ValueError('invalid ELF table')
 for i in range(n):
  kind,flags,pos,va,_,size,memsize,_=struct.unpack_from('<IIQQQQQQ',b,off+i*ents)
  if kind==1:
   if pos+size>len(b) or size>memsize or va+memsize>0x80000:raise ValueError('invalid segment')
   u.mem_write(BASE+va,b[pos:pos+size])
 table=BASE+0x5a5e0;rows=[struct.unpack('<IIQ',u.mem_read(table+i*16,16)) for i in range(89)]
 found=[row for row in rows if row[0]==command]
 if bool(found)!=expected_found:raise ValueError('unexpected table membership')
 descriptor=0x3001000;data=0x3010000;input_addr=0x3002000;stop=0x300f000
 u.mem_write(descriptor,struct.pack('<QQ',data,0x9ff8));u.mem_write(input_addr,struct.pack('<I',command)+bytes.fromhex('a10b18c8'))
 u.mem_write(BASE+0x5a2f8,struct.pack('<Q',0x3005000)) # mock stack guard pointer
 for reg,value in [(UC_ARM64_REG_X0,input_addr),(UC_ARM64_REG_X1,8),(UC_ARM64_REG_X2,descriptor),
                   (UC_ARM64_REG_X30,stop),(UC_ARM64_REG_SP,0x401f000)]:u.reg_write(reg,value)
 observed={'scan_iterations':0,'miss':False,'match':False}
 def hook(emu,addr,size,unused):
  word=struct.unpack('<I',emu.mem_read(addr,4))[0]
  # Unicorn cannot execute this firmware's PACIB/RETAB; model control flow only.
  if word==0xdac107fe:emu.reg_write(UC_ARM64_REG_PC,addr+4);return
  if word==0xd65f0fff:emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30));return
  if addr==BASE+0xb318:observed['scan_iterations']+=1
  if addr==BASE+0xb344:observed['miss']=True
  if addr==BASE+0xb3c0:
   entry=emu.reg_read(UC_ARM64_REG_X25)-4
   item=struct.unpack('<IIQ',emu.mem_read(entry,16))
   if item[0]!=command:raise ValueError('matched wrong command')
   observed.update(match=True,handler=hex(item[2]));emu.emu_stop();return
  if addr in (BASE+0xdd30,BASE+0x40,BASE+0xd01c,BASE+0x20,BASE+0x4474c):
   if addr==BASE+0x4474c:
    dst=emu.reg_read(UC_ARM64_REG_X0);v=emu.reg_read(UC_ARM64_REG_X1);length=emu.reg_read(UC_ARM64_REG_X2)
    if not data<=dst<=data+0x9ff8 or length>data+0x9ff8-dst:raise ValueError('memset outside output')
    if length:emu.mem_write(dst,bytes([v&255])*length)
   emu.reg_write(UC_ARM64_REG_X0,(int(initialized) if addr==BASE+0xdd30 else 1 if addr==BASE+0x40 else 0))
   emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(BASE+0xb0b4,stop,count=200000)
 if expected_found:
  if not observed['match'] or observed['miss']:raise ValueError('expected table match absent')
 else:
  if u.reg_read(UC_ARM64_REG_PC)!=stop or observed['match']:raise ValueError('unexpected dispatcher result')
  status,length=struct.unpack('<II',u.mem_read(data,8));observed.update(response_status=hex(status),response_payload_field=hex(length))
  if initialized:
   if not observed['miss'] or status!=0xffffffd8 or length!=0x9ff0 or observed['scan_iterations']!=89:raise ValueError('unexpected no-match response')
  elif observed['miss'] or observed['scan_iterations'] or status!=0xfffffc18 or length!=0x9ff0:raise ValueError('initialization control mismatch')
 return observed

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--partition',type=pathlib.Path,required=True);p.add_argument('--report',type=pathlib.Path,required=True);a=p.parse_args()
 r={'result':'passed','partition_sha256':PIN,'set_version_3121':run(a.partition,0x3121,False),
    'uninitialized_3121':run(a.partition,0x3121,False,False),
    'known_get_version_0200':run(a.partition,0x200,True),'known_3120':run(a.partition,0x3120,True),
    'scope':'Pinned TA command wrapper and dispatch executed with initialization/time/log/memset stubs; PAC modeled, no handler, firmware, device or secure world. The table and output explain the observed pattern if this wrapper handles that request, but do not independently prove device runtime control flow.'}
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
if __name__=='__main__':main()
