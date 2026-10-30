#!/usr/bin/env python3
"""Private SDK/TA fragments, stopping BEFORE every external service.

Only fixed public synthetic frames/TLS are supplied. Negative return-site
injections are counterfactuals, never real service results or completed init.
No phone, key/blob or vendor native execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn import arm64_const as r
import audit_fuxi_m3_metadata_read as ta
from audit_fuxi_m3_boot_client import machine as ta_machine,dynamic,relocations
from audit_fuxi_m3_key_recovery import elf_bytes
from audit_fuxi_m3_sdk_reference import TZ_SHA

SDK=0xd860f000
TLS=ta.SCRATCH+0x10000
STACK=0x401f000
STOPS={SDK+0x19b0,SDK+0x19d0,SDK+0x19f0,SDK+0x1a50,
       SDK+0x311a4,SDK+0x2e014,SDK+0x86b00,SDK+0x44}


def sdk_symbols(tz):
    d={}
    for off in range(0,0x200,16):
        tag,value=struct.unpack('<QQ',elf_bytes(tz,SDK+0x89000+off,16))
        if not tag:break
        d[tag]=value
    strings=elf_bytes(tz,SDK+d[5],d[10]);count=struct.unpack('<II',elf_bytes(tz,SDK+d[4],8))[1]
    assert count==468
    result={}
    for i in range(count):
        off,info,other,section,value,size=struct.unpack('<IBBHQQ',elf_bytes(tz,SDK+d[6]+i*24,24))
        name=strings[off:].split(b'\0',1)[0].decode()
        if name in ('cmnlib_init','GPAppLib_init','GPAppLib_appInit','qsee_is_sw_fuse_blown','qsee_cfg_getpropval'):
            assert info==0x12 and section==1
            result[name]=dict(relative=value,bytes=size)
    assert {k:v['relative'] for k,v in result.items()}==dict(cmnlib_init=0x3178,GPAppLib_init=0x1071c,
        GPAppLib_appInit=0x1091c,qsee_is_sw_fuse_blown=0x32258,qsee_cfg_getpropval=0x2d8d4)
    return result


def machine(raw,tz,symbols):
    if len(tz)!=3973120 or hashlib.sha256(tz).hexdigest()!=TZ_SHA:raise ValueError('fixed TZ mismatch')
    u=ta_machine(raw);u.mem_map(SDK,0xa0000)
    ph=struct.unpack_from('<Q',tz,32)[0];size,count=struct.unpack_from('<HH',tz,54)
    assert size==56 and count==40
    for i in range(count):
        kind,flags,off,va,pa,n,mem,align=struct.unpack_from('<IIQQQQQQ',tz,ph+i*size)
        if kind==1 and va in (SDK,SDK+0x87000,SDK+0x89000):
            assert va+mem<=SDK+0xa0000
            u.mem_write(va,tz[off:off+n])
            if flags&1:u.fuxi_code_ranges.append((va,va+n))
    # Bind only the two exact, symbol-checked imports used in these fragments.
    d=dynamic(raw);strings=elf_bytes(raw,d[5],d[10]);imports={}
    for off,info,add in relocations(raw,d,23,2):
        if off not in (0x5a160,0x5a190):continue
        at=struct.unpack_from('<I',elf_bytes(raw,d[6]+(info>>32)*24,24))[0]
        name=strings[at:].split(b'\0',1)[0].decode();imports[off]=name
        u.mem_write(ta.BASE+off,struct.pack('<Q',SDK+symbols[name]['relative']))
    assert imports=={0x5a160:'qsee_cfg_getpropval',0x5a190:'qsee_is_sw_fuse_blown'}
    u.reg_write(r.UC_ARM64_REG_TPIDRRO_EL0,TLS)
    u.reg_write(r.UC_ARM64_REG_SP,STACK);u.reg_write(r.UC_ARM64_REG_X30,ta.STOP)
    return u


def execute(u,entry,*,preserve=False,stops=STOPS):
    result=dict(instructions=0,logs_suppressed=0,ta_boot_writes=[])
    def code(m,pc,_size,_ctx):
        result['instructions']+=1
        if pc in stops:
            result['stopped_before']=hex(pc);m.emu_stop();return
        if not any((lo<=pc-ta.BASE<hi) if lo<0x80000 else lo<=pc<hi for lo,hi in u.fuxi_code_ranges):
            raise ValueError('outside fixed code')
        instruction=struct.unpack('<I',m.mem_read(pc,4))[0]
        if instruction&0xffe0001f in (0xd4000001,0xd4000002,0xd4000003):
            raise ValueError('SVC/HVC/SMC forbidden')
        if instruction==0xdac107fe:m.reg_write(r.UC_ARM64_REG_PC,pc+4)
        elif instruction==0xd65f0fff:m.reg_write(r.UC_ARM64_REG_PC,m.reg_read(r.UC_ARM64_REG_X30))
        elif pc==ta.BASE+0x20:
            result['logs_suppressed']+=1;m.reg_write(r.UC_ARM64_REG_X0,0)
            m.reg_write(r.UC_ARM64_REG_PC,m.reg_read(r.UC_ARM64_REG_X30))
    def write(_m,_access,address,size,_value,_ctx):
        if address<ta.BASE+0x5b4f8 and address+size>ta.BASE+0x5b4f4:
            result['ta_boot_writes'].append(dict(address=hex(address),bytes=size))
    h=u.hook_add(UC_HOOK_CODE,code);w=u.hook_add(UC_HOOK_MEM_WRITE,write)
    try:
        if not preserve:u.reg_write(r.UC_ARM64_REG_SP,STACK);u.reg_write(r.UC_ARM64_REG_X30,ta.STOP)
        u.emu_start(entry,ta.STOP,count=20000)
        if 'stopped_before' not in result and u.reg_read(r.UC_ARM64_REG_PC)!=ta.STOP:
            raise ValueError('instruction bound reached')
    finally:u.hook_del(h);u.hook_del(w)
    value=u.reg_read(r.UC_ARM64_REG_X0)&0xffffffff
    result['return_status']=None if 'stopped_before' in result else value-(1<<32) if value&(1<<31) else value
    result['ta_boot_after']=struct.unpack('<I',u.mem_read(ta.BASE+0x5b4f4,4))[0]
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('partition','tz','identity','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--objdump',default='/opt/homebrew/opt/llvm/bin/llvm-objdump');a=p.parse_args()
    root=Path(__file__).resolve().parents[1];raw=a.partition.read_bytes();tz=a.tz.read_bytes()
    identity=json.loads(a.identity.read_text())
    assert identity['stable_snapshots']==2 and identity['properties']['ro.boot.slot_suffix']=='_a'
    assert identity['partitions']['tz_a']['sha256']==hashlib.sha256(tz+bytes(4194304-len(tz))).hexdigest()
    for name,digest in identity['sources'].items():assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest
    symbols=sdk_symbols(tz);controls=[]
    for present in (False,True):
        u=machine(raw,tz,symbols);context=ta.SCRATCH+0x6000;data=bytearray(216)
        struct.pack_into('<I',data,0,0x20001)
        if present:struct.pack_into('<QQ',data,24,ta.STOP,7)
        u.mem_write(context,bytes(data));u.reg_write(r.UC_ARM64_REG_X0,context)
        row=execute(u,SDK+0x3178)
        assert row['stopped_before']==hex(SDK+(0x19b0 if present else 0x44))
        assert not row['ta_boot_writes'] and row['ta_boot_after']==0
        controls.append(dict(case='cmnlib-context-object-'+str(present),synthetic_object_present=present,execution=row))
    u=machine(raw,tz,symbols);row=execute(u,SDK+0x1071c)
    assert row['stopped_before']==hex(SDK+0x311a4) and u.reg_read(r.UC_ARM64_REG_X0)==56
    controls.append(dict(case='GPAppLib-init-allocator-boundary',requested_bytes=56,execution=row))
    # Execute appInit up to its first object invocation. Synthetic TLS object
    # pair is an opaque private placeholder, never a real service capability.
    for injected in (-1,-65536):
        u=machine(raw,tz,symbols);u.mem_write(TLS+0x58,struct.pack('<QQ',ta.STOP,7))
        before=execute(u,SDK+0x1091c)
        assert before['stopped_before']==hex(SDK+0x19f0)
        desc=u.reg_read(r.UC_ARM64_REG_X2);out,size=struct.unpack('<QQ',u.mem_read(desc,16))
        assert u.reg_read(r.UC_ARM64_REG_X1)==1 and u.reg_read(r.UC_ARM64_REG_X3)==0x10 and size==4
        u.reg_write(r.UC_ARM64_REG_X0,injected&0xffffffff)
        after=execute(u,SDK+0x1095c,preserve=True)
        assert after['return_status']==0 and struct.unpack('<II',u.mem_read(TLS+0x90,8))==(0xffff0000,3)
        assert not after['ta_boot_writes'] and after['ta_boot_after']==0
        controls.append(dict(case='appInit-negative-return-site',injected_status=injected,operation=1,counts='0x10',
                             output_capacity=4,before_service=before,counterfactual_suffix=after,tls_result='ffff0000',tls_state=3))
    u=machine(raw,tz,symbols);u.reg_write(r.UC_ARM64_REG_X0,ta.SCRATCH+0x7000)
    row=execute(u,ta.BASE+0x194fc)
    assert row['stopped_before']==hex(SDK+0x2e014) and u.reg_read(r.UC_ARM64_REG_X0)==22
    assert u.reg_read(r.UC_ARM64_REG_X22)==1 and u.reg_read(r.UC_ARM64_REG_X23)==1
    controls.append(dict(case='208-precondition-software-fuse',fuse_id=1,output_bytes=1,service_uid=22,execution=row))
    u=machine(raw,tz,symbols);u.reg_write(r.UC_ARM64_REG_X0,ta.SCRATCH+0x7000)
    before=execute(u,ta.BASE+0x18d4c)
    assert before['stopped_before']==hex(SDK+0x86b00)
    assert u.reg_read(r.UC_ARM64_REG_X0)&0xffffffff==(-95)&0xffffffff
    pointer=u.reg_read(r.UC_ARM64_REG_X1)
    assert bytes(u.mem_read(pointer,16))==b'enable_spu_uefi\0'
    assert u.reg_read(r.UC_ARM64_REG_X2)==16 and u.reg_read(r.UC_ARM64_REG_X5)==12
    # Negative service return-site only: no service is executed, not even an
    # initializer modeled as successful. The TA wrapper caches fallback zero.
    u.reg_write(r.UC_ARM64_REG_X0,0xffffffff)
    after=execute(u,ta.BASE+0x18dc0,preserve=True)
    assert u.mem_read(ta.BASE+0x5b588,1)[0]==1 and struct.unpack('<I',u.mem_read(ta.BASE+0x5b58c,4))[0]==0
    assert struct.unpack('<I',u.mem_read(ta.SCRATCH+0x7000,4))[0]==0
    controls.append(dict(case='boot-completion-property-boundary',property='enable_spu_uefi',syscall_id=-95,
                         output_capacity=12,before_service=before,injected_negative_status=-1,counterfactual_suffix=after,cached_fallback=0))
    for cached in (0,1):
        u=machine(raw,tz,symbols);u.mem_write(ta.BASE+0x5b588,b'\1');u.mem_write(ta.BASE+0x5b58c,struct.pack('<I',cached))
        u.reg_write(r.UC_ARM64_REG_X0,ta.SCRATCH+0x7000);row=execute(u,ta.BASE+0x18d4c)
        assert 'stopped_before' not in row and struct.unpack('<I',u.mem_read(ta.SCRATCH+0x7000,4))[0]==cached
        controls.append(dict(case='synthetic-cached-spu-property',value=cached,execution=row))
    boundary=[]
    for instruction,label in ((0xd4000003,'SMC'),(0xd4028001,'SVC'),(0x14000000,'loop')):
        u=machine(raw,tz,symbols);u.mem_write(SDK+0x1071c,struct.pack('<I',instruction))
        try:execute(u,SDK+0x1071c)
        except ValueError as e:assert ('forbidden' if label!='loop' else 'bound reached') in str(e)
        else:raise AssertionError('external execution accepted')
        boundary.append(label)
    changed=bytearray(tz);changed[-1]^=1
    try:machine(raw,changed,symbols)
    except ValueError:boundary.append('modified-TZ')
    else:raise AssertionError('changed TZ accepted')
    a.output.mkdir(parents=True,exist_ok=True);evidence={}
    ranges={'sdk-app-init':(a.tz,SDK+0x1091c,SDK+0x109a0),'sdk-cmnlib-init':(a.tz,SDK+0x3178,SDK+0x341c),
            'sdk-gp-init':(a.tz,SDK+0x1071c,SDK+0x1091c),'sdk-fuse':(a.tz,SDK+0x32258,SDK+0x32360),
            'sdk-property':(a.tz,SDK+0x2d8d4,SDK+0x2d908),'sdk-syscall':(a.tz,SDK+0x86b00,SDK+0x86b70),
            'ta-boot-fuse':(a.partition,0x194fc,0x195a0),'ta-spu-property':(a.partition,0x18d4c,0x18e38)}
    for name,(path,lo,hi) in ranges.items():
        data=elf_bytes(tz if path==a.tz else raw,lo,hi-lo)
        (a.output/(name+'.asm')).write_text(subprocess.check_output([a.objdump,'-d','--start-address='+hex(lo),'--stop-address='+hex(hi),str(path)],text=True,stderr=subprocess.PIPE))
        evidence[name]=dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(data).hexdigest())
    files=[Path(__file__),root/'tools/audit_fuxi_m3_boot_client.py',root/'tools/audit_fuxi_m3_metadata_read.py',
           root/'tools/audit_fuxi_m3_key_recovery.py',root/'tools/audit_fuxi_m3_sdk_reference.py',
           root/'tools/audit_fuxi_m3_begin_version.py',root/'tools/audit_fuxi_m3_configure_gate.py']
    report=dict(result='passed',ta_sha256=ta.TA_SHA,tz_sha256=TZ_SHA,identity_sha256=hashlib.sha256(a.identity.read_bytes()).hexdigest(),
                sdk_relocations_applied=False,full_sdk_initialization_executed=False,
                symbols=symbols,controls=controls,boundary_controls=boundary,evidence=evidence,
                limits=['Only private synthetic public TLS/frames. Every external object/allocator/syscall stopped before execution.',
                        'SDK mapped at fixed TZ virtual addresses for these TLS/argument-only fragments; no complete SDK relocation/load model.',
                        'Negative return-site injections are counterfactuals, not observed service results or successful initialization.',
                        'appInit returning zero alone does not prove its external operation succeeded; TLS can retain an error.',
                        'Fragment boot remains zero; cmnlib/GP init and platform/completion were not fully executed.',
                        'No actual TA instance reuse/freshness, boot context inheritance, -62 return PC or M3/M4/M5 proof.'],
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    (a.output/'sdk-audit.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS 9 SDK/TA fragment controls + 4 execution boundaries; every service stopped')


if __name__=='__main__':main()
