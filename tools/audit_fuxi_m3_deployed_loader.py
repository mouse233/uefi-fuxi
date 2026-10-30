#!/usr/bin/env python3
"""Matched TZ UID122 dispatcher/cache audit. No phone or secure calls.

Synthetic private cache nodes and bounded ordinary heap/copy models only.
Registry lookup, authentication, TA loading, RPC and new TA execution all stop.
Passing a fragment is not evidence of actual registry/cache/instance state.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ
from unicorn import arm64_const as r
from audit_fuxi_m3_key_recovery import elf_bytes
from audit_fuxi_m3_sdk_reference import TZ_SHA

START=0x15646000
DATA=0x3000000
STACK=0x401f000
HALT=DATA+0x1f000
ROOT1,ROOT2=0x157acf50,0x157acf60
INVOKE=0x1569d918
RANGES=[(INVOKE,0x1569dd88),(0x156934d0,0x1569355c),(0x1569dff0,0x1569e068),
        (0x15648ff0,0x1564905c),(0x1564992c,0x1564995c),(0x15733490,0x15733520),
        (0x157335a8,0x157337b8),(0x157337b8,0x15733820),(0x15731cdc,0x15731ce8),
        (0x1569d4c4,0x1569d500)]
STOPS={0x15732c18,0x15733820,0x15686d04,0x1569ddf8,0x1573061c,0x157350f0,
       0x15654e6c,0x1564ba38,0x15733520,0x157333d0}


def machine(tz,cache='none',arch=1):
    if len(tz)!=3973120 or hashlib.sha256(tz).hexdigest()!=TZ_SHA:raise ValueError('fixed TZ mismatch')
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(START,0x2ba000)
    u.mem_map(DATA,0x20000);u.mem_map(0x4000000,0x20000)
    ph=struct.unpack_from('<Q',tz,32)[0];size,count=struct.unpack_from('<HH',tz,54)
    assert size==56 and count==40
    for i in range(count):
        typ,flags,off,va,pa,n,mem,align=struct.unpack_from('<IIQQQQQQ',tz,ph+i*size)
        if typ==1 and START<=va<START+0x2ba000:
            assert va+mem<=START+0x2ba000
            u.mem_write(va,tz[off:off+n])
    # Private list state replaces unknown live registry/cache contents.
    for root in (ROOT1,ROOT2):u.mem_write(root,struct.pack('<QQ',root,root))
    node,app,name=DATA+0x3000,DATA+0x4000,DATA+0x5000
    u.mem_write(name,(b'other' if cache=='wrong-name' else b'keymaster64')+b'\0')
    u.mem_write(app+0x71,bytes([arch]))
    if cache!='none':
        root=ROOT2 if cache=='second' else ROOT1
        u.mem_write(root,struct.pack('<QQ',node,node))
        u.mem_write(node,struct.pack('<QQI',root,root,1))
        u.mem_write(node+0x18,struct.pack('<QQ',app,name))
    u.reg_write(r.UC_ARM64_REG_SP,STACK);u.reg_write(r.UC_ARM64_REG_X30,HALT)
    u.loader_allocations={};u.loader_heap=DATA+0x8000
    return u


def execute(u,entry,extra_stops=(),preserve=False):
    result=dict(instructions=0,models=[],name_reads=0,elf_reads=0)
    stops=STOPS|set(extra_stops)
    def ret(m,value):
        m.reg_write(r.UC_ARM64_REG_X0,value)
        m.reg_write(r.UC_ARM64_REG_PC,m.reg_read(r.UC_ARM64_REG_X30))
    def valid(pointer,n):return DATA<=pointer and n<=0x10000 and pointer+n<=DATA+0x10000
    def hook(m,pc,_size,_ctx):
        result['instructions']+=1
        if pc in stops:
            result['stopped_before']=hex(pc);m.emu_stop();return
        if pc==0x15683c34:
            n=m.reg_read(r.UC_ARM64_REG_X0)
            assert 1<=n<=65 and m.loader_heap+n<DATA+0x9000
            pointer=m.loader_heap;m.loader_heap+=(n+15)&~15;m.loader_allocations[pointer]=n
            m.mem_write(pointer,bytes(n));result['models'].append(dict(kind='private-heap',bytes=n));ret(m,pointer);return
        if pc==0x15683cf0:
            pointer=m.reg_read(r.UC_ARM64_REG_X0);assert pointer in m.loader_allocations
            n=m.loader_allocations.pop(pointer);m.mem_write(pointer,bytes(n))
            result['models'].append(dict(kind='private-free',bytes=n));ret(m,0);return
        if pc==0x15648df4:
            pointer,value,n=[m.reg_read(getattr(r,'UC_ARM64_REG_X'+str(i))) for i in range(3)]
            assert value==0 and m.loader_allocations.get(pointer)==n
            m.mem_write(pointer,bytes(n));result['models'].append(dict(kind='bounded-zero',bytes=n));ret(m,pointer);return
        if pc==0x1564876c:
            dst,cap,src,n=[m.reg_read(getattr(r,'UC_ARM64_REG_X'+str(i))) for i in range(4)]
            assert valid(dst,cap) and valid(src,n) and cap>=n and n<=64
            m.mem_write(dst,bytes(m.mem_read(src,n)))
            if src==DATA+0x1000:result['name_reads']+=1
            result['models'].append(dict(kind='bounded-copy',bytes=n));ret(m,n);return
        if not any(lo<=pc<hi for lo,hi in RANGES):raise ValueError('outside audited loader code: '+hex(pc))
        word=struct.unpack('<I',m.mem_read(pc,4))[0]
        if word&0xffe0001f in (0xd4000001,0xd4000002,0xd4000003):raise ValueError('SVC/HVC/SMC forbidden')
        if word==0xdac103fe:m.reg_write(r.UC_ARM64_REG_PC,pc+4)
        elif word==0xd65f0bff:m.reg_write(r.UC_ARM64_REG_PC,m.reg_read(r.UC_ARM64_REG_X30))
    def read(_m,_access,address,n,_value,_ctx):
        if DATA+0x1000<=address<DATA+0x1100:result['name_reads']+=1
        if DATA+0x2000<=address<DATA+0x2100:result['elf_reads']+=1
    h=u.hook_add(UC_HOOK_CODE,hook);m=u.hook_add(UC_HOOK_MEM_READ,read)
    try:
        if not preserve:u.reg_write(r.UC_ARM64_REG_SP,STACK);u.reg_write(r.UC_ARM64_REG_X30,HALT)
        u.emu_start(entry,HALT,count=50000)
        if 'stopped_before' not in result and u.reg_read(r.UC_ARM64_REG_PC)!=HALT:raise ValueError('instruction bound reached')
    finally:u.hook_del(h);u.hook_del(m)
    result['status']=None if 'stopped_before' in result else u.reg_read(r.UC_ARM64_REG_X0)&0xffffffff
    return result


def request(u,op,counts,bo_size=4,name=b'keymaster64'):
    args,context=DATA,DATA+0x6000
    u.mem_write(DATA+0x1000,name+b'\0');u.mem_write(DATA+0x2000,b'PUBLIC INVALID ELF\0')
    if op==2:
        u.mem_write(args,struct.pack('<QQQQQQ',DATA+0x1000,len(name),DATA+0x7000,bo_size,0,0))
    elif op==1:
        u.mem_write(args,struct.pack('<QQQQQQQQ',DATA+0x2000,18,DATA+0x1000,len(name),DATA+0x7000,64,0,0))
    u.mem_write(context,struct.pack('<QQQ',1,0,0))
    for i,v in enumerate((context,op,args,counts)):u.reg_write(getattr(r,'UC_ARM64_REG_X'+str(i)),v)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('tz','identity','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--objdump',default='/opt/homebrew/opt/llvm/bin/llvm-objdump');a=p.parse_args()
    root=Path(__file__).resolve().parents[1];tz=a.tz.read_bytes();identity=json.loads(a.identity.read_text())
    assert identity['result']=='captured' and identity['serial']=='fcde91e' and identity['boot_continuity_checked']
    assert identity['stable_snapshots']==2 and identity['properties']['ro.boot.slot_suffix']=='_a'
    for name,digest in identity['sources'].items():assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest
    assert identity['partitions']['tz_a']['sha256']==hashlib.sha256(tz+bytes(4194304-len(tz))).hexdigest()
    machine(tz)
    header=root/'out/m3-qsee-static-v1/sm8550-source/IQSEEComCompatAppLoader.h'
    assert hashlib.sha256(header.read_bytes()).hexdigest()=='597124e1769ab805fef0e947a4636dc043250ba368cc218557a339fd55122a06'
    native=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3SmciDiagnostic.inc'
    assert 'Lookup=TRUE;Op=2;Counts=0x1001;' in native.read_text()
    # Root UID122 routing/factory tail and its exact handler selection.
    edges=[(0x156a018c,0x1569d464,False),(0x1569db64,0x157335a8,True),
           (0x1569dbb0,0x1569ddf8,True),(0x1569da7c,0x156934d0,True),
           (0x1569dca8,0x1569dff0,True),(0x1569dcec,0x157335a8,True)]
    for pc,target,link in edges:
        word=struct.unpack('<I',elf_bytes(tz,pc,4))[0];assert word>>26==(0x25 if link else 5)
        imm=word&0x3ffffff
        if imm&0x2000000:imm-=0x4000000
        assert pc+imm*4==target
    factory=[]
    for uid,expected in ((122,INVOKE),(3,0x1569d518),(121,None)):
        u=machine(tz)
        for reg,v in ((r.UC_ARM64_REG_X21,uid),(r.UC_ARM64_REG_X20,DATA+0x6000),(r.UC_ARM64_REG_X19,DATA)):
            u.reg_write(reg,v)
        row=execute(u,0x1569d4c4,{0x1569d4f8,0x1569d500})
        pointer=struct.unpack('<Q',u.mem_read(DATA,8))[0]
        assert pointer==(expected or 0)
        factory.append(dict(uid=uid,selected_handler=hex(pointer),execution=row))
    formats=[]
    for name in (b'keymaster64',b'keymaster'):
        for counts,size in ((0x1001,4),(0x1011,3),(0x1011,8),(0x1011,4)):
            u=machine(tz);request(u,2,counts,size,name);row=execute(u,INVOKE)
            if counts==0x1011 and size==4:
                assert row.get('stopped_before')=='0x15732c18'
            else:assert row['status']==2 and row['name_reads']==0 and not row['models']
            formats.append(dict(name=name.decode(),counts=hex(counts),arch_output_capacity=size,execution=row))
    reused=[]
    for cache in ('first','second'):
        for arch in (0,1):
            u=machine(tz,cache,arch);request(u,2,0x1011)
            if cache=='second':
                # The first list may consult an unexecuted registry even when
                # empty. Only a negative result is injected at its return site
                # to isolate the second-list branch; never claim a real miss.
                paused=execute(u,INVOKE,{0x157336c8});assert paused['stopped_before']=='0x157336c8'
                u.reg_write(r.UC_ARM64_REG_X0,11)
                row=execute(u,0x157335fc,preserve=True)
            else:row=execute(u,INVOKE)
            assert row['status']==0 and struct.unpack('<I',u.mem_read(DATA+0x7000,4))[0]==arch+1
            pointer,context=struct.unpack('<QQ',u.mem_read(DATA+0x20,16))
            assert pointer==0x15733904 and context in u.loader_allocations
            assert struct.unpack('<Q',u.mem_read(context+8,8))[0]==DATA+0x3000
            assert struct.unpack('<I',u.mem_read(DATA+0x3010,4))[0]==2
            assert struct.unpack('<Q',u.mem_read(ROOT1,8))[0]==DATA+0x3000
            reused.append(dict(cache=cache,synthetic_arch_byte=arch,returned_elf_class=arch+1,
                               first_list_result_injected=11 if cache=='second' else None,
                               private_cached_node_reused=True,node_reference_after=2,execution=row))
    # loadFromBuffer can reach an existing private node before examining ELF.
    loads=[]
    for cache in ('first','second','none','wrong-name'):
        u=machine(tz,cache);request(u,1,0x1012);row=execute(u,INVOKE)
        assert row.get('stopped_before')==('0x15733820' if cache=='first' else '0x15732c18')
        assert row['elf_reads']==0
        loads.append(dict(cache=cache,execution=row))
    # Preserve the real load dispatch frame at its cache call, then inject only
    # negative/non-success local results to distinguish fallback from refusal.
    negative=[]
    for status,target in ((11,0x15686d04),(5,0x157350f0)):
        u=machine(tz);request(u,1,0x1012)
        paused=execute(u,INVOKE,{0x157335a8});assert paused['stopped_before']=='0x157335a8'
        u.reg_write(r.UC_ARM64_REG_X0,status);row=execute(u,0x1569db68,preserve=True)
        assert row['stopped_before']==hex(target)
        negative.append(dict(injected_local_result=status,counterfactual_execution=row))
    boundary=[]
    for word,label in ((0xd4000003,'SMC'),(0xd4028001,'SVC'),(0x14000000,'loop')):
        u=machine(tz);u.mem_write(INVOKE,struct.pack('<I',word))
        try:execute(u,INVOKE)
        except ValueError as e:assert ('forbidden' if label!='loop' else 'bound reached') in str(e)
        else:raise AssertionError('execution boundary ignored')
        boundary.append(label)
    changed=bytearray(tz);changed[-1]^=1
    try:machine(changed)
    except ValueError:boundary.append('modified-TZ')
    else:raise AssertionError('modified image accepted')
    a.output.mkdir(parents=True,exist_ok=True);evidence={}
    for name,lo,hi in [('uid122-route',0x156a000c,0x156a0190),('uid122-factory',0x1569d464,0x1569d514),
                       ('loader-dispatch',INVOKE,0x1569dd88),('cache-resolver',0x157335a8,0x157337b8),
                       ('compat-wrapper',0x15733490,0x15733520),('arch-output',0x157337b8,0x15733820)]:
        (a.output/(name+'.asm')).write_text(subprocess.check_output([a.objdump,'-d','--start-address='+hex(lo),'--stop-address='+hex(hi),str(a.tz)],text=True,stderr=subprocess.PIPE))
        evidence[name]=dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(elf_bytes(tz,lo,hi-lo)).hexdigest())
    sources=[Path(__file__),root/'tools/audit_fuxi_m3_key_recovery.py',root/'tools/audit_fuxi_m3_sdk_reference.py',
             root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3SmciDiagnostic.inc']
    report=dict(result='passed',tz_sha256=TZ_SHA,identity_sha256=hashlib.sha256(a.identity.read_bytes()).hexdigest(),
                factory_controls=factory,lookup_format_controls=formats,synthetic_cache_controls=reused,
                load_controls=loads,negative_return_controls=negative,boundary_controls=boundary,evidence=evidence,
                deployed_lookup=dict(op=2,counts='0x1011',arch_output_bytes=4),
                old_lookup=dict(counts='0x1001',rejected_status=2,rejected_before_name_read=True),
                prior_reference_header_sha256=hashlib.sha256(header.read_bytes()).hexdigest(),
                limits=['Private cache/list/architecture state is synthetic; not actual firmware runtime state.',
                        'Only bounded ordinary allocation/zero/copy/free modeled; no registry, auth, RPC or new TA load executed.',
                        'Correct lookup layout is necessary but does not prove real lookup success or permission.',
                        'Historical lookup attempt was not bound to this exact running TZ/return PC; this is a current-code explanation, not a retrospective runtime trace.',
                        'loadFromBuffer has a cache reuse path; actual ABL/UEFI instance or boot context continuity still unproven.',
                        'No phone, firmware change, security command, generation, upgrade or persistence; -62/M3/M4/M5 unverified.'],
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sources})
    (a.output/'audit.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS 3 UID factory, 8 lookup shape, 4 private cache, 4 load routes, 2 negative suffix, 4 boundaries; no device')


if __name__=='__main__':main()
