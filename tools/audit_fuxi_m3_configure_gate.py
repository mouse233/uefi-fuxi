#!/usr/bin/env python3
"""Fixed TA configure/dispatcher gates on PUBLIC synthetic input, no device.

The real parser, slot writers and configured getter execute in private Unicorn
memory. Existing execution boundary forbids SMC/HVC/SVC and key export. Only PAC
control flow and log suppression are modeled. Never supplies a real key/blob.
"""
import argparse,hashlib,itertools,json,struct,re
from pathlib import Path
import audit_fuxi_m3_metadata_read as ta
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X21,UC_ARM64_REG_X25
from audit_fuxi_m3_recovery_wire import Codec
from audit_fuxi_m3_key_recovery import elf_bytes

VALUES=[(0x300002c1,170000),(0x300002c2,20261005),(0x300002ce,20261005)]

def uint(n):
    if n<24:return bytes([n])
    return b'\x1a'+n.to_bytes(4,'big')

def encode(params,count=None):
    return bytes([0xa0+1+len(params)])+b'\x16'+uint(len(params) if count is None else count)+b''.join(uint(k)+uint(v) for k,v in params)

def table_entry(raw,cmd):
    ph=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
    for n in range(count):
        kind,_,off,va,_,fsz,_,_=struct.unpack_from('<IIQQQQQQ',raw,ph+n*size)
        if kind==1 and va<=0x5a5e0<va+fsz:
            start=off+0x5a5e0-va
            for i in range(89):
                command,flags,handler=struct.unpack_from('<IIQ',raw,start+i*16)
                if command==cmd:return 0x5a5e0+i*16,flags,handler
    raise ValueError('fixed command not found')

def gate(u,entry):
    # Enter immediately after the real dispatcher matched this fixed entry.
    # Stop before any handler or error cleanup runs; no success is substituted.
    stopped=[]
    def hook(m,pc,_size,_ctx):
        if pc-ta.BASE in (0xb3d0,0xb454):stopped.append(pc-ta.BASE);m.emu_stop()
    hid=u.hook_add(UC_HOOK_CODE,hook);u.reg_write(UC_ARM64_REG_X25,ta.BASE+entry+4)
    u.emu_start(ta.BASE+0xb3c0,ta.STOP,count=100)
    u.hook_del(hid)
    assert len(stopped)==1
    return dict(passed=stopped[0]==0xb3d0,stop_pc=hex(stopped[0]),status=0 if stopped[0]==0xb3d0 else (u.reg_read(UC_ARM64_REG_X21)&0xffffffff)-(1<<32))

def configure(raw,payload):
    u=ta.machine(raw);writes=[]
    def write(_m,_access,address,size,_value,_ctx):
        if ta.BASE<=address<ta.BASE+0x80000:writes.append((address-ta.BASE,size))
    u.hook_add(UC_HOOK_MEM_WRITE,write);u.mem_write(ta.INPUT,payload)
    u.reg_write(UC_ARM64_REG_X0,ta.INPUT);u.reg_write(UC_ARM64_REG_X1,len(payload))
    result=ta.execute(u,0x37f28)
    allowed={(0x5b4f0,4),(0x5b4f8,4),(0x5b4fc,4),(0x5b4ed,1),(0x5b4ec,1)}
    assert set(writes)<=allowed,set(writes)-allowed
    result.update(configured=u.mem_read(ta.BASE+0x5b4ed,1)[0],ta_ram_writes=[dict(va=hex(x),bytes=n) for x,n in writes],values=list(struct.unpack('<IIII',u.mem_read(ta.BASE+0x5b4f0,16))))
    return u,result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--partition',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--ramdisk',type=Path,required=True);p.add_argument('--runtime-library',type=Path,required=True);p.add_argument('--runtime-context',type=Path,required=True);a=p.parse_args()
    raw=a.partition.read_bytes();assert hashlib.sha256(raw).hexdigest()==ta.TA_SHA
    a.output.mkdir(parents=True,exist_ok=True)
    reference=(a.ramdisk/'vendor/lib64/libqtikeymint.so').read_bytes();runtime=a.runtime_library.read_bytes()
    assert hashlib.sha256(reference).hexdigest()=='657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb'
    assert hashlib.sha256(runtime).hexdigest()=='368b34db8efee95d1713cee10d823e8572f6668ef559867c67e292dc3b9e8c52'
    code={}
    for lo,hi in ((0x18590,0x187a4),(0x189a0,0x18c88),(0x35178,0x352f4)):
        x=elf_bytes(reference,lo,hi-lo);assert x==elf_bytes(runtime,lo,hi-lo)
        code[hex(lo)]=dict(end=hex(hi),sha256=hashlib.sha256(x).hexdigest(),same_in_runtime=True)
    for va,name in ((0x115f0,b'ro.build.version.security_patch'),(0x11610,b'ro.vendor.build.security_patch'),(0x1162f,b'ro.build.version.release')):
        assert elf_bytes(reference,va,len(name)+1)==name+b'\0'
        assert elf_bytes(runtime,va,len(name)+1)==name+b'\0'
    ctx=json.loads(a.runtime_context.read_text());assert ctx['serial']=='fcde91e' and ctx['props']['ro.boot.slot_suffix']=='_a'
    assert ctx['props']['ro.build.version.release']=='17'
    for name in ('ro.build.version.security_patch','ro.vendor.build.security_patch'):
        assert re.fullmatch(r'2026-10-05',ctx['props'][name])
    # Fixed constructor branches 18718/18764 select 189a0 when date_support=1;
    # that helper's 18ae8..18b00 computes year*10000 + month*100 + day.
    assert elf_bytes(runtime,0x18718,8)==bytes.fromhex('74000034a1000094')
    assert elf_bytes(runtime,0x18764,8)==bytes.fromhex('740000348e000094')
    codec=Codec(a.ramdisk/'vendor/lib64');vendor_vectors=[]
    for params in itertools.permutations(VALUES):
        u=codec.u;u.mem_write(codec.this,struct.pack('<Q',codec.qt+0x3e870))
        data=b''.join(struct.pack('<IIQQ',tag,0,value,0) for tag,value in params)
        u.mem_write(codec.params+0x100,data);u.mem_write(codec.params,struct.pack('<QQ',codec.params+0x100,3))
        u.mem_write(codec.output,struct.pack('<QQ',codec.buffer,0x8000))
        codec.call(0x35178,[codec.this,codec.params,codec.output])
        n=struct.unpack('<Q',u.mem_read(codec.output+8,8))[0];assert n<=64
        encoded=bytes(u.mem_read(codec.buffer,n));assert encoded==encode(params)
        vendor_vectors.append(encoded.hex())
    entries={cmd:table_entry(raw,cmd) for cmd in (0x200,0x2116,0x310f)}
    assert entries[0x2116][2]==0xb7b4 and entries[0x310f][2]==0x8984
    assert entries[0x310f][1]&255==1 and entries[0x2116][1]&255==0
    before=gate(ta.machine(raw),entries[0x310f][0]);assert before['status']==-64 and not before['passed']
    assert gate(ta.machine(raw),entries[0x2116][0])['passed']
    cases=[]
    for params in itertools.permutations(VALUES):
        u,r=configure(raw,encode(params));assert r['status']==0 and r['configured']==1 and r['values']==[170000,0,20261005,20261005]
        r['begin_gate']=gate(u,entries[0x310f][0]);assert r['begin_gate']['passed'];cases.append(r)
    for index in range(3):
        _,r=configure(raw,encode([v for i,v in enumerate(VALUES) if i!=index]));assert r['status']==-38 and not r['configured'];cases.append(r)
    for payload in (encode(VALUES+[(0x300002cf,1)]),encode(VALUES,count=4),encode([VALUES[0],VALUES[0],VALUES[1]]),encode(VALUES)[:-1]):
        _,r=configure(raw,payload);assert r['status']<0 and not r['configured'];cases.append(r)
    # Detect input mutation before any emulation/interpretation.
    changed=bytearray(raw);changed[-1]^=1
    try:ta.machine(changed)
    except ValueError:pass
    else:raise AssertionError('modified TA accepted')
    payload=encode(VALUES);(a.output/'configure-public-cbor.bin').write_bytes(payload)
    files=[Path(__file__),Path(ta.__file__),Path(__file__).with_name('audit_fuxi_m3_recovery_wire.py'),Path(__file__).with_name('audit_fuxi_m3_key_recovery.py')]
    report=dict(result='passed',partition_sha256=ta.TA_SHA,cases=len(cases),vendor_request_matches=len(vendor_vectors),vendor_vectors=vendor_vectors,constructor_date_support=1,public_parameter_values=VALUES,runtime_library_sha256=hashlib.sha256(runtime).hexdigest(),context_sha256=hashlib.sha256(a.runtime_context.read_bytes()).hexdigest(),runtime_code_equivalence=code,unconfigured_begin_gate=before,entries={hex(k):dict(entry=hex(v[0]),flags=hex(v[1]),handler=hex(v[2])) for k,v in entries.items()},configure_cbor_hex=payload.hex(),tests=cases,interpretation='Live -64 and fixed dispatcher prove configuration gate blocks begin before key handler. Public-input parser sets that flag using TA RAM stores; successful gate is not key recovery. Runtime/reference date-support constructor and serializer bytes match, both patches use YYYYMMDD. No device or secure service executed. Does not prove universal absence of persistence outside this parser/call path.',sources={str(f.relative_to(Path(__file__).resolve().parents[1])):hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    (a.output/'audit.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(cases),'real TA public parser/gate cases; no device or key operations')
if __name__=='__main__':main()
