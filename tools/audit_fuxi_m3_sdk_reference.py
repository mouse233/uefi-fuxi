#!/usr/bin/env python3
"""Bounded local OTA reference extraction and SDK symbol audit; no execution.

The ROM's Keymaster matches the fixed capture after zero padding. This alone
does NOT establish that its TZ/SDK matches the running phone. Vendor bytes stay
in ignored out/, and no code from this tool is linked into UEFI.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import struct
import subprocess
import zipfile

from audit_fuxi_m3_key_recovery import elf_bytes, PINS

MANIFEST_SHA='cc48764e4df5e8941f09b7a90623c95aff3b52481df6bdac705b94518795b146'
TZ_SHA='d4b8afbe3a8b3468a0f4f740059ab9aed0a8ef803af4f1f58b164ce1c460d418'
KEYMASTER_SHA='61b45016eba26d3e9c4e1dcca5238420847a49618cd8030591f04971f91da480'


def varint(b,i):
    n=shift=0
    while i<len(b) and shift<70:
        byte=b[i];i+=1;n|=(byte&127)<<shift
        if byte<128:return n,i
        shift+=7
    raise ValueError('bounded protobuf varint')


def fields(b):
    i=count=0
    while i<len(b):
        count+=1
        if count>10000:raise ValueError('protobuf field count')
        key,i=varint(b,i);tag,kind=key>>3,key&7
        if not tag:raise ValueError('zero field')
        if kind==0:value,i=varint(b,i)
        elif kind==2:
            length,i=varint(b,i)
            if length>len(b)-i:raise ValueError('protobuf length')
            value=b[i:i+length];i+=length
        else:raise ValueError('unsupported protobuf field')
        yield tag,kind,value


def extract_reference(archive,fixed):
    with zipfile.ZipFile(archive) as z:
        info=z.getinfo('payload.bin')
        assert info.compress_type==0 and info.file_size==3531201824
        with z.open(info) as f:
            header=f.read(24)
            assert struct.unpack('>4sQQI',header)==(b'CrAU',2,199029,267)
            manifest=f.read(199029)
            assert hashlib.sha256(manifest).hexdigest()==MANIFEST_SHA
            records=[v for n,t,v in fields(manifest) if n==13 and t==2]
            parts={next(v.decode() for n,t,v in fields(p) if n==1 and t==2):p for p in records}
            assert len(parts)==len(records) and 'keymaster' in parts and 'tz' in parts
            images={};metadata={}
            # Only the two fixed, small firmware records; never vendor/userdata.
            for name,total,digest in [('keymaster',409600,KEYMASTER_SHA),('tz',3973120,TZ_SHA)]:
                rows=list(fields(parts[name]));declared=dict((n,v) for n,t,v in fields(next(v for n,t,v in rows if n==7)))
                assert declared=={1:total,2:bytes.fromhex(digest)}
                operations=[dict((n,v) for n,t,v in fields(v)) for n,t,v in rows if n==8]
                assert len(operations)==(1 if name=='keymaster' else 2)
                chunks=[]
                for op in operations:
                    assert op[1]==8 and op[3]<=1048576 and op[2]+op[3]<=info.file_size-199320
                    f.seek(199320+op[2]);packed=f.read(op[3])
                    assert hashlib.sha256(packed).digest()==op[8]
                    extent=dict((n,v) for n,t,v in fields(op[6]))
                    assert set(extent)=={1,2} and extent[1]*4096==sum(map(len,chunks))
                    dc=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=64*1024*1024)
                    raw=dc.decompress(packed,max_length=total+1)
                    assert dc.eof and not dc.unused_data and len(raw)==extent[2]*4096
                    chunks.append(raw)
                image=b''.join(chunks)
                assert len(image)==total and hashlib.sha256(image).hexdigest()==digest
                images[name]=image;metadata[name]=dict(bytes=total,sha256=digest)
    assert len(fixed)==524288 and hashlib.sha256(fixed).hexdigest()==PINS['partition']
    assert fixed[:len(images['keymaster'])]==images['keymaster'] and not any(fixed[len(images['keymaster']):])
    metadata.update(manifest_sha256=MANIFEST_SHA,partition_names=list(parts),
                    keymaster_matches_capture_prefix=True,capture_zero_padding_bytes=114688,
                    standalone_cmnlib_partition_present=bool({'cmnlib','cmnlib64'}&parts.keys()))
    return images['tz'],metadata


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('archive','partition','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--objdump',default='/opt/homebrew/opt/llvm/bin/llvm-objdump')
    a=p.parse_args();tz,metadata=extract_reference(a.archive,a.partition.read_bytes())
    # The built-in module's relative dynamic values are mapped through the TZ
    # PT_LOAD layout; no raw file offset is mistaken for a runtime address.
    base=0xd860f000;dynva=0xd8698000
    dynamic={}
    for off in range(0,0x200,16):
        tag,value=struct.unpack('<QQ',elf_bytes(tz,dynva+off,16))
        if not tag:break
        dynamic[tag]=value
    assert dynamic[6]==0x8c1a0 and dynamic[11]==24 and dynamic[5]==0x8ed80 and dynamic[10]==0x26bb
    buckets,count=struct.unpack('<II',elf_bytes(tz,base+dynamic[4],8))
    assert buckets==count==468
    strings=elf_bytes(tz,base+dynamic[5],dynamic[10]);exports={}
    expected={'cmnlib_init':(0x3178,0x2a4),'GPAppLib_init':(0x1071c,0x200),'GPAppLib_appInit':(0x1091c,0x84)}
    for i in range(count):
        off,info,other,section,value,size=struct.unpack('<IBBHQQ',elf_bytes(tz,base+dynamic[6]+i*24,24))
        assert off<len(strings)
        name=strings[off:].split(b'\0',1)[0].decode()
        if name in expected:
            assert name not in exports and info==0x12 and section==1 and (value,size)==expected[name]
            code=elf_bytes(tz,base+value,size)
            assert code[:4]==bytes.fromhex('5f2403d5')
            exports[name]=dict(symbol_index=i,relative_value=hex(value),tz_va=hex(base+value),bytes=size,
                               sha256=hashlib.sha256(code).hexdigest())
    assert exports.keys()==expected.keys()
    # The appInit entry crosses an object-service call. Never replace its result
    # with success to claim a fully initialized TA or a boot patch value.
    pc,target=0xd861f958,0xd86109f0
    inst=struct.unpack('<I',elf_bytes(tz,pc,4))[0];assert inst>>26==0x25
    imm=inst&0x3ffffff
    if imm&0x2000000:imm-=0x4000000
    assert pc+imm*4==target
    assert elf_bytes(tz,target,12)==bytes.fromhex('5f2403d5 f0030aaa 00021fd6')
    a.output.mkdir(parents=True,exist_ok=True)
    tzpath=a.output/'rom-tz.img';tzpath.write_bytes(tz)
    for name,row in exports.items():
        lo=int(row['tz_va'],16);hi=lo+row['bytes']
        asm=subprocess.check_output([a.objdump,'-d','--start-address='+hex(lo),'--stop-address='+hex(hi),str(tzpath)],text=True,stderr=subprocess.PIPE)
        (a.output/(name+'.asm')).write_text(asm)
    (a.output/'sdk-service-trampoline.asm').write_text(subprocess.check_output(
        [a.objdump,'-d','--start-address='+hex(target),'--stop-address='+hex(target+12),str(tzpath)],
        text=True,stderr=subprocess.PIPE))
    root=Path(__file__).resolve().parents[1]
    sources=[Path(__file__),root/'tools/audit_fuxi_m3_key_recovery.py']
    result=dict(result='passed',archive_name=a.archive.name,archive_bytes=a.archive.stat().st_size,
                reference=metadata,sdk_module_base_in_tz=hex(base),dynamic_va=hex(dynva),exports=exports,
                app_init_service_boundary=dict(call_pc=hex(pc),target=hex(target),indirect_branch_register='x10',executed=False),
                limits=['Archive hashes prove local integrity, not signature authenticity or running TZ identity.',
                        'Keymaster exact prefix equality does not prove SDK/runtime version equality.',
                        'Three exports resolved to defined function bytes; SDK code/callees/service not executed.',
                        'No phone, secure-world command, native vendor code execution, generation, upgrade or persistence.',
                        'Actual boot context/lifetime/return PC and M3/M4/M5 remain unverified.'],
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sources})
    (a.output/'sdk-reference.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS fixed OTA integrity, captured Keymaster prefix + zero tail, 3 defined SDK exports; static only')


if __name__=='__main__':main()
