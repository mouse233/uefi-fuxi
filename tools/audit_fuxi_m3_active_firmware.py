#!/usr/bin/env python3
"""Bind local ROM ABL/TZ to captured slot A hashes, then audit ABL fragments.

Pure host work. No further ADB access, vendor native execution or secure service
call. A matching partition hash does not attest loaded RAM or boot path choice.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import struct
import subprocess
import zipfile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as r
from audit_fuxi_m3_sdk_reference import fields,MANIFEST_SHA,extract_reference,TZ_SHA
from audit_fuxi_m3_boot_provenance import abl_run,ta_record,STACK,DATA,HALT,IMAGES

ACTIVE_ABL_SHA='eddd52b961aea860ed7a04f27b4e6f7976e04ee30ca1113b0e3b867aa919431d'
ACTIVE_PE_SHA='48de0c341840c30e99d483ebbbdc0df4de67bc971d76bd05477587ace87aab3b'


def extract_abl(archive):
    with zipfile.ZipFile(archive) as z:
        assert z.getinfo('payload.bin').compress_type==0
        with z.open('payload.bin') as f:
            assert struct.unpack('>4sQQI',f.read(24))==(b'CrAU',2,199029,267)
            manifest=f.read(199029);assert hashlib.sha256(manifest).hexdigest()==MANIFEST_SHA
            records=[v for n,t,v in fields(manifest) if n==13]
            record=next(v for v in records if next(v for n,t,v in fields(v) if n==1)==b'abl')
            rows=list(fields(record))
            declared=dict((n,v) for n,t,v in fields(next(v for n,t,v in rows if n==7)))
            assert declared=={1:233472,2:bytes.fromhex('adfb733e9daa84f2c863639268fe03f1e1d4f7732d7d93aae6b650f56745e59c')}
            ops=[dict((n,v) for n,t,v in fields(v)) for n,t,v in rows if n==8]
            assert len(ops)==1 and ops[0][1]==8 and ops[0][3]==223712
            op=ops[0];f.seek(199320+op[2]);packed=f.read(op[3]);assert hashlib.sha256(packed).digest()==op[8]
            dc=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=64*1024*1024)
            raw=dc.decompress(packed,max_length=1048576)
            assert dc.eof and not dc.unused_data and len(raw)==declared[1] and hashlib.sha256(raw).digest()==declared[2]
    padded=raw+bytes(8388608-len(raw));assert hashlib.sha256(padded).hexdigest()==ACTIVE_ABL_SHA
    section=0x1060;n=int.from_bytes(padded[section:section+3],'little')
    assert n==0x35f83 and padded[section+3]==2
    assert padded[section+4:section+20]==bytes.fromhex('98584eee143959429d6edc7bd79403cf')
    assert struct.unpack_from('<H',padded,section+20)[0]==24
    dc=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE,memlimit=64*1024*1024)
    expanded=dc.decompress(padded[section+24:section+n],max_length=2*1024*1024)
    assert dc.eof and len(expanded)==1134792
    assert int.from_bytes(expanded[180:183],'little')==1134596 and expanded[183]==16
    pe=expanded[184:184+1134592]
    assert hashlib.sha256(pe).hexdigest()==ACTIVE_PE_SHA
    return padded,pe


def machine(pe):
    assert len(pe)==1134592 and hashlib.sha256(pe).hexdigest()==ACTIVE_PE_SHA
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x1000,0x200000);u.mem_write(0x1000,pe[0x1000:])
    for base in (STACK,DATA,HALT):u.mem_map(base,0x10000)
    u.reg_write(r.UC_ARM64_REG_CPACR_EL1,3<<20);u.reg_write(r.UC_ARM64_REG_SP,STACK+0xf000)
    u.reg_write(r.UC_ARM64_REG_X30,HALT)
    return u


def header(pe,value,version=3):
    u=machine(pe);b=bytearray(4096);b[:8]=b'ANDROID!'
    struct.pack_into('<I',b,40,version);struct.pack_into('<I',b,16 if version>2 else 44,value)
    u.mem_write(DATA,bytes(b));u.reg_write(r.UC_ARM64_REG_X23,DATA)
    result=abl_run(u,0x2cd24,[(0x2cd24,0x2ce68)],{0x2ce68,0x2d07c,0x2d11c})
    result.update(header_version=version,os_version_raw=hex(value))
    if result['stop']=='0x2ce68':
        result['packed_os'],result['packed_patch']=struct.unpack('<II',u.mem_read(STACK+0xf058,8))
    return result


def builder(pe,os,patch):
    u=machine(pe);record=bytearray(32);struct.pack_into('<I',record,4,1);struct.pack_into('<II',record,24,os,patch)
    u.mem_write(DATA,bytes(record));u.mem_write(DATA+0x1000,bytes(32))
    for reg,value in ((r.UC_ARM64_REG_X20,DATA),(r.UC_ARM64_REG_X21,DATA+0x1000),(r.UC_ARM64_REG_X22,DATA+0x2000)):
        u.reg_write(reg,value)
    result=abl_run(u,0x41f60,[(0x41f60,0x41fb0)],{0x41fb0},copy=(STACK+0xf034,DATA+0x1000,32))
    request=bytes(u.mem_read(STACK+0xf020,64))
    assert struct.unpack_from('<IIII',request)==(0x208,0,16,48)
    assert struct.unpack_from('<II',request,56)==(os,patch)
    assert u.reg_read(r.UC_ARM64_REG_X3)==64 and u.reg_read(r.UC_ARM64_REG_X5)==4
    result.update(command='0x208',request_bytes=64,record_bytes=48,packed_os=os,packed_patch=patch)
    return request,result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('archive','partition','identity','candidate-a','candidate-b','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--objdump',default='/opt/homebrew/opt/llvm/bin/llvm-objdump');a=p.parse_args()
    root=Path(__file__).resolve().parents[1];capture=json.loads(a.identity.read_text())
    assert capture['result']=='captured' and capture['serial']=='fcde91e' and capture['stable_snapshots']==2
    assert capture['properties']['ro.boot.slot_suffix']=='_a' and capture['boot_continuity_checked']
    for name,digest in capture['sources'].items():assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest
    raw=a.partition.read_bytes();tz,_=extract_reference(a.archive,raw);abl,pe=extract_abl(a.archive)
    padded_tz_sha=hashlib.sha256(tz+bytes(4194304-len(tz))).hexdigest()
    assert capture['partitions']['abl_a']['bytes']==8388608 and capture['partitions']['abl_a']['sha256']==ACTIVE_ABL_SHA
    assert capture['partitions']['tz_a']['bytes']==4194304 and capture['partitions']['tz_a']['sha256']==padded_tz_sha
    assert struct.unpack_from('<IIII',pe,0xa9da0)==(0x208,0,16,48)
    for pc,target in ((0x2d0d0,0x41d28),(0x41fb0,0x423e0)):
        inst=struct.unpack_from('<I',pe,pc)[0];assert inst>>26==0x25
        imm=inst&0x3ffffff
        if imm&0x2000000:imm-=0x4000000
        assert pc+imm*4==target
    chains=[]
    for path,digest in zip((a.candidate_a,a.candidate_b),IMAGES):
        b=path.read_bytes();assert hashlib.sha256(b).hexdigest()==digest
        value=struct.unpack_from('<I',b,16)[0];assert value==0x220001a7
        fields_=header(pe,value);assert fields_['stop']=='0x2ce68'
        req,built=builder(pe,fields_['packed_os'],fields_['packed_patch'])
        converted=ta_record(raw,req,finish=True)
        assert converted['stopped_before']=='0xbdf8' and converted['boot_after']==202607 and converted['normalized_os']==170000
        chains.append(dict(candidate_sha256=digest,header_fallback=fields_,builder=built,ta_fragment=converted))
    controls=[header(pe,v,h) for v,h in ((0,3),(1,3),(0x22000000,3),(0x220001a7,2),(0x220001a7,4))]
    assert [x['stop'] for x in controls]==['0x2d07c','0x2d07c','0x2d11c','0x2ce68','0x2ce68']
    req,built=builder(pe,17<<14,(26<<4)|10|(5<<11));converted=ta_record(raw,req,finish=True)
    assert converted['boot_after']==20261005 and converted['stopped_before']=='0xbdf8'
    boundaries=[]
    for entry in (0x423e0,0x41a7c):
        try:abl_run(machine(pe),entry,[],set())
        except ValueError as e:assert 'external/protocol boundary' in str(e)
        else:raise AssertionError('service executed')
        boundaries.append(dict(entry=hex(entry),rejected=True))
    a.output.mkdir(parents=True,exist_ok=True)
    (a.output/'rom-abl-a.img').write_bytes(abl);pepath=a.output/'LinuxLoader-a.efi';pepath.write_bytes(pe)
    evidence={}
    for name,lo,hi in [('active-abl-header',0x2cd24,0x2ce74),('active-abl-builder',0x41f0c,0x41fc4),('active-abl-callsite',0x2d0cc,0x2d0d8)]:
        asm=subprocess.check_output([a.objdump,'-d','--start-address='+hex(lo),'--stop-address='+hex(hi),str(pepath)],text=True,stderr=subprocess.PIPE)
        (a.output/(name+'.asm')).write_text(asm);evidence[name]=dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(pe[lo:hi]).hexdigest())
    files=[Path(__file__),root/'tools/audit_fuxi_m3_sdk_reference.py',root/'tools/audit_fuxi_m3_boot_provenance.py',
           root/'tools/audit_fuxi_m3_boot_client.py',root/'tools/audit_fuxi_m3_begin_version.py',root/'tools/audit_fuxi_m3_metadata_read.py',
           root/'tools/audit_fuxi_m3_key_recovery.py',root/'tools/audit_fuxi_m3_configure_gate.py',root/'tools/collect_fuxi_m3_firmware_identity.py']
    report=dict(result='passed',identity_evidence_sha256=hashlib.sha256(a.identity.read_bytes()).hexdigest(),
                identity_captured_at=capture['captured_at'],current_slot='_a',active_abl_sha256=ACTIVE_ABL_SHA,
                active_linuxloader_sha256=ACTIVE_PE_SHA,rom_tz_sha256=TZ_SHA,active_tz_padded_sha256=padded_tz_sha,
                active_partition_matches=dict(abl=True,tz=True),evidence=evidence,candidate_chains=chains,
                header_controls=controls,synthetic_date_chain=dict(builder=built,ta_fragment=converted),boundary_controls=boundaries,
                limits=['Partition identity matched via two stable TWRP hash rounds, not secure-world RAM attestation.',
                        'Current ABL code is separately pinned/re-audited; historical slot B addresses are not used.',
                        'Header fallback entered after path decision, builder after unexecuted ROT success; synthetic public fields only.',
                        'No QSEECom/SDK/platform service or boot-state command executed; TA stops before completion.',
                        'Actual field source, runtime boot value, TA lifetime/-62 return PC and M3/M4/M5 remain unverified.'],
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    (a.output/'active-firmware-audit.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS active slot A ABL/TZ identity + 10 host fragment/boundary controls; no further phone access')


if __name__=='__main__':main()
