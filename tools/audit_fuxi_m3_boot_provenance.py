#!/usr/bin/env python3
"""Captured ABL -> public boot record -> fixed TA, private offline fragments.

No phone, command sender, AVB authentication or external SDK is executed. ABL
fragments stop BEFORE QSEECom; TA fragments start AFTER the platform gate and
stop BEFORE completion. Neither fragment is a successful boot-state operation.
"""
import argparse
import hashlib
import json
import lzma
import struct
import subprocess
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as r
import audit_fuxi_m3_metadata_read as ta
from audit_fuxi_m3_boot_client import machine, word
from audit_fuxi_m3_begin_version import run
from audit_fuxi_m3_key_recovery import elf_bytes

ABL_SHA = '78595f9a5fbaba528b894fa7f3991db37fe1bcd03be3036e5cb3c254405655f3'
PE_SHA = 'b5ccae26a30febeb6c303dde9c141eee2241f0046c27e5918667f1d7d316e954'
IMAGES = (
    '169e7401d2fa3fcce8347f50232b253c11bf884773b474fb2365b3b52185e44b',
    '81e1abd43ec63d27abd970be69943557d388b61e72ce6274f1684b9a977474f5',
)
STACK, DATA, HALT = 0x1000000, 0x2000000, 0x3000000


def checked(raw, digest, size):
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('fixed input SHA256/length mismatch')
    return raw


def abl_machine(pe):
    checked(pe, PE_SHA, 1142784)
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0x1000, 0x200000)
    u.mem_write(0x1000, pe[0x1000:])
    for base in (STACK, DATA, HALT):
        u.mem_map(base, 0x10000)
    u.reg_write(r.UC_ARM64_REG_CPACR_EL1, 3 << 20)
    u.reg_write(r.UC_ARM64_REG_SP, STACK+0xf000)
    u.reg_write(r.UC_ARM64_REG_X30, HALT)
    return u


def abl_run(u, entry, allowed, stops, copy=None):
    state = dict(instructions=0, debug_checks_suppressed=0, bounded_copies=0)
    def hook(m, pc, _size, _ctx):
        state['instructions'] += 1
        if pc in stops:
            state['stop'] = hex(pc)
            m.emu_stop()
            return
        if pc == 0x18c0:  # DebugPrintEnabled only, no security success stub.
            state['debug_checks_suppressed'] += 1
            m.reg_write(r.UC_ARM64_REG_X0, 0)
            m.reg_write(r.UC_ARM64_REG_PC, m.reg_read(r.UC_ARM64_REG_X30))
            return
        if copy and pc == 0x4094:
            dst, src, size = [m.reg_read(getattr(r, 'UC_ARM64_REG_X'+str(i))) for i in range(3)]
            assert (dst, src, size) == copy
            m.mem_write(dst, bytes(m.mem_read(src, size)))
            m.reg_write(r.UC_ARM64_REG_X0, dst)
            m.reg_write(r.UC_ARM64_REG_PC, m.reg_read(r.UC_ARM64_REG_X30))
            state['bounded_copies'] += 1
            return
        if not any(lo <= pc < hi for lo, hi in allowed):
            raise ValueError('ABL external/protocol boundary: '+hex(pc))
        instruction = struct.unpack('<I', m.mem_read(pc, 4))[0]
        if instruction & 0xffe0001f in (0xd4000001, 0xd4000002, 0xd4000003):
            raise ValueError('SVC/HVC/SMC forbidden')
    h = u.hook_add(UC_HOOK_CODE, hook)
    try:
        u.emu_start(entry, HALT, count=10000)
    finally:
        u.hook_del(h)
    if 'stop' not in state:
        raise ValueError('ABL instruction bound reached')
    return state


def header_fields(pe, version, header_version=3):
    u = abl_machine(pe)
    header = bytearray(4096)
    header[:8] = b'ANDROID!'
    struct.pack_into('<I', header, 40, header_version)
    struct.pack_into('<I', header, 16 if header_version > 2 else 44, version)
    u.mem_write(DATA, bytes(header))
    u.reg_write(r.UC_ARM64_REG_X23, DATA)
    result = abl_run(u, 0x2da38, [(0x2da38,0x2db7c)], {0x2db7c,0x2dc30,0x2dcd8})
    result.update(header_version=header_version, raw_os_version=hex(version))
    if result['stop'] == '0x2db7c':
        result['packed_os'], result['packed_patch'] = struct.unpack('<II',u.mem_read(STACK+0xf058,8))
    return result


def property_date(pe, text):
    # Only the property parser after successful lookup; no AVB/property lookup.
    u = abl_machine(pe)
    u.mem_write(DATA, text.encode())
    u.reg_write(r.UC_ARM64_REG_X0, DATA)
    u.reg_write(r.UC_ARM64_REG_X11, len(text))
    u.reg_write(r.UC_ARM64_REG_X24, 10)
    result = abl_run(u, 0x2d878, [(0x2d878,0x2d914)], {0x2d914,0x2dba0})
    result['synthetic_public_date'] = text
    if result['stop'] == '0x2d914':
        result['packed_patch'] = struct.unpack('<I', u.mem_read(STACK+0xf05c,4))[0]
    return result


def build_record(pe, packed_os, packed_patch):
    # Actual ABL builder AFTER prior ROT command success, before QSEECom send.
    u = abl_machine(pe)
    state, digest, context = DATA, DATA+0x1000, DATA+0x2000
    data = bytearray(32)
    struct.pack_into('<I',data,4,1)  # Synthetic color enum, not real device state.
    struct.pack_into('<II',data,24,packed_os,packed_patch)
    u.mem_write(state,bytes(data))
    u.mem_write(digest,bytes(32))  # No real public-key/boot digest supplied.
    u.reg_write(r.UC_ARM64_REG_X20,state)
    u.reg_write(r.UC_ARM64_REG_X21,digest)
    u.reg_write(r.UC_ARM64_REG_X22,context)
    result = abl_run(u,0x71a20,[(0x71a20,0x71a70)],{0x71a70},
                     copy=(STACK+0xf034,digest,32))
    request = bytes(u.mem_read(STACK+0xf020,64))
    assert struct.unpack_from('<IIII',request) == (0x208,0,16,48)
    assert struct.unpack_from('<II',request,56) == (packed_os,packed_patch)
    assert u.reg_read(r.UC_ARM64_REG_X3) == 64 and u.reg_read(r.UC_ARM64_REG_X5) == 4
    assert result['bounded_copies'] == 1
    result.update(command='0x208', request_bytes=64, response_capacity=4,
                  record_offset=16,record_bytes=48,packed_os=packed_os,packed_patch=packed_patch,
                  scope='Synthetic public record; previous ROT result not executed; stopped before QSEECom.')
    return request,result


def ta_record(raw, request, length=None, offset=0x4000, finish=False):
    # The platform query/one-time guard at bb7c..bbfc is intentionally excluded.
    # Execute real 31f10 bounds code, rather than treating it as authentication.
    u = machine(raw)
    frame, address = 0x401e000, ta.SCRATCH+offset
    u.mem_write(address,request)
    guard=struct.unpack('<Q',u.mem_read(ta.BASE+0x5a2f8,8))[0]
    u.mem_write(frame-8,bytes(u.mem_read(guard,8)))
    u.mem_write(frame+8,struct.pack('<Q',ta.STOP))
    for reg,value in ((r.UC_ARM64_REG_X19,address),(r.UC_ARM64_REG_X20,len(request) if length is None else length),
                      (r.UC_ARM64_REG_X21,ta.BASE+0x5b000),(r.UC_ARM64_REG_X29,frame),
                      (r.UC_ARM64_REG_SP,frame-0x40),(r.UC_ARM64_REG_X30,ta.STOP)):
        u.reg_write(reg,value)
    copies = []
    def copy(m,pc,_size,_ctx):
        if pc != ta.BASE+0x446b4:
            return
        dst,cap,src,n = [m.reg_read(getattr(r,'UC_ARM64_REG_X'+str(i))) for i in range(4)]
        assert (dst,cap,src,n) == (ta.BASE+0x5ba7c,48,address+16,48)
        m.mem_write(dst,bytes(m.mem_read(src,n)))
        m.reg_write(r.UC_ARM64_REG_X0,n)
        m.reg_write(r.UC_ARM64_REG_PC,m.reg_read(r.UC_ARM64_REG_X30))
        copies.append(n)
    u.hook_add(UC_HOOK_CODE,copy)
    stops = {0xbdf8,0x194fc,0x404b4} if finish else {0xbcf8,0x194fc,0x404b4}
    result = run(u,0xbc00,stops,preserve_frame=True)
    result.update(platform_query_executed=False, completion_executed=False,
                  copied_bytes=copies,boot_after=word(u,0x5b4f4),flag_after=u.mem_read(ta.BASE+0x5ba58,1)[0])
    if result.get('stopped_before') == '0xbcf8':
        record,size = struct.unpack('<QQ',u.mem_read(frame-0x18,16))
        result.update(record_relative_offset=record-address,record_bytes=size)
        assert result['boot_after'] == result['flag_after'] == 0
    if result.get('stopped_before') == '0xbdf8':
        assert copies == [48] and result['flag_after'] == 1
        result['normalized_os'] = word(u,0x5baa4)
    return result


def branch(pe, pc, target):
    instruction = struct.unpack_from('<I',pe,pc)[0]
    assert instruction >> 26 == 0x25
    imm=instruction & 0x3ffffff
    if imm & 0x2000000:imm-=0x4000000
    assert pc+imm*4 == target


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('abl','linuxloader','partition','candidate-a','candidate-b','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--objdump',default='/opt/homebrew/opt/llvm/bin/llvm-objdump')
    a=p.parse_args()
    abl=checked(a.abl.read_bytes(),ABL_SHA,8388608)
    pe=checked(a.linuxloader.read_bytes(),PE_SHA,1142784)
    raw=a.partition.read_bytes();machine(raw)
    calls=[]
    for pc in range(0x31f10,0x31fbc,4):
        inst=struct.unpack('<I',elf_bytes(raw,pc,4))[0]
        if inst>>26==0x25:
            imm=inst&0x3ffffff
            if imm&0x2000000:imm-=0x4000000
            calls.append(pc+imm*4)
    assert calls==[0x20,0x20,0x20]
    # Fixed GUID-defined LZMA section; bounded decompression re-establishes the
    # relationship with the captured ABL, not merely two independent hashes.
    section=0x1060
    section_size=int.from_bytes(abl[section:section+3],'little')
    assert section_size==0x36c4f and abl[section+3]==2
    assert abl[section+4:section+20]==bytes.fromhex('98584eee143959429d6edc7bd79403cf')
    assert struct.unpack_from('<H',abl,section+20)[0]==24
    dec=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE,memlimit=64*1024*1024)
    expanded=dec.decompress(abl[section+24:section+section_size],max_length=2*1024*1024)
    assert dec.eof and len(expanded)==1142984 and expanded[184:184+len(pe)]==pe
    assert expanded.count(pe)==1
    for pc,target in ((0x2dc8c,0x717e8),(0x71724,0x71ea0),(0x71a0c,0x71ea0),(0x71a70,0x71ea0)):
        branch(pe,pc,target)
    assert struct.unpack_from('<IIII',pe,0xac030)==(0x208,0,16,48)
    images=[]
    for path,digest in zip((a.candidate_a,a.candidate_b),IMAGES):
        image=checked(path.read_bytes(),digest,1888256)
        assert image[:8]==b'ANDROID!' and struct.unpack_from('<I',image,40)[0]==3
        version=struct.unpack_from('<I',image,16)[0]
        assert version==0x220001a7
        fields=header_fields(pe,version)
        assert fields['stop']=='0x2db7c' and fields['packed_patch']==0x1a7
        request,builder=build_record(pe,fields['packed_os'],fields['packed_patch'])
        normalized=ta_record(raw,request,finish=True)
        assert normalized['stopped_before']=='0xbdf8' and normalized['normalized_os']==170000 and normalized['boot_after']==202607
        images.append(dict(image_sha256=digest,header_version=3,header_os_version_raw=hex(version),
                           header_date='2026-07',fallback=fields,builder=builder,ta_fragment=normalized))
    # Complete bounds helper + conversion, never platform/completion calls.
    controls=[]
    for date,expected in (('2026-10-05',20261005),('2026-10-31',20261031),('2000-01-01',20000101)):
        fields=property_date(pe,date);assert fields['stop']=='0x2d914'
        request,builder=build_record(pe,17<<14,fields['packed_patch'])
        normalized=ta_record(raw,request,finish=True)
        assert normalized['stopped_before']=='0xbdf8' and normalized['boot_after']==expected
        controls.append(dict(date_parser=fields,builder=builder,ta_fragment=normalized))
    invalid_dates=[property_date(pe,date) for date in ('2026-00-05','2026-13-05','2026-10-00','2026-10-32','1999-10-05')]
    assert all(x['stop']=='0x2dba0' for x in invalid_dates)
    headers=[header_fields(pe,v,h) for v,h in ((0,3),(1,3),(0x22000000,3),(0x220001a7,2),(0x220001a7,4))]
    assert [x['stop'] for x in headers]==['0x2dc30','0x2dc30','0x2dcd8','0x2db7c','0x2db7c']
    request,_=build_record(pe,17<<14,0x1aa)
    bounds=[]
    cases=[('valid',request,None,0x4000,None),('short-header',request,15,0x4000,-29),
           ('truncated-record',request,63,0x4000,-21),('different-address',request,None,0x5000,None)]
    for label,off,size in (('offset-before-header',8,48),('offset-beyond-input',65,48),
                           ('length-overflow',16,0xffffffff),('short-record',16,47)):
        b=bytearray(request);struct.pack_into('<II',b,8,off,size)
        cases.append((label,bytes(b),None,0x4000,-21))
    for label,req,length,offset,status in cases:
        row=ta_record(raw,req,length,offset)
        assert row['status']==status
        if status is None:
            assert row['stopped_before']=='0xbcf8' and row['record_relative_offset']==16 and row['record_bytes']==48
        else:assert row['boot_after']==row['flag_after']==0
        bounds.append(dict(case=label,**row))
    boundaries=[]
    for entry in (0x194fc,0x404b4):
        u=machine(raw);result=run(u,entry,{entry})
        assert result['stopped_before']==hex(entry)
        boundaries.append(dict(entry=hex(entry),stopped_before=True))
    for entry in (0x71ea0,0x7153c):
        try:abl_run(abl_machine(pe),entry,[],set())
        except ValueError as e:assert 'external/protocol boundary' in str(e)
        else:raise AssertionError('ABL service executed')
        boundaries.append(dict(entry=hex(entry),rejected=True))
    for original,digest,size in ((abl,ABL_SHA,len(abl)),(pe,PE_SHA,len(pe))):
        b=bytearray(original);b[-1]^=1
        try:checked(b,digest,size)
        except ValueError:boundaries.append(dict(control='modified-fixed-input',rejected=True))
        else:raise AssertionError('changed binary accepted')
    a.output.mkdir(parents=True,exist_ok=True)
    ranges={'abl-record-builder':(a.linuxloader,0x719cc,0x71a84),
            'abl-header-fallback':(a.linuxloader,0x2da38,0x2db88),
            'abl-property-parser':(a.linuxloader,0x2d7ac,0x2d914),
            'abl-keymaster-start':(a.linuxloader,0x7153c,0x717e8),
            'ta-bounds-helper':(a.partition,0x31f10,0x31fbc),
            'ta-boot-handler':(a.partition,0xbb7c,0xbedc),
            'ta-boot-completion':(a.partition,0x404b4,0x40558)}
    evidence={}
    for name,(path,lo,hi) in ranges.items():
        asm=subprocess.check_output([a.objdump,'-d','--start-address='+hex(lo),'--stop-address='+hex(hi),str(path)],text=True,stderr=subprocess.PIPE)
        (a.output/(name+'.asm')).write_text(asm)
        data=pe[lo:hi] if path==a.linuxloader else elf_bytes(raw,lo,hi-lo)
        evidence[name]=dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(data).hexdigest())
    root=Path(__file__).resolve().parents[1]
    sources=[Path(__file__),root/'tools/audit_fuxi_m3_boot_client.py',root/'tools/audit_fuxi_m3_begin_version.py',
             root/'tools/audit_fuxi_m3_metadata_read.py',root/'tools/audit_fuxi_m3_key_recovery.py',root/'tools/audit_fuxi_m3_configure_gate.py']
    result=dict(result='passed',abl_sha256=ABL_SHA,linuxloader_sha256=PE_SHA,ta_sha256=ta.TA_SHA,
                bounds_helper_direct_call_targets=[hex(x) for x in calls],
                pe_extraction=dict(lzma_section=hex(section),expanded_bytes=len(expanded),pe_offset=184,matched=True),
                evidence=evidence,candidate_fallback_controls=images,date_property_controls=controls,
                invalid_date_controls=invalid_dates,header_controls=headers,ta_bounds_controls=bounds,
                boundary_controls=boundaries,
                limits=['Captured ABL is from slot_b on 2026-10-22; current slot_a ABL identity/active path not proven.',
                        'Header fallback/property parser entered after route/AVB lookup decisions; selection not executed.',
                        'Synthetic public request only; ABL QSEECom/ROT/service calls not executed or stubbed successful.',
                        '31f10 is bounds-only in this fixed TA; platform gate/dispatcher authorization remain unexecuted.',
                        'TA stops before 404b4 completion; flag/boot writes do not establish complete operation.',
                        'External SDK and real boot initialization/lifetime/TA error PC remain unknown.',
                        'No candidate change, new image, phone access, secure command, key generation/upgrade or persistence.'],
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sources})
    (a.output/'audit.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS 2 candidate header chains, 3 date chains, 5 date rejections, 5 header controls, 8 bounds cases, 6 boundaries; no device')


if __name__=='__main__':main()
