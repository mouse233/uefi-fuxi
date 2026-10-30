#!/usr/bin/env python3
"""Read only fixed recovery binding metadata, never seed/key/buffer contents.

Requires the pinned A17 recovery, root ADB, a mapped /data and stable process
identity. Reads exactly the global pointer (8 bytes) and binding vector/state
header (28 bytes), twice. Does not dereference any vector/seed pointer.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess

SERIAL = 'fcde91e'
RECOVERY_SHA = '9aa603b1b2851df9c773c153f7df4520b7c634be0c15bc55f43c2fb83b82e4b0'
BINDING_POINTER_VA = 0x274398
ANDROID_VOLD_SHA = '9c20de9cb015e066474ad9cc23e1364d5ddf4fa55fca5f2c9a57e3ad0caed418'
ANDROID_BINDING_POINTER_VA = 0xf9790


def parse_maps(text):
    rows=[]
    for line in text.splitlines():
        m=re.fullmatch(r'([0-9a-f]+)-([0-9a-f]+) ([rwxps-]{4}) ([0-9a-f]+) ([0-9a-f]+:[0-9a-f]+) ([0-9]+)(?:\s+(.*))?',line)
        if not m: raise ValueError('malformed process mapping')
        lo,hi,off=(int(m.group(i),16) for i in (1,2,4))
        if lo>=hi or hi>1<<48: raise ValueError('mapping outside supported userspace')
        rows.append((lo,hi,m.group(3),off,m.group(7) or ''))
    if not rows:raise ValueError('empty process mappings')
    return rows


def collect(run,android=False):
    def text(*args):return run(*args).decode('utf-8','strict').strip()
    if text('get-state')!=('device' if android else 'recovery'):raise ValueError('unexpected ADB state for pinned process')
    for key,value in (('ro.product.device','fuxi'),('ro.boot.serialno',SERIAL),('ro.build.version.release','17')):
        if text('shell','getprop',key)!=value:raise ValueError('unexpected recovery identity')
    twrp=text('shell','getprop','ro.twrp.version')
    if (android and twrp) or (not android and not twrp):raise ValueError('unexpected Android/recovery identity')
    if text('shell','id','-u')!='0':raise ValueError('existing root recovery ADB required')
    mounts=text('shell','cat','/proc/mounts').splitlines()
    data=[line.split() for line in mounts if len(line.split())>=4 and line.split()[1]=='/data']
    if len(data)!=1 or data[0][2]!='f2fs' or not re.fullmatch(r'/dev/block/dm-[0-9]+',data[0][0]):
        raise ValueError('expected uniquely mapped F2FS /data')
    process='vold' if android else 'recovery'
    expected_sha=ANDROID_VOLD_SHA if android else RECOVERY_SHA
    pids=text('shell','pidof',process).split()
    if len(pids)!=1 or not re.fullmatch(r'[1-9][0-9]{0,6}',pids[0]):raise ValueError('unique recovery PID required')
    pid=pids[0];exe='/proc/'+pid+'/exe'
    identity=text('shell','sha256sum',exe).split()
    if identity!=[expected_sha,exe]:raise ValueError('fixed executable SHA mismatch')
    def start_time():
        stat=text('shell','cat','/proc/'+pid+'/stat')
        # Field22 follows the final ')' and state field; names may contain spaces.
        tail=stat.rsplit(')',1)
        if len(tail)!=2 or not stat.startswith(pid+' ('):raise ValueError('unexpected process stat')
        fields=tail[1].split()
        if len(fields)<20 or not fields[19].isdigit():raise ValueError('invalid process start time')
        return fields[19]
    before=start_time()
    maps_text=text('shell','cat','/proc/'+pid+'/maps');maps=parse_maps(maps_text)
    paths=('/system/bin/vold',) if android else ('/system/bin/recovery','/sbin/recovery')
    origins=[row for row in maps if row[3]==0 and row[4] in paths and 'r' in row[2]]
    if len(origins)!=1:raise ValueError('unique pinned recovery mapping origin required')
    origin=origins[0];pointer_address=origin[0]+(ANDROID_BINDING_POINTER_VA if android else BINDING_POINTER_VA)
    def readable(address,size,anonymous=False):
        rows=[r for r in maps if r[0]<=address and address+size<=r[1] and 'r' in r[2] and 'w' in r[2] and 'p' in r[2]]
        if len(rows)!=1:raise ValueError('binding metadata outside unique private read/write mapping')
        if anonymous and rows[0][4] and not rows[0][4].startswith('[anon:') and rows[0][4]!='[heap]':
            raise ValueError('binding object is not in a supported anonymous allocation')
    readable(pointer_address,8)
    def memory(address,size):
        # Only these two scalar metadata sizes can be read. No arbitrary dump,
        # no follow-up access to begin/end/capacity, no shell-derived arguments.
        if size not in (8,28) or address<4096 or address+size>=1<<48:raise ValueError('metadata read bound')
        command=shlex.join(['dd','if=/proc/'+pid+'/mem','bs=1','skip='+str(address),'count='+str(size)])+' 2>/dev/null'
        raw=run('exec-out','sh','-c',command)
        if len(raw)!=size:raise ValueError('short process metadata read')
        return raw
    snapshots=[]
    for unused in range(2):
        pointer=memory(pointer_address,8)
        address=struct.unpack('<Q',pointer)[0]
        # The pinned TWRP recovery also uses tagged AArch64 heap pointers, as
        # observed by a pointer-only read. Strip only the top byte, then retain
        # the existing low-48-bit, alignment and private-mapping checks.
        address&=0x00ffffffffffffff
        if address&7 or not 4096<=address<(1<<48)-28:raise ValueError('invalid binding object pointer')
        readable(address,28,True)
        header=memory(address,28)
        snapshots.append((pointer,header))
    if snapshots[0]!=snapshots[1] or before!=start_time() or maps_text!=text('shell','cat','/proc/'+pid+'/maps'):
        raise ValueError('binding process metadata changed during capture')
    begin,end,capacity,state=struct.unpack('<QQQI',snapshots[0][1])
    if state!=2 or begin or end or capacity:
        # Report no pointers, lengths or contents on rejection. State1 requires
        # a separate binding-seed path; it must not fall back to an empty seed.
        raise ValueError('unbound-used state with empty vector not established')
    return dict(schema=1,collected_utc=datetime.now(timezone.utc).isoformat(),serial=SERIAL,
                process=process,executable_sha256=expected_sha,process_pid=int(pid),process_start_ticks=before,
                pointer_tag_present=bool(struct.unpack('<Q',snapshots[0][0])[0]>>56),
                data_mount=dict(device=data[0][0],filesystem=data[0][2]),
                binding=dict(state=2,meaning='used without seed',vector_empty=True,stable_snapshots=2),
                collector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                scope='Read-only fixed process runtime binding metadata. No seed, key, authentication token or decrypted contents read. Does not prove a UEFI recovery or identify/authorize a per-key configuration.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb',type=Path,default=Path('/opt/homebrew/bin/adb'))
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--android-vold',action='store_true',help='read the pinned current Android vold using existing su, instead of TWRP recovery')
    a=p.parse_args()
    if a.output.exists():raise SystemExit('refusing to overwrite a capture')
    ps=subprocess.run(['ps','-eo','pid=,args='],capture_output=True,text=True,check=True)
    if any(any(s in line for s in ('test-usb-ram-full','usb-ram-send','boot-ram-window')) for line in ps.stdout.splitlines()):
        raise SystemExit('another device task is active')
    def run(*args):
        actual=args
        if a.android_vold and args[0] in ('shell','exec-out'):
            actual=(args[0],'/system/bin/su','-c',shlex.join(args[1:]))
        result=subprocess.run([str(a.adb),'-s',SERIAL,*actual],capture_output=True,timeout=20)
        if result.returncode:raise ValueError('ADB read failed; no capture produced')
        return result.stdout
    result=collect(run,a.android_vold)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print('Captured non-secret recovery binding state:',a.output)


if __name__=='__main__':main()
