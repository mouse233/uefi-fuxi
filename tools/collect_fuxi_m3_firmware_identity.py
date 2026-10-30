#!/usr/bin/env python3
"""Hash four fixed fuxi firmware partitions in TWRP; no raw capture or writes.

Reads identity, partition geometry, a fixed userspace library hash and firmware
hashes only. Does not read userdata/metadata, logs, process memory or issue a
KeyMint/security command. Stable partition identity is not a running-RAM trace.
"""
import argparse
import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path
from zoneinfo import ZoneInfo

SERIAL='fcde91e'
ABL_SHA='78595f9a5fbaba528b894fa7f3991db37fe1bcd03be3036e5cb3c254405655f3'
TZ_SHA='d4b8afbe3a8b3468a0f4f740059ab9aed0a8ef803af4f1f58b164ce1c460d418'
LIB='/vendor/lib64/libqtikeymint.so'
LIB_SHA='657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb'
PARTS={'abl_a':('/dev/block/sde11',8388608), 'abl_b':('/dev/block/sde41',8388608),
       'tz_a':('/dev/block/sde5',4194304), 'tz_b':('/dev/block/sde35',4194304)}


def references(abl,tz):
    if len(abl)!=8388608 or hashlib.sha256(abl).hexdigest()!=ABL_SHA:
        raise ValueError('fixed historical ABL reference mismatch')
    if len(tz)!=3973120 or hashlib.sha256(tz).hexdigest()!=TZ_SHA:
        raise ValueError('fixed local ROM TZ reference mismatch')
    return dict(abl=dict(bytes=len(abl),sha256=ABL_SHA,padded_sha256=ABL_SHA),
                tz=dict(bytes=len(tz),sha256=TZ_SHA,padded_sha256=hashlib.sha256(tz+bytes(4194304-len(tz))).hexdigest()))


def collect(run,refs):
    def text(*args):return run(*args).decode('utf-8',errors='strict').strip()
    def identity():
        if text('get-state')!='recovery':raise ValueError('expected recovery transport')
        keys=('ro.product.device','ro.boot.serialno','ro.boot.slot_suffix','ro.twrp.version','ro.build.version.release')
        props={k:text('shell','getprop',k) for k in keys}
        if (props['ro.product.device']!='fuxi' or props['ro.boot.serialno']!=SERIAL or
            props['ro.boot.slot_suffix']!='_a' or not props['ro.twrp.version'] or
            props['ro.build.version.release']!='17' or text('shell','id','-u')!='0'):
            raise ValueError('unexpected fixed fuxi TWRP identity')
        boot=text('shell','cat','/proc/sys/kernel/random/boot_id')
        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot):
            raise ValueError('invalid boot continuity marker')
        return props,boot
    def library():
        if text('shell','sha256sum',LIB).split()!=[LIB_SHA,LIB]:
            raise ValueError('fixed KeyMint reference library mismatch')
    def geometry():
        result={}
        for name,(target,size) in PARTS.items():
            path='/dev/block/by-name/'+name
            if text('shell','readlink','-f',path)!=target:
                raise ValueError('unexpected firmware partition mapping')
            if text('shell','test -b '+path+' && echo block')!='block':
                raise ValueError('expected firmware block device')
            if text('shell','blockdev','--getsize64',path)!=str(size):
                raise ValueError('unexpected firmware partition size')
            result[name]=dict(path=path,target=target,bytes=size)
        return result
    before=identity();library();geo=geometry();snapshots=[]
    for _ in range(2):
        row={}
        for name in PARTS:
            path=geo[name]['path'];values=text('shell','sha256sum',path).split()
            if len(values)!=2 or not re.fullmatch(r'[0-9a-f]{64}',values[0]) or values[1]!=path:
                raise ValueError('invalid firmware hash response')
            row[name]=values[0]
        snapshots.append(row)
    if snapshots[0]!=snapshots[1] or before!=identity() or geo!=geometry():
        raise ValueError('firmware or recovery context changed during capture')
    library()
    for name,row in geo.items():
        row['sha256']=snapshots[0][name]
        row['reference']=name.split('_')[0]
        row['matches_zero_padded_reference']=row['sha256']==refs[row['reference']]['padded_sha256']
    return dict(result='captured',serial=SERIAL,properties=before[0],stable_snapshots=2,
                boot_continuity_checked=True,reference_library_sha256=LIB_SHA,
                references=refs,partitions=geo,
                all_references_match=all(x['matches_zero_padded_reference'] for x in geo.values()),
                firmware_bytes_hashed_on_device=sum(x[1] for x in PARTS.values())*2,
                raw_firmware_bytes_transferred=0,
                limits=['Device-side hashes only; no raw firmware, userdata/metadata or key material captured.',
                        'Current partition contents + slot property do not attest loaded secure-world RAM or TA instance state.',
                        'No KeyMint/security call, process-memory read, reboot, slot change, mount, remount or partition write.',
                        'SDK service results, boot patch runtime value, real -62 return PC and M3/M4/M5 remain unverified.'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb',default='/opt/homebrew/bin/adb')
    p.add_argument('--serial',choices=[SERIAL],required=True)
    for name in ('abl-reference','tz-reference','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():raise SystemExit('refusing to replace prior capture')
    refs=references(a.abl_reference.read_bytes(),a.tz_reference.read_bytes())
    processes=subprocess.check_output(['ps','-eo','pid=,args='],text=True)
    if re.search(r'test-usb-ram-full|usb-ram-send|boot-ram-window',processes):
        raise SystemExit('another device task is active')
    def run(*args):
        proc=subprocess.run([a.adb,'-s',a.serial,*args],capture_output=True,timeout=30)
        if proc.returncode:raise ValueError('fixed read-only ADB command failed; output suppressed')
        return proc.stdout
    report=collect(run,refs)
    report['captured_at']=datetime.datetime.now(ZoneInfo('Asia/Shanghai')).isoformat()
    root=Path(__file__).resolve().parents[1]
    report['sources']={str(Path(__file__).relative_to(root)):hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x') as f:f.write(json.dumps(report,indent=2)+'\n')
    print('Captured 2 stable firmware-hash snapshots; matches='+str(report['all_references_match'])+'; no raw bytes/device writes')


if __name__=='__main__':main()
