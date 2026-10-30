#!/usr/bin/env python3
"""Synthetic ADB/proc metadata tests, never a device binding capture."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import struct
from collect_fuxi_recovery_binding import collect,RECOVERY_SHA,BINDING_POINTER_VA,ANDROID_VOLD_SHA,ANDROID_BINDING_POINTER_VA


class Fake:
    def __init__(self,fault='',recovery_tag=False):
        self.fault=fault;self.reads=[];self.stats=0;self.maps_calls=0
        self.recovery_tag=recovery_tag
        self.base=0x7000000000;self.object=0x7100000000
    def __call__(self,*args):
        fault=self.fault
        if args==('get-state',):return b'device' if fault=='state' else b'recovery'
        if args[:2]==('shell','getprop'):
            props={'ro.product.device':'fuxi','ro.boot.serialno':'fcde91e','ro.build.version.release':'17','ro.twrp.version':'A17'}
            value=props[args[2]]
            if fault==args[2]:value='' if args[2]=='ro.twrp.version' else 'unexpected'
            return value.encode()
        if args==('shell','id','-u'):return b'2000' if fault=='root' else b'0'
        if args==('shell','cat','/proc/mounts'):
            return b'/dev/block/sda1 /data f2fs rw 0 0' if fault=='mount' else b'/dev/block/dm-7 /data f2fs rw 0 0'
        if args==('shell','pidof','recovery'):return b'123 456' if fault=='pids' else b'123'
        if args==('shell','sha256sum','/proc/123/exe'):
            return ((('0'*64) if fault=='sha' else RECOVERY_SHA)+'  /proc/123/exe').encode()
        if args==('shell','cat','/proc/123/stat'):
            self.stats+=1
            fields=['S']+['0']*18+[str(999+(1 if fault=='pid-race' and self.stats==2 else 0))]
            return ('123 (recovery process) '+' '.join(fields)).encode()
        if args==('shell','cat','/proc/123/maps'):
            self.maps_calls+=1;b=self.base
            first=f'{b:x}-{b+0x100000:x} r-xp 00000000 00:01 12 /system/bin/recovery\n'
            data=f'{b+0x270000:x}-{b+0x280000:x} rw-p 00270000 00:01 12 /system/bin/recovery\n'
            heap=f'{self.object:x}-{self.object+4096:x} rw-p 00000000 00:00 0 [anon:libc_malloc]\n'
            if fault=='map-origin':first=first+f'{b+0x1000000:x}-{b+0x1100000:x} r-xp 00000000 00:01 12 /system/bin/recovery\n'
            if fault=='map-perms':data=data.replace('rw-p','r--p')
            if fault=='map-malformed':return b'broken map'
            if fault=='map-race' and self.maps_calls==2:heap=heap.replace('[anon:libc_malloc]','[heap]')
            return (first+data+heap).encode()
        if args[:3]==('exec-out','sh','-c'):
            parts=shlex.split(args[3]);assert parts[0:3]==['dd','if=/proc/123/mem','bs=1'] and parts[-1]=='2>/dev/null'
            address=int(parts[3].split('=')[1]);size=int(parts[4].split('=')[1]);self.reads.append((address,size))
            assert (address,size) in ((self.base+BINDING_POINTER_VA,8),(self.object,28))
            if size==8:
                pointer=self.object+(0x10000 if fault=='pointer' else 0)
                if self.recovery_tag:pointer|=0xb400000000000000
                if fault=='noncanonical-pointer':pointer|=0xb401000000000000
                return struct.pack('<Q',pointer)
            state={'binding0':0,'binding1':1,'binding3':3}.get(fault,2)
            if fault=='header-race' and len(self.reads)==4:state=1
            raw=struct.pack('<QQQI',1 if fault=='vector' else 0,0,0,state)
            return raw[:-1] if fault=='short' else raw
        raise AssertionError('unexpected command '+repr(args))


class AndroidFake(Fake):
    def __init__(self,tagged=False):super().__init__();self.tagged=tagged
    def __call__(self,*args):
        if args==('get-state',):return b'device'
        if args==('shell','getprop','ro.twrp.version'):return b''
        if args==('shell','pidof','vold'):args=('shell','pidof','recovery')
        if args==('shell','sha256sum','/proc/123/exe'):return (ANDROID_VOLD_SHA+'  /proc/123/exe').encode()
        if args[:3]==('exec-out','sh','-c'):
            args=(args[0],args[1],args[2],args[3].replace('skip='+str(self.base+ANDROID_BINDING_POINTER_VA),'skip='+str(self.base+BINDING_POINTER_VA)))
        value=super().__call__(*args)
        if args==('shell','cat','/proc/123/maps'):
            value=value.replace(b'/system/bin/recovery',b'/system/bin/vold').replace(f'{self.base+0x270000:x}-{self.base+0x280000:x}'.encode(),f'{self.base+0xf9000:x}-{self.base+0xfa000:x}'.encode())
        if self.tagged and args[:3]==('exec-out','sh','-c') and len(value)==8:
            value=struct.pack('<Q',struct.unpack('<Q',value)[0]|0xb400000000000000)
        return value


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    fake=Fake();report=collect(fake)
    assert report['binding']==dict(state=2,meaning='used without seed',vector_empty=True,stable_snapshots=2)
    assert [n for _,n in fake.reads]==[8,28,8,28]
    serialized=json.dumps(report)
    assert str(fake.object) not in serialized and 'seed_bytes' not in serialized
    faults=['state','ro.product.device','ro.boot.serialno','ro.build.version.release','ro.twrp.version','root','mount','pids','sha',
            'map-origin','map-perms','map-malformed','pointer','noncanonical-pointer','binding0','binding1','binding3','vector','header-race','pid-race','map-race','short']
    for fault in faults:
        fake=Fake(fault)
        try:collect(fake)
        except (ValueError,UnicodeError):pass
        else:raise AssertionError('invalid binding accepted: '+fault)
    for tagged in (False,True):
        report=collect(AndroidFake(tagged),True)
        assert report['process']=='vold' and report['executable_sha256']==ANDROID_VOLD_SHA and report['binding']['state']==2
    tagged_recovery=Fake(recovery_tag=True);report=collect(tagged_recovery)
    assert report['pointer_tag_present'] and report['binding']['state']==2
    assert [n for _,n in tagged_recovery.reads]==[8,28,8,28]
    root=Path(__file__).resolve().parents[1]
    result=dict(result='passed',synthetic=True,cases=4+len(faults),metadata_bytes_per_success=72,
                scope='Fake ADB and /proc headers only. Not a phone capture and never evidence to set BindingChecked.',
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in (Path(__file__),Path(__file__).with_name('collect_fuxi_recovery_binding.py'))})
    a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(result='passed',synthetic=True,cases=result['cases'])))


if __name__=='__main__':main()
