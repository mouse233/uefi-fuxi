#!/usr/bin/env python3
"""Inject only device replies to test fail-closed identity and capture races."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
from collect_fuxi_m3_firmware_identity import collect, PARTS, LIB, LIB_SHA, SERIAL


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    refs={k:dict(bytes=1,sha256=v*64,padded_sha256=v*64) for k,v in (('abl','a'),('tz','b'))}
    results=[]
    for case in ('stable-match','stable-firmware-differs','wrong-serial','wrong-slot','not-recovery','not-root',
                 'wrong-library','wrong-target','not-block','wrong-size','bad-hash','partition-race',
                 'boot-race','transport-error','library-race','geometry-race'):
        hashes=identities=libraries=geometry_reads=0;calls=[]
        def run(*args):
            nonlocal hashes,identities,libraries,geometry_reads
            calls.append(args)
            if case=='transport-error':raise ValueError('simulated transport failed')
            if args==('get-state',):
                identities+=1
                return b'fastboot' if case=='not-recovery' else b'recovery'
            if args[:2]==('shell','getprop'):
                values={'ro.product.device':'fuxi','ro.boot.serialno':SERIAL,'ro.boot.slot_suffix':'_a',
                        'ro.twrp.version':'test','ro.build.version.release':'17'}
                if case=='wrong-serial':values['ro.boot.serialno']='another'
                if case=='wrong-slot':values['ro.boot.slot_suffix']='_b'
                return values[args[2]].encode()
            if args==('shell','id','-u'):return b'1000' if case=='not-root' else b'0'
            if args==('shell','cat','/proc/sys/kernel/random/boot_id'):
                return ('00000000-0000-0000-0000-'+('000000000001' if case=='boot-race' and identities>1 else '000000000000')).encode()
            if args[:2]==('shell','readlink'):
                name=args[-1].split('/')[-1]
                return (('/dev/block/sde99' if case=='wrong-target' else PARTS[name][0])).encode()
            if args[0]=='shell' and len(args)==2 and args[1].startswith('test -b '):
                return b'' if case=='not-block' else b'block'
            if args[:2]==('shell','blockdev'):
                geometry_reads+=1;size=PARTS[args[-1].split('/')[-1]][1]
                if case=='wrong-size' or case=='geometry-race' and geometry_reads>4:size+=4096
                return str(size).encode()
            if args[:2]==('shell','sha256sum'):
                path=args[-1]
                if path==LIB:
                    libraries+=1
                    return ((('f'*64 if case=='wrong-library' or case=='library-race' and libraries>1 else LIB_SHA))+'  '+LIB).encode()
                hashes+=1;name=path.split('/')[-1]
                digest=refs[name.split('_')[0]]['padded_sha256']
                if case=='stable-firmware-differs':digest='c'*64
                if case=='partition-race' and hashes>4:digest='f'*64
                if case=='bad-hash':digest='bad'
                return (digest+'  '+path).encode()
            raise AssertionError('unexpected command')
        try:report=collect(run,copy.deepcopy(refs))
        except ValueError:
            assert case not in ('stable-match','stable-firmware-differs'),case
            results.append(dict(case=case,rejected=True))
        else:
            assert case in ('stable-match','stable-firmware-differs'),case
            assert report['all_references_match']==(case=='stable-match') and report['raw_firmware_bytes_transferred']==0
            assert report['firmware_bytes_hashed_on_device']==50331648
            results.append(dict(case=case,captured=True,matches=report['all_references_match']))
        # Fail before partition reads when identity, mapping or reference is bad.
        if case in ('wrong-serial','wrong-slot','not-recovery','not-root','wrong-library','wrong-target','not-block','wrong-size'):
            assert hashes==0,case
        assert all(not any(x in str(cmd) for x in ('userdata','metadata','reboot','mount','dd ','keymaster_key_blob')) for cmd in calls)
    root=Path(__file__).resolve().parents[1]
    sources={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
             (Path(__file__),root/'tools/collect_fuxi_m3_firmware_identity.py')}
    a.report.parent.mkdir(parents=True,exist_ok=True)
    a.report.write_text(json.dumps(dict(result='passed',cases=results,sources=sources),indent=2)+'\n')
    print('PASS 16 firmware identity collector cases; no device')


if __name__=='__main__':main()
