#!/usr/bin/env python3
"""Synthetic tests for the read-only TWRP context collector; never a phone."""
import argparse
import hashlib
import json
from pathlib import Path
from collect_fuxi_twrp_keymint_context import collect, PROPS, PROCESSES, PINS, LIBS


class Fake:
    def __init__(self, fault=''):
        self.fault=fault; self.calls=[]; self.stats={}; self.reads={}; self.props={name:'' for name in PROPS}
        self.props.update({'ro.product.device':'fuxi','ro.boot.serialno':'fcde91e',
            'ro.twrp.version':'reference-TWRP','ro.build.version.release':'17',
            'ro.system.build.version.release':'17','ro.build.version.security_patch':'2099-12-31',
            'ro.vendor.build.security_patch':'2099-12-31','ro.boot.slot_suffix':'_a',
            'vendor.sys.listeners.registered':'true'})
        for name in PROPS:
            if name.startswith('init.svc.'):self.props[name]='running'
        self.pids={name:str(100+i) for i,name in enumerate(PROCESSES)}
    def __call__(self,*args):
        self.calls.append(args); f=self.fault
        if args==('get-state',):return b'device' if f=='mode' else b'recovery'
        if args==('shell','id','-u'):return b'2000' if f=='root' else b'0'
        if args[:2]==('shell','getprop'):
            key=args[2];self.reads[key]=self.reads.get(key,0)+1;value=self.props[key]
            if f==key:value='unexpected'
            if f=='property-race' and key=='ro.build.version.release' and self.reads[key]>1:value='16'
            return value.encode()
        if args[:2]==('shell','pidof'):
            name=args[2];return (self.pids[name]+(' 999' if f=='pids' else '')).encode()
        if args[:2]==('shell','sha256sum'):
            path=args[2]
            if path in LIBS:value=PINS[path]
            else:
                name=next(n for n,pid in self.pids.items() if path=='/proc/'+pid+'/exe')
                value=PINS[name]
            if f=='hash-mismatch' and path==LIBS[0]:value='0'*64
            if f=='bad-hash':return b'malformed'
            return (value+'  '+path).encode()
        if args[:2]==('shell','cat'):
            path=args[2]
            for name,pid in self.pids.items():
                if path=='/proc/'+pid+'/stat':
                    self.stats[pid]=self.stats.get(pid,0)+1
                    start=1000+(1 if f=='pid-race' and self.stats[pid]>1 else 0)
                    return (pid+' (process name) '+' '.join(['S']+['0']*18+[str(start)])).encode()
                if path=='/proc/'+pid+'/maps':
                    if f=='bad-maps':return b'malformed'
                    libs=LIBS[:-1] if f=='missing-map' else LIBS
                    return '\n'.join(f'{0x100000+i*4096:x}-{0x101000+i*4096:x} r-xp 00000000 00:01 12 {lib}' for i,lib in enumerate(libs)).encode()
        raise AssertionError('non-allowlisted or state-changing command: '+repr(args))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    good=Fake();r=collect(good)
    assert r['reference_hashes_match'] and r['stable_snapshots']==2 and not r['constructor_values_proven']
    assert '/proc/' not in json.dumps(r) and '100000-' not in json.dumps(r)
    faults=['mode','root','ro.product.device','ro.boot.serialno','ro.boot.slot_suffix',
            'init.svc.keystore2','init.svc.vendor.keymint-qti','init.svc.vendor.qseecomd',
            'vendor.sys.listeners.registered','pids','bad-hash','bad-maps','missing-map','pid-race','property-race']
    for fault in faults:
        fake=Fake(fault)
        try:collect(fake)
        except ValueError:pass
        else:raise AssertionError('invalid capture accepted: '+fault)
    mismatch=collect(Fake('hash-mismatch'))
    assert not mismatch['reference_hashes_match'] and mismatch['reference_mismatches']==[LIBS[0]]
    files=[Path(__file__),Path(__file__).with_name('collect_fuxi_twrp_keymint_context.py'),
           Path(__file__).with_name('collect_fuxi_recovery_binding.py')]
    report=dict(result='passed',synthetic=True,cases=len(faults)+2,
        scope='Fake ADB command allowlist and process/property metadata only; not a live capture or constructor proof.',
        sources={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in files})
    a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',report['cases'],'TWRP context collector cases; synthetic ADB only')


if __name__=='__main__':main()
