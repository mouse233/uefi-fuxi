#!/usr/bin/env python3
"""Pin current Android vold's binding metadata offsets; no device execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from collect_fuxi_recovery_binding import ANDROID_VOLD_SHA,ANDROID_BINDING_POINTER_VA


def audit(binary,output):
    raw=binary.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ANDROID_VOLD_SHA:raise ValueError('fixed Android vold mismatch')
    output.mkdir(parents=True,exist_ok=True)
    checks={
        'initialize':(0x4a150,0x4a178,['mov w0, #0x48','adrp x8, 0xf9000','stp q0, q0, [x0]','str x0, [x8, #0x790]']),
        'retrieve-application-id':(0x4650c,0x46524,['bl 0x46bf8']),
        'first-use':(0x46cf4,0x46d30,['adrp x20, 0xf9000','ldr x24, [x20, #0x790]','ldr w9, [x8, #0x18]',
                                               'cmp w9, #0x1','mov w9, #0x2','str w9, [x8, #0x18]','ldp x22, x23, [x8]']),
        'set-seed':(0x479fc,0x47a70,['adrp x19, 0xf9000','ldr x24, [x19, #0x790]',
                                         'ldr w8, [x25, #0x18]','cmp w8, #0x2','cmp w8, #0x1','mov w8, #0x1','str w8, [x25, #0x18]']),
        'set-property':(0x47bbc,0x47bf0,['adrp x8, 0x19000','add x8, x8, #0x89b','SetProperty']),
    }
    evidence={}
    for name,(lo,hi,tokens) in checks.items():
        asm=subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-objdump','-d',f'--start-address={lo}',f'--stop-address={hi}',str(binary)],text=True)
        normalized=re.sub(r'[\t ]+',' ',asm)
        if not all(t in normalized for t in tokens):raise ValueError('binding instruction changed: '+name)
        (output/(name+'.asm')).write_text(asm)
        evidence[name]=dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(asm.encode()).hexdigest())
    if raw[0x1989b:0x1989b+24]!=b'vold.storage_seed_bound\0':raise ValueError('property string changed')
    root=Path(__file__).resolve().parents[1]
    report=dict(result='passed',executable_sha256=ANDROID_VOLD_SHA,global_pointer_va=hex(ANDROID_BINDING_POINTER_VA),
                object_bytes=72,vector_header_bytes=24,state_offset=24,capture_object_bytes=28,
                states={'0':'not set or used','1':'seed set','2':'used without binding'},
                evidence=evidence,scope='Fixed Android executable instruction facts only, not a runtime binding capture.',
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in (Path(__file__),Path(__file__).with_name('collect_fuxi_recovery_binding.py'))})
    (output/'audit.json').write_text(json.dumps(report,indent=2)+'\n');return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    r=audit(a.binary,a.output);print(json.dumps(dict(result=r['result'],global_pointer_va=r['global_pointer_va'])))
if __name__=='__main__':main()
