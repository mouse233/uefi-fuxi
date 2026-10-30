#!/usr/bin/env python3
"""Bind opt-in lookup layout to fixed deployed TZ evidence and NS structures."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from m3_lookup_arch_binding import load_binding,EVIDENCE


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    root=Path(__file__).resolve().parents[1];binding=load_binding()
    ref=root/'out/m3-qsee-static-v1/sm8550-source/smcinvoke.c'
    # Fixed existing NS reference. A matching internal TZ ABI alone does not
    # prove this marshalling on hardware; the candidate is an explicit probe.
    from audit_fuxi_m3_root_contract import PINNED,check_inputs
    paths={n:root/n for n in PINNED};check_inputs(paths)
    text=ref.read_text();decl=[]
    for kind,name in [('struct','smcinvoke_buf_hdr'),('union','smcinvoke_tz_args'),('struct','smcinvoke_msg_hdr')]:
        m=re.search(r'\b'+kind+r'\s+'+name+r'\s*\{[^{}]*\};',text);assert m;decl.append(m.group())
    code='#include <stdint.h>\n#include <stddef.h>\n'+'\n'.join(decl)+r'''
struct lookup {struct smcinvoke_msg_hdr h; union smcinvoke_tz_args a[3];};
_Static_assert(sizeof(struct lookup)==36,"end");
_Static_assert(offsetof(struct lookup,a[1])==20,"BO");
_Static_assert(offsetof(struct lookup,a[2])==28,"OO");
_Static_assert(((sizeof(struct lookup)+7)&~7)==40,"BI");
_Static_assert(((40+11+7)&~7)==56,"architecture BO");
'''
    a.output.mkdir(parents=True,exist_ok=True);source=a.output/'lookup-arch-wire.c';source.write_text(code)
    subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsyntax-only',str(source)],check=True)
    files=[Path(__file__),root/'tools/m3_lookup_arch_binding.py',root/EVIDENCE,
           root/'tools/audit_fuxi_m3_root_contract.py',root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3SmciDiagnostic.inc']
    report=dict(result='passed',**binding,input_sha256=PINNED,wire_compile_assertions=5,
                reference_exact_device_match=False,sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files},
                scope='Matched TZ op/count/output shape + pinned NS structure offsets, not a hardware authorization/instance proof.')
    (a.output.parent/'m3-lookup-contract-tests.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS deployed lookup contract and 5 compiled NS structure assertions')


if __name__=='__main__':main()
