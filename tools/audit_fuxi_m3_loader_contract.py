#!/usr/bin/env python3
"""Bind loader op/count/UID/inline layout to pinned reference and local module."""
import argparse,hashlib,json,re,subprocess,tempfile
from pathlib import Path
from audit_fuxi_m3_root_contract import PINNED,check_inputs,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 root=Path(__file__).resolve().parents[1];out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 paths={n:root/n for n in PINNED};check_inputs(paths)
 ref=root/'out/m3-qsee-static-v1/sm8550-source'
 h=(ref/'IClientEnv.h').read_text();c=(ref/'smcinvoke.c').read_text()
 require(r'IClientEnv_OP_open\s+0\b',h,'open operation')
 require(r'IClientEnv_open\(.*?&uid_val, sizeof\(uint32_t\).*?ObjectCounts_pack\(1, 0, 0, 1\)',h,'open BI/OO')
 require(r'uint32_t offset = sizeof\(struct smcinvoke_msg_hdr\) \+\s*sizeof\(union smcinvoke_tz_args\) \*\s*OBJECT_COUNTS_TOTAL\(req->counts\)',c,'wire end')
 require(r'FOR_ARGS\(i, req->counts, BI\).*?offset = smci_size_align\(offset, SMCINVOKE_ARGS_ALIGN_SIZE\).*?tz_args\[i\].b.offset = offset;\s*tz_args\[i\].b.size = args_buf\[i\].b.size',c,'inline BI alignment')
 module=paths[next(n for n in PINNED if n.endswith('/smcinvoke_dlkm.ko'))]
 asm=subprocess.check_output(['llvm-objdump','-dr','--start-address=0x1e38','--stop-address=0x1e98',str(module)],text=True)
 norm=re.sub(r'[\t ]+',' ',asm)
 for token in [r'mov w8, #0x7a',r'mov w1, wzr',r'mov w3, #0x1001',r'get_client_env_object']:require(token,norm,'fixed module open')
 (out/'open-loader.asm').write_text(asm)
 # Compile extracted reference wire declarations, rather than restating their sizes.
 decl=[]
 for kind,name in [('struct','smcinvoke_buf_hdr'),('union','smcinvoke_tz_args'),('struct','smcinvoke_msg_hdr')]:
  m=re.search(r'\b'+kind+r'\s+'+name+r'\s*\{[^{}]*\};',c);assert m;decl.append(m.group())
 code='#include <stdint.h>\n#include <stddef.h>\n'+'\n'.join(decl)+r"""
 struct wire {struct smcinvoke_msg_hdr h; union smcinvoke_tz_args a[2];};
 _Static_assert(sizeof(struct wire)==28,"wire end");
 _Static_assert(offsetof(struct wire,a[1])==20,"OO offset");
 _Static_assert(((sizeof(struct wire)+7)&~7)==32,"BI align8");
 _Static_assert(sizeof(uint32_t)==4,"UID size");
 """
 (out/'loader-wire.c').write_text(code)
 subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsyntax-only',str(out/'loader-wire.c')],check=True)
 rejected=[]
 with tempfile.TemporaryDirectory(prefix='loader-pin-') as t:
  for i,(name,path) in enumerate(paths.items()):
   copy=Path(t)/str(i);raw=bytearray(path.read_bytes());raw[-1]^=1;copy.write_bytes(raw)
   try:check_inputs({**paths,name:copy})
   except ValueError:rejected.append(name)
   else:raise AssertionError('mutated input accepted')
 source=[Path(__file__),root/'tools/audit_fuxi_m3_root_contract.py',root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3SmciDiagnostic.inc']
 result=dict(result='passed',uid=122,operation=0,counts='1001',payload_offset=32,payload_bytes=4,oo_offset=20,input_sha256=PINNED,modified_inputs_rejected=rejected,reference_exact_device_match=False,sources={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source},scope='Fixed local instruction patterns and pinned reference inline layout; no runtime authorization or object success proof')
 (out.parent/'m3-loader-contract-tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
