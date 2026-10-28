#!/usr/bin/env python3
"""Bind loader lookup op/name/wire layout to pinned reference and local module."""
import argparse,hashlib,json,re,subprocess,tempfile
from pathlib import Path
from audit_fuxi_m3_root_contract import PINNED,check_inputs,require
EXTRA={'out/m3-qsee-static-v1/sm8550-source/IQSEEComCompatAppLoader.h':'597124e1769ab805fef0e947a4636dc043250ba368cc218557a339fd55122a06'}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 root=Path(__file__).resolve().parents[1];out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 pinned={**PINNED,**EXTRA};paths={n:root/n for n in pinned}
 check_inputs(paths)
 for n,h in EXTRA.items():assert hashlib.sha256((root/n).read_bytes()).hexdigest()==h,n
 ref=root/'out/m3-qsee-static-v1/sm8550-source'
 h=(ref/'IQSEEComCompatAppLoader.h').read_text();c=(ref/'smcinvoke.c').read_text()
 require(r'IQSEEComCompatAppLoader_OP_lookupTA\s+2\b',h,'lookup operation')
 require(r'IQSEEComCompatAppLoader_lookupTA\(.*?appName_ptr,\s*size_t appName_len.*?ObjectCounts_pack\(1, 0, 0, 1\)',h,'lookup BI/OO')
 require(r'IQSEEComCompatAppLoader_MAX_FILENAME_LEN UINT32_C\(64\)',h,'name limit')
 require(r'uint32_t offset = sizeof\(struct smcinvoke_msg_hdr\) \+\s*sizeof\(union smcinvoke_tz_args\) \*\s*OBJECT_COUNTS_TOTAL\(req->counts\)',c,'wire end')
 require(r'FOR_ARGS\(i, req->counts, BI\).*?offset = smci_size_align\(offset, SMCINVOKE_ARGS_ALIGN_SIZE\).*?tz_args\[i\].b.offset = offset;\s*tz_args\[i\].b.size = args_buf\[i\].b.size',c,'inline BI alignment')
 module=paths[next(n for n in pinned if n.endswith('/smcinvoke_dlkm.ko'))]
 asm=subprocess.check_output(['llvm-objdump','-dr','--start-address=0x1f18','--stop-address=0x1f84',str(module)],text=True)
 norm=re.sub(r'[\t ]+',' ',asm)
 for token in [r'mov w1, #0x2',r'mov w3, #0x1001',r'firmware_request_from_smcinvoke',r'b 0x2028']:require(token,norm,'fixed module lookup')
 (out/'lookup-loader.asm').write_text(asm)
 decl=[]
 for kind,name in [('struct','smcinvoke_buf_hdr'),('union','smcinvoke_tz_args'),('struct','smcinvoke_msg_hdr')]:
  m=re.search(r'\b'+kind+r'\s+'+name+r'\s*\{[^{}]*\};',c);assert m;decl.append(m.group())
 code='#include <stdint.h>\n#include <stddef.h>\n'+'\n'.join(decl)+r"""
 struct wire {struct smcinvoke_msg_hdr h; union smcinvoke_tz_args a[2];};
 _Static_assert(sizeof(struct wire)==28,"wire end");
 _Static_assert(offsetof(struct wire,a[1])==20,"OO offset");
 _Static_assert(((sizeof(struct wire)+7)&~7)==32,"BI align8");
 _Static_assert(offsetof(struct wire,a[0].b.offset)==12,"BI descriptor");
 """
 (out/'lookup-wire.c').write_text(code)
 subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsyntax-only',str(out/'lookup-wire.c')],check=True)
 rejected=[]
 with tempfile.TemporaryDirectory(prefix='lookup-pin-') as t:
  for i,(name,path) in enumerate(paths.items()):
   expected=pinned[name];copy=Path(t)/str(i)
   raw=bytearray(path.read_bytes());raw[-1]^=1;copy.write_bytes(raw)
   assert hashlib.sha256(copy.read_bytes()).hexdigest()!=expected,name
   if name in EXTRA:
    rejected.append(name)
   else:
    try:check_inputs({**paths,name:copy})
    except ValueError:rejected.append(name)
    else:raise AssertionError('mutated input accepted')
 source=[Path(__file__),root/'tools/audit_fuxi_m3_root_contract.py',root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3SmciDiagnostic.inc']
 result=dict(result='passed',operation=2,counts='1001',payload_offset=32,oo_offset=20,name_limit=64,names=['keymaster64','keymaster'],input_sha256=pinned,modified_inputs_rejected=rejected,reference_exact_device_match=False,sources={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source},scope='Fixed local instruction patterns and pinned lookup inline layout; no runtime authorization or TA existence proof')
 (out.parent/'m3-lookup-contract-tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
