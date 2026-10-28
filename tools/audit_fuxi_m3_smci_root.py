#!/usr/bin/env python3
"""Bind C2 descriptor and object layout assumptions to fixed local modules."""
import argparse,hashlib,json,re,shutil,subprocess,tempfile
from pathlib import Path

EXPECTED={
 'qcom-scm.ko':'8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5',
 'smcinvoke_dlkm.ko':'831a6db7570e66729db84cd0a7ddc63f8cdbc4b03fd250dee15b80b561969348'}


def check_inputs(modules):
 for name,sha in EXPECTED.items():
  if hashlib.sha256((modules/name).read_bytes()).hexdigest()!=sha:raise ValueError('SHA256 mismatch '+name)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--ramdisk',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 modules=a.ramdisk/'vendor/lib/modules/1.1';check_inputs(modules);a.output.mkdir(parents=True,exist_ok=True)
 probes={
  'invoke-descriptor':('qcom-scm.ko',['--start-address=0x7148','--stop-address=0x7210'],
    [r'mov w9, #0x6',r'mov w8, #0x224',r'mov w8, #0x32',r'mov w4, #0x2',
     r'stp x0, x1, \[sp, #0x30\]',r'stp x2, x3, \[sp, #0x40\]',
     r'ldr x8, \[sp, #0x10\]',r'ldr x8, \[sp, #0x8\]',r'ldr x8, \[sp, #0x18\]']),
  'fnid':('qcom-scm.ko',['--start-address=0x85e8','--stop-address=0x8680'],
    [r'cmp w2, #0x2',r'cmp w4, #0x1',r'lsl w8, w20, #30',r'lsl w9, w19, #24',
     r'and x9, x9, #0x3f000000',r'bfi w8, w12, #31, #1']),
  'register':('smcinvoke_dlkm.ko',['--disassemble-symbols=get_client_env_object'],
    [r'mov w1, #0x5',r'mov w3, #0x1100']),
  'release':('smcinvoke_dlkm.ko',['--start-address=0x7c60','--stop-address=0x7cd0'],
    [r'mov w10, #0xffff',r'mov w2, #0x1000',r'mov w5, #0x1000']),
 }
 for name,(module,options,patterns) in probes.items():
  text=subprocess.check_output(['llvm-objdump','-dr',*options,str(modules/module)],text=True)
  normalized=re.sub(r'[\t ]+',' ',text)
  for pattern in patterns:
   if not re.search(pattern,normalized):raise ValueError(name+' instruction mismatch '+pattern)
  (a.output/(name+'.asm')).write_text(text)
 # Validate tamper refusal independently of the disassembler.
 rejected=[]
 with tempfile.TemporaryDirectory(prefix='fuxi-c2-audit-') as temp:
  dst=Path(temp)
  for name in EXPECTED:shutil.copyfile(modules/name,dst/name)
  for name in EXPECTED:
   path=dst/name;raw=path.read_bytes();b=bytearray(raw);b[-1]^=1;path.write_bytes(b)
   try:check_inputs(dst)
   except ValueError:rejected.append(name)
   else:raise RuntimeError('tampered module accepted')
   path.write_bytes(raw)
 report=dict(result='passed',files_sha256=EXPECTED,modified_inputs_rejected=rejected,
  owner=0x32,service=6,command=0,arginfo=0x224,standard_smc64_fnid='72000600',
  returned_registers=dict(scm_status='a0',response_type='a1',object_result='low32(a2)',data='low32(a3)'),
  register=dict(root=1,op=5,counts='1100',null_input=True),release=dict(op='ffff',input_bytes=4096,output_bytes=4096),
  scope='Fixed binary local facts only; standard call and all-zero terminal policy remain hardware-unverified. No callbacks, interruption resume, TA or keys.')
 (a.output/'audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
