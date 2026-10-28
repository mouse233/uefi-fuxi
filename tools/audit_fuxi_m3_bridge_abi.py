#!/usr/bin/env python3
"""Pin bridge call type and result slots to the fixed local module."""
import argparse,hashlib,json,re,subprocess,tempfile
from pathlib import Path
EXPECTED='8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5'
def check(p):
 if hashlib.sha256(p.read_bytes()).hexdigest()!=EXPECTED:raise ValueError('fixed qcom-scm.ko SHA256 mismatch')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--module',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 check(a.module);a.output.mkdir(exist_ok=True,parents=True)
 probes={
 'enable':(0x4358,0x445c,[r'movk x8, #0x1c, lsl #32',r'mov w4, wzr',r'__scm_smc_call',r'ldr w8, \[sp, #0x8\]',r'csel w0, w8, w0, eq']),
 'create':(0x4560,0x4684,[r'movk x9, #0x1e, lsl #32',r'mov w8, #0x4',r'mov w8, #0x2',r'mov w4, wzr',r'ldr x8, \[sp, #0x10\]',r'str x8, \[x19\]',r'ldr w8, \[sp, #0x8\]',r'csel w0, w8, w0, eq']),
 'delete':(0x445c,0x4560,[r'movk x8, #0x1d, lsl #32',r'mov w4, wzr',r'mov x3, xzr',r'__scm_smc_call']),
 'transport':(0x85e8,0x87a0,[r'cmp w4, #0x1',r'cset w12, eq',r'bfi w8, w12, #31, #1',r'cmp w10, #0x5',r'ldr x27, \[x23, #0x28\]',r'mov x5, x27',r'mov x6, xzr',r'mov x7, xzr']),
 'results':(0x8940,0x8958,[r'ldp x8, x9, \[x29, #-0x50\]',r'ldur x10, \[x29, #-0x40\]',r'stp x8, x9, \[x11\]',r'str x10, \[x11, #0x10\]']),
 'probe-hlos':(0x96a8,0x9734,[r'mov w8, #0x3',r'mov w9, #0x6',r'str w8, \[sp, #0x10\]',r'stp wzr, w9, \[sp, #0x8\]',r'\.rodata\+0xa91',r'cset w9, ne',r'csel x20, x11, x10, ne']),
 'probe-create':(0x99ac,0x99d4,[r'ldrb w8, \[x25\]',r'add x3, sp, #0xc',r'mov x2, x20',r'eor w4, w8, #0x1',r'mov w5, #0x6',r'qtee_shmbridge_register']),
 'pool':(0x9754,0x97b4,[r'mov w9, #0x400000',r'csel w1, w8, w9, ge',r'__get_free_pages']),
 'pool-map':(0x9894,0x993c,[r'dma_map_page_attrs',r'gen_pool_create',r'gen_pool_add_owner']),
 'register-permissions':(0x9184,0x91c8,[r'ldr w8, \[x25, x12\]',r'ldrh w3, \[x26, x12\]',r'bfi x8, x11, #3, #61',r'bfi x3, x10, #16, #48']),
 'register':(0x91c8,0x9204,[r'lsl w10, w23, #9',r'orr x0, x8, x20',r'orr x1, x9, x20',r'qcom_scm_create_shm_bridge']),
 }
 for name,(start,end,patterns) in probes.items():
  text=subprocess.check_output(['llvm-objdump','-dr',f'--start-address={start}',f'--stop-address={end}',str(a.module)],text=True)
  norm=re.sub(r'[\t ]+',' ',text)
  for pattern in patterns:
   if not re.search(pattern,norm):raise ValueError(name+': '+pattern)
  (a.output/(name+'.asm')).write_text(text)
 with tempfile.TemporaryDirectory(prefix='bridge-abi-tamper-') as tmp:
  mutated=Path(tmp)/'qcom-scm.ko';raw=bytearray(a.module.read_bytes());raw[-1]^=1;mutated.write_bytes(raw)
  try:check(mutated)
  except ValueError:pass
  else:raise AssertionError('tampered module accepted')
 root=Path(__file__).resolve().parents[1]
 dtb=root/'Resources/DTBs/fuxi.dtb'
 dtb_sha=hashlib.sha256(dtb.read_bytes()).hexdigest()
 if dtb_sha!='0590a46ca03be8de4cdf273f4ba4bc884e41555e771f55d2601ba9df121b5d5c':raise ValueError('fixed reference DTB mismatch')
 result=subprocess.run(['dtc','-I','dtb','-O','dts',str(dtb)],capture_output=True,text=True,check=True)
 (a.output/'fuxi-reference.dts').write_text(result.stdout)
 (a.output/'dtc-warnings.log').write_text(result.stderr)
 nodes=re.findall(r'\bqtee_shmbridge\s*\{([^{}]*)\}',result.stdout)
 if len(nodes)!=1 or 'qcom,tee-shared-memory-bridge' not in nodes[0] or 'qcom,support-hypervisor' in nodes[0]:raise ValueError('fixed reference bridge node changed')
 with tempfile.TemporaryDirectory(prefix='bridge-rodata-') as tmp:
  rodata=Path(tmp)/'rodata'
  subprocess.run(['llvm-objcopy','--dump-section','.rodata='+str(rodata),str(a.module)],check=True)
  if rodata.read_bytes()[0xa91:0xaa9]!=b'qcom,support-hypervisor'+bytes([0]):raise ValueError('probe property name mismatch')
 paths=[Path(__file__),dtb,root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/DataReadOnly.c',root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/DataReadOnly.h']
 report=dict(result='passed',module_sha256=EXPECTED,modified_input_rejected=True,fnids=['42000c1c','42000c1e','42000c1d'],create=dict(scm_status='a0',service_result='low32(a1)',handle='a2',handle_bits=64),enable=dict(scm_status='a0',service_result='low32(a1)'),delete=dict(scm_status='a0',service_result_not_consumed=True),hlos=dict(vm_count=1,vmid=3,ns_perm=6,tz_perm=6,hyp_flags=0,create_arguments=['phys|6','phys|6','size|0x200','3']),
 reference_dtb=dict(path='Resources/DTBs/fuxi.dtb',sha256=dtb_sha,node=nodes[0].strip(),support_hypervisor=False,runtime_verified=False),
 pool=dict(default_bytes=4194304,ordinary_pages=True,dma_mapping=True,gen_pool=True,replicated_by_probe=False),
 scope='Fixed local module and repository reference DTB; no deployed DT/overlay or secure firmware equivalence, no error cause proof',sources={str(x.relative_to(root)):hashlib.sha256(x.read_bytes()).hexdigest() for x in paths})
 (a.output.parent/'m3-bridge-abi-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
