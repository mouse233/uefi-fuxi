#!/usr/bin/env python3
"""Audit fixed root/SMCI contract inputs; no device, SMC or vendor execution."""
import argparse,hashlib,json,re,shutil,subprocess,tempfile
from pathlib import Path
PINNED={
 'out/twrp-a17-analysis/ramdisk/vendor/lib/modules/1.1/qcom-scm.ko':'8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5',
 'out/twrp-a17-analysis/ramdisk/vendor/lib/modules/1.1/smcinvoke_dlkm.ko':'831a6db7570e66729db84cd0a7ddc63f8cdbc4b03fd250dee15b80b561969348',
 'out/m3-qsee-static-v1/sm8550-source/smcinvoke.c':'9907468f34d72323e4f9919f9a3019a8fef0e0e70cb629a83f8951c2288a6b7f',
 'out/m3-qsee-static-v1/sm8550-source/smcinvoke_kernel.c':'26b3716f8ec796cea6dace1b7adb9d8603ab1ac9eb51ecacac32c3ce8624272d',
 'out/m3-qsee-static-v1/sm8550-source/IClientEnv.h':'e4efdfa386aef8105af11eb133e7eeeccb219014db06f5b43f11fac2e2528d2a',
 'out/m3-qsee-static-v1/sm8550-source/smcinvoke_object.h':'46fcdb259980ea248a8adacae5008983628cc7018d2022ab76c7a11722b85aba',
}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def check_inputs(paths):
 for name,expected in PINNED.items():
  if sha(paths[name])!=expected:raise ValueError('SHA256 mismatch: '+name)
def require(pattern,text,label):
 if not re.search(pattern,text,re.S):raise ValueError(label+': '+pattern)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 root=Path(__file__).resolve().parents[1];out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 paths={name:root/name for name in PINNED};check_inputs(paths)
 src=(root/'out/m3-qsee-static-v1/sm8550-source/smcinvoke.c').read_text()
 kernel=(root/'out/m3-qsee-static-v1/sm8550-source/smcinvoke_kernel.c').read_text()
 interface=(root/'out/m3-qsee-static-v1/sm8550-source/IClientEnv.h').read_text()
 require(r'IClientEnv_OP_registerWithCredentials\s+5',interface,'register op')
 require(r'IClientEnv_registerWithCredentials\(rootObj,\s*Object_NULL,\s*clientEnvObj\)',kernel,'null credentials')
 require(r'ObjectCounts_pack\(0,\s*0,\s*1,\s*1\)',interface,'register counts')
 require(r'SMCINVOKE_TZ_ROOT_OBJ\s+1\b',src,'root handle')
 require(r'tz_args\s*=\s*\(union smcinvoke_tz_args \*\)\s*\(buf\s*\+\s*sizeof\(struct smcinvoke_msg_hdr\)\)',src,'descriptor base')
 require(r'tz_args \+= OBJECT_COUNTS_NUM_OI\(req->counts\);\s*FOR_ARGS\(i, req->counts, OO\)',src,'OO after OI')
 require(r'marshal_out_invoke_req\(in_buf,',src,'outputs in request buffer')
 require(r'if \(!ret && !is_inbound_req\(response_type\)\)',src,'terminal distinction')
 require(r'response_type == SMCINVOKE_RESULT_INBOUND_REQ_NEEDED.*?process_piggyback_cb_data\(out_buf, out_buf_len\)',src,'callback/piggyback')
 require(r'legacy_smc_call = of_property_read_bool.*?"qcom,support-legacy_smc".*?invoke_cmd = legacy_smc_call \? SMCINVOKE_INVOKE_CMD_LEGACY : SMCINVOKE_INVOKE_CMD',src,'entry selection')
 declarations=[]
 for kind,name in [('struct','smcinvoke_buf_hdr'),('union','smcinvoke_tz_args'),('struct','smcinvoke_msg_hdr')]:
  m=re.search(r'\b'+kind+r'\s+'+name+r'\s*\{[^{}]*\};',src)
  if not m:raise ValueError('wire declaration not found: '+name)
  declarations.append(m.group())
 code='#include <stdint.h>\n#include <stddef.h>\n'+'\n'.join(declarations)+"""
 _Static_assert(sizeof(struct smcinvoke_msg_hdr)==12,"header");
 _Static_assert(sizeof(union smcinvoke_tz_args)==8,"descriptor");
 _Static_assert(offsetof(struct smcinvoke_msg_hdr,counts)==8,"counts offset");
 struct root_wire { struct smcinvoke_msg_hdr hdr; union smcinvoke_tz_args args[2]; };
 _Static_assert(offsetof(struct root_wire,args[0])==12,"input object offset");
 _Static_assert(offsetof(struct root_wire,args[1])==20,"output object offset");
 _Static_assert(sizeof(struct root_wire)==28,"two descriptor end");
 """
 (out/'wire-layout-extracted.c').write_text(code)
 subprocess.run([shutil.which('clang') or 'clang','-std=c11','-Wall','-Wextra','-Werror','-fsyntax-only',str(out/'wire-layout-extracted.c')],check=True)
 modules=list(paths)[:2]
 probes={
 'root-null-register':(modules[1],0x1820,0x18dc,[r'mov w1, #0x5',r'mov w3, #0x1100',r'stp xzr, xzr, \[sp, #0x18\]',r'stp xzr, xzr, \[sp, #0x8\]',r'invoke_over_smcinvoke']),
 'object-descriptor':(modules[0],0x7270,0x733c,[r'movk x9, #0x2, lsl #32',r'mov w8, #0x224',r'mov w8, #0x32',r'mov w4, #0x2',r'ldr x8, \[sp, #0x10\]',r'str w8, \[x21\]',r'ldr x8, \[sp, #0x8\]',r'str x8, \[x20\]',r'ldr x8, \[sp, #0x18\]',r'str w8, \[x19\]']),
 'marshal-output-layout':(modules[1],0xc728,0xc780,[r'ubfx w8, w10, #8, #4',r'ubfx w10, w10, #12, #4',r'lsl w12, w10, #3',r'add w12, w12, #0xc',r'add x27, x12, #0xc']),
 'release':(modules[1],0x7c60,0x7cd0,[r'mov w10, #0xffff',r'mov w2, #0x1000',r'mov w5, #0x1000']),
 'cache-entries':(modules[1],0xc4a0,0xc620,[r'qtee_shmbridge_flush_shm_buf',r'qcom_scm_invoke_smc_legacy',r'qtee_shmbridge_inv_shm_buf',r'qcom_scm_invoke_callback_response',r'qcom_scm_invoke_smc']),
 'smccc-return':(modules[0],0x8940,0x8958,[r'ldp x8, x9, \[x29, #-0x50\]',r'ldur x10, \[x29, #-0x40\]',r'stp x8, x9, \[x11\]']),
 }
 for name,(module,start,stop,patterns) in probes.items():
  text=subprocess.check_output(['llvm-objdump','-dr',f'--start-address={start}',f'--stop-address={stop}',str(paths[module])],text=True)
  norm=re.sub(r'[\t ]+',' ',text)
  for pattern in patterns:require(pattern,norm,name)
  (out/(name+'.asm')).write_text(text)
 rejected=[]
 with tempfile.TemporaryDirectory(prefix='m3-root-pin-test-') as tmp:
  testpaths={}
  for i,(name,path) in enumerate(paths.items()):
   copy=Path(tmp)/str(i);shutil.copyfile(path,copy);testpaths[name]=copy
  for name,path in testpaths.items():
   original=path.read_bytes();modified=bytearray(original);modified[-1]^=1;path.write_bytes(modified)
   try:check_inputs(testpaths)
   except ValueError:rejected.append(name)
   else:raise AssertionError('modified input accepted: '+name)
   path.write_bytes(original)
 files=[Path(__file__),root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3SmciDiagnostic.inc',root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3BridgeDiagnostic.inc',root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/DataReadOnly.c',root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/DataReadOnly.h']
 report=dict(result='passed',input_sha256=PINNED,modified_inputs_rejected=rejected,
  contract=dict(root_handle=1,op=5,counts='1100',null_credentials=True,header_bytes=12,descriptor_bytes=8,oi_offset=12,oo_offset=20,wire_bytes=28,input_buffer_bytes=4096,output_buffer_bytes=4096,release_op='ffff',object_fnid='72000602',arginfo='224',scm_status='raw a0',response_type='a1',object_result='low32(a2)',data='low32(a3)'),
  production_acceptance='conservative subset: all-zero a0..a3, unchanged request header/reserved bytes, OO handle >1 without local bit, empty output page',
  not_general_abi_requirements=['all-zero response type/data','unchanged padding/tail','empty output page','remote handle >1'],
  source_reference=dict(repository='LineageOS/android_kernel_xiaomi_sm8550-modules',commit='9e8972287159837a256d0afcddc3f636f67ce8dd',exact_device_match=False),
  findings=['No root null/op/count/offset or cmd2 descriptor mismatch found in bounded audit','cmd2 reference branch omits explicit Linux cache sync; UEFI explicit cache operations are not runtime-equivalence proof','A valid callback/listener/piggyback result must stop this finite probe, not be labelled firmware ABI failure','Previous zero-VM transport never proved root invocation preconditions'],
  hardware_required=['actual HLOS root register return and accepted remote handle','release raw tuple and bridge deletion/page release','whether inbound callback or piggyback handling is required','current secure-world permission and cache/memory contract'],
  sources={str(x.relative_to(root)):sha(x) for x in files},
  scope='Fixed inputs, local instruction patterns and compiled extracted wire declarations only; no device, SMC, TA, key or decryption')
 (out/'root-contract-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
