#!/usr/bin/env python3
"""Bind actual ROOTCTX objects/image and prove recovery callers stay disabled."""
import argparse,hashlib,json,re,shutil,subprocess
from pathlib import Path
from m3_root_trust_binding import load_binding
from m3_configure_binding import load_configure_evidence
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[1];out=a.output.resolve();h=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
nm=shutil.which('llvm-nm') or shutil.which('llvm-nm-18');dump=shutil.which('llvm-objdump') or shutil.which('llvm-objdump-18')
assert nm and dump
c=json.loads((out/'candidate.json').read_text());defs=json.loads((out/'board-effective.json').read_text())['firmware']['defines']
assert c['m3_root_trust_query'] and not c['m3_recover_key'] and not c['m3_reads_recovery_inputs']
for k in ('FUXI_M3_ROOT_TRUST_QUERY','FUXI_M3_SMCI_VERSION','FUXI_M3_SMCI_RESUME','FUXI_UFS_DIAGNOSTIC_PARK'):assert defs[k]=='1'
for k in ('FUXI_M3_KEY_RECOVERY','FUXI_M3_SECRET_EXCHANGE','FUXI_M3_BINDING_NONE','FUXI_M3_CONFIGURE_RECOVERY','FUXI_M3_SMCI_SETVER','FUXI_M3_SMCI_DATE','FUXI_M3_METADATA_KEY','FUXI_USB_RAM_SYSTEM_HANDOFF'):assert defs[k]=='0'
assert c['m3_root_trust_binding']==load_binding(out/'root-trust-evidence.json')
assert c['m3_configure_binding']==load_configure_evidence(out/'configure-evidence.json')
src=root/'Build/fuxiPkg/DEBUG_CLANGPDB/AARCH64/fuxiPkg/Drivers/FuxiNativeUfsDxe/FuxiNativeUfsDxe/OUTPUT'
archive=out/'live-objects';archive.mkdir(exist_ok=True)
objects={}
for name in ('FuxiNativeUfsDxe.obj','FuxiNativeUfsDxe.map'):
 dst=archive/name;shutil.copyfile(src/name,dst);objects[name]=h(dst)
syms=subprocess.check_output([nm,str(archive/'FuxiNativeUfsDxe.obj')],text=True)
imports=set(re.findall(r'\bU (\S+)$',syms,re.M))
assert not imports.intersection({'FkrPrepare','FkrRecoverExisting','FkrGetRecovered','FkrReadF2fsFile','FseExchange','FseInitialize','FsePermitCleanup'})
efi=(out/'FuxiNativeUfsDxe.efi').read_bytes()
marker='FUXIM3 ROOTCTX boot-patch=%u; structural observation only, MAC unverified'.encode('utf-16-le')
assert marker in efi
assert 'FUXIM3 RECOVERY prepared=%r binding=%08x; no material output'.encode('utf-16-le') not in efi
assert bytes.fromhex('16210000'+c['m3_configure_binding']['configure_cbor_hex']) in efi
assert bytes.fromhex('1f310000a10450')+b'FUXI-ROT-PROBE01' in efi
assert len(re.findall(r'\bsmc\s',subprocess.check_output([dump,'-d',str(out/'FuxiNativeUfsDxe.efi')],text=True)))==1
modules=[]
for mode,query in (('modules-no-smc',False),('modules-scm-query',True)):
 base=out/mode;r=json.loads((base/'build.json').read_text())
 assert r['exit_code']==0 and r['scm_queries_enabled']==query and not r['secret_exchange_compiled']
 for n,v in r['sources'].items():assert h(root/n)==v,n
 for name,row in r['modules'].items():
  f=base/(name+'.efi');assert h(f)==row['sha256'] and marker not in f.read_bytes()
  smc=len(re.findall(r'\bsmc\s',subprocess.check_output([dump,'-d',str(f)],text=True)))
  assert smc==int(query and name=='FuxiDataProbeDxe')
  modules.append(dict(mode=mode,module=name,sha256=h(f),smc=smc))
report=dict(result='passed',image_sha256=h(out/'Mu-fuxi-ufs-m1.img'),objects=objects,native_imports=sorted(imports),modules=modules,recovery_callers_absent=True,sources={str(Path(__file__).relative_to(root)):h(Path(__file__))},scope='Actual built objects/linked EFI/gates; not secure-world MAC or boot proof.')
(out/'root-context-object-tests.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS ROOTCTX objects/EFI and default/query gates; recovery callers absent')
