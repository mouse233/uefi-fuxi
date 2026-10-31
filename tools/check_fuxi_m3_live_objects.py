#!/usr/bin/env python3
"""Bind actual AARCH64 recovery references/imports and off-mode modules."""
import argparse, hashlib, json, re, shutil, subprocess
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    root=Path(__file__).resolve().parents[1];out=a.output.resolve()
    h=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
    nm=shutil.which('llvm-nm') or shutil.which('llvm-nm-18') or '/opt/homebrew/opt/llvm/bin/llvm-nm'
    dump=shutil.which('llvm-objdump') or shutil.which('llvm-objdump-18') or '/opt/homebrew/opt/llvm/bin/llvm-objdump'
    rows=[]
    for mode,query in [('modules-no-smc',False),('modules-scm-query',True)]:
        base=out/mode;r=json.loads((base/'build.json').read_text())
        assert r['exit_code']==0 and r['scm_queries_enabled']==query and not r['secret_exchange_compiled']
        for name,digest in r['sources'].items():assert h(root/name)==digest,name
        for name,module in r['modules'].items():
            f=base/(name+'.efi');assert h(f)==module['sha256']
            asm=subprocess.check_output([dump,'-d',str(f)],text=True)
            count=len(re.findall(r'\bsmc\s',asm));assert count==int(query and name=='FuxiDataProbeDxe')
            rows.append(dict(mode=mode,module=name,sha256=h(f),smc=count))
            assert 'FUXIM3 CONFIGURE Success; continue existing-key recovery'.encode('utf-16-le') not in f.read_bytes()
            assert 'FUXIM3 CHARACTERISTICS begin once: read-only blob version fields'.encode('utf-16-le') not in f.read_bytes()
        syms=subprocess.check_output([nm,str(base/'M3SecretExchange.obj')],text=True)
        assert not re.findall(r'\bU (\S+)$',syms,re.M)
    src=root/'Build/fuxiPkg/DEBUG_CLANGPDB/AARCH64/fuxiPkg/Drivers/FuxiNativeUfsDxe/FuxiNativeUfsDxe/OUTPUT'
    archive=out/'live-objects';archive.mkdir(exist_ok=True);objects={}
    for name in ('M3KeyRecovery','M3Secdiscardable','M3KeyRecoveryF2fs','M3KeyMintBackend','M3SecretExchange'):
        target=archive/(name+'.obj');shutil.copyfile(src/'FuxiDataProbeDxe'/target.name,target)
        syms=subprocess.check_output([nm,str(target)],text=True);imports=set(re.findall(r'\bU (\S+)$',syms,re.M))
        if name=='M3SecretExchange':assert imports=={'ArmCallSmc','WriteBackInvalidateDataCacheRange','InvalidateDataCacheRange'}
        objects[name]=dict(sha256=h(target),imports=sorted(imports))
    nt=archive/'FuxiNativeUfsDxe.obj';shutil.copyfile(src/nt.name,nt)
    syms=subprocess.check_output([nm,str(nt)],text=True)
    for name in ('FseExchange','FseInitialize','FsePermitCleanup','FkrPrepare','FkrRecoverExisting','FkrGetRecovered','FkrReset'):
        assert re.search(r'\bU '+name+r'$',syms,re.M),name
    mf=archive/'FuxiNativeUfsDxe.map';shutil.copyfile(src/mf.name,mf)
    # Prepare/RecoverExisting are LTO-inlined, so verify their object references
    # above and preserved exchange/reader/reset/state symbols in the linked map.
    for name in ('FseExchange','FkrReset','FkrReadF2fsFile','mRecoveryAttempted','mRecoveryWork'):assert name in mf.read_text(),name
    board=out/'board-effective.json';defs=json.loads(board.read_text())['firmware']['defines']
    assert all(defs[n]=='1' for n in ('FUXI_M3_KEY_RECOVERY','FUXI_M3_SECRET_EXCHANGE','FUXI_M3_BINDING_NONE'))
    assert defs['FUXI_M3_BINDING_TAG']=='0xf2e5a8b4'
    assert all(defs[n]=='0' for n in ('FUXI_M3_METADATA_KEY','FUXI_M3_SMCI_SETVER','FUXI_M3_SMCI_DATE','FUXI_USB_RAM_SYSTEM_HANDOFF'))
    candidate=json.loads((out/'candidate.json').read_text())
    assert defs['FUXI_M3_CONFIGURE_RECOVERY']==str(int(candidate.get('m3_configure_recovery',False)))
    assert defs['FUXI_M3_RECOVERY_PUBLIC']==str(int(candidate.get('m3_recovery_public',False)))
    configure=None
    if candidate.get('m3_configure_recovery'):
        from m3_configure_binding import load_configure_evidence
        configure=load_configure_evidence(out/'configure-evidence.json',candidate['m3_configure_binding']['os_patch'])
        assert defs['FUXI_M3_CONFIGURE_TAG']==configure['tag'] and candidate['m3_configure_binding']==configure
        assert defs['FUXI_M3_CONFIGURE_PATCH']==str(configure['os_patch'])
        packet=bytes.fromhex('16210000'+configure['configure_cbor_hex'])
        assert packet in (out/'FuxiNativeUfsDxe.efi').read_bytes(), 'compiled configure request mismatch'
    assert defs['FUXI_M3_CHARACTERISTICS_PROBE']==str(int(candidate.get('m3_characteristics_probe',False)))
    probe=None
    if candidate.get('m3_characteristics_probe'):
        assert candidate.get('m3_configure_recovery') and candidate['m3_smci_ops'][5]=='characteristics-probe'
        backend=(root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/M3KeyMintBackend.c').read_text()
        assert 'Put32(C->Request,0x2109)' in backend
        assert 'Head(&W,5,2); BytesPair(&W,23,Blob,BlobBytes); BytesPair(&W,29,Inner,IW.N);' in backend
        assert 'BytesPair(&IW,0x90000259,AppId,AppIdBytes);' in backend
        probe=dict(command='0x2109',request='map{23:blob}',sources={str(Path(__file__).relative_to(root)):h(Path(__file__))})
    image=out/'Mu-fuxi-ufs-m1.img';assert h(image)==json.loads((out/'candidate.json').read_text())['sha256']
    report=dict(result='passed',image_sha256=h(image),modules=rows,objects=objects,native_object_sha256=h(nt),linked_map_sha256=h(mf),board_sha256=h(board),configure_binding=configure,characteristics_probe=probe,sources={str(Path(__file__).relative_to(root)):h(Path(__file__))},scope='AARCH64 objects and linked map only. No live authentication proof.')
    (out/'live-object-checks.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS live AARCH64 references, exchange imports and off-mode gates')
if __name__=='__main__':main()
