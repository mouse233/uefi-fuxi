#!/usr/bin/env python3
"""ASan/UBSan actual backend/core, synthetic transport and pinned vendor vectors."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from audit_fuxi_m3_ta_contract import build_send_request


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--edk2',type=Path,required=True)
    p.add_argument('--vendor-vectors',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    a=p.parse_args(); root=Path(__file__).resolve().parents[1]
    a.report.parent.mkdir(parents=True,exist_ok=True)
    a.report.write_text('{"result":"running"}\n')
    vendor=json.loads((a.vendor_vectors/'audit.json').read_text())
    oracle=root/'tools/audit_fuxi_m3_recovery_wire.py'
    assert vendor['result']=='passed' and vendor['source_sha256']==hashlib.sha256(oracle.read_bytes()).hexdigest()
    src=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
    sources=[src/n for n in ('M3KeyMintBackend.c','M3KeyRecovery.c','M3Secdiscardable.c')]
    test=root/'tools/tests/m3_keymint_backend_host.c'
    with tempfile.TemporaryDirectory(prefix='m3-backend-') as tmp:
        binary=Path(tmp)/'test'
        command=['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-macro-redefined','-fshort-wchar','-g','-O1',
                 '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                 '-I'+str(a.edk2/'MdePkg/Include'),'-I'+str(a.edk2/'MdePkg/Include/AArch64'),
                 '-I'+str(src),str(test),*(str(s) for s in sources),'-o',str(binary)]
        subprocess.run(command,check=True)
        result=subprocess.check_output([str(binary)],text=True)
        print(result.strip())
        count=0
        for vector in vendor['vectors']:
            raw=(a.vendor_vectors/vector['file']).read_bytes()
            assert hashlib.sha256(raw).hexdigest()==vector['sha256']
            actual=subprocess.check_output([str(binary),'encode',vector['kind'],str(vector['blob_bytes']),str(vector['handle'])])
            assert actual==raw,vector['file'];count+=1
        for vector in vendor['responses']:
            file=a.vendor_vectors/vector['file']
            assert hashlib.sha256(file.read_bytes()).hexdigest()==vector['sha256']
            subprocess.run([str(binary),'decode',vector['kind'],str(file)],check=True)
        frames=0
        for vector in vendor['vectors']:
            if vector['kind']!='begin':continue
            request=(0x310f).to_bytes(4,'little')+(a.vendor_vectors/vector['file']).read_bytes()
            model=build_send_request(4,request,0xa000-((len(request)+3)//4*4),True)
            actual=subprocess.check_output([str(binary),'frame',str(vector['blob_bytes'])])
            assert actual==model['buffer'],vector['file'];frames+=1
    bound=[*sources,test,oracle,Path(__file__),root/'tools/audit_fuxi_m3_ta_contract.py',src/'M3KeyMintBackend.h',src/'M3KeyRecovery.h']
    report=dict(result='passed',host_output=result.strip(),vendor_request_matches=count,vendor_response_matches=len(vendor['responses']),independent_smci_frames=frames,sanitizers=['address','undefined'],
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in bound},
                vendor_report_sha256=hashlib.sha256((a.vendor_vectors/'audit.json').read_bytes()).hexdigest(),
                scope='Production backend/core on synthetic transport; no live SMC, TA, actual key or GCM authentication proof. Prior recovery-core OpenSSL tests remain separate.')
    a.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(result='passed',vendor_request_matches=count)))


if __name__=='__main__':main()
