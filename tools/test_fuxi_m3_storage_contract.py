#!/usr/bin/env python3
"""No-secret synthetic response bounds and fixed input tamper refusal."""
import argparse,contextlib,hashlib,io,json,struct,tempfile
from pathlib import Path
from audit_fuxi_m3_storage_contract import EXPECTED,check_inputs,validate_synthetic_export_envelope
def envelope(body,status=0,size=None):return struct.pack('<II',status,len(body) if size is None else size)+body
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--ramdisk',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
 vectors=0
 for n in (1,23,24,32,33,64,128,208,1000,4096,40960-16):
  header=bytes([0x40+n]) if n<24 else b'\x58'+bytes([n]) if n<256 else b'\x59'+n.to_bytes(2,'big')
  body=b'\xa1\x18\x24'+header+b'\xa5'*n
  captured=io.StringIO()
  with contextlib.redirect_stdout(captured):result=validate_synthetic_export_envelope(envelope(body))
  assert result=={'opaque_bytes':n,'representation':'opaque-storage-export','hardware_verified':False}
  assert captured.getvalue()=='' and not any(type(v) is bytes for v in result.values());vectors+=1
 good=envelope(b'\xa1\x18\x24\x41\xa5')
 bad=[b'',good[:7],envelope(b'\xa1\x18\x24\x41\xa5',status=1),envelope(b'\xa1\x18\x24\x41\xa5',size=4),
  envelope(b'\xa1\x17\x41\xa5'),envelope(b'\xa2\x18\x24\x41\xa5'),envelope(b'\xbf\x18\x24\x41\xa5\xff'),
  envelope(b'\xa1\x18\x24\x40'),envelope(b'\xa1\x18\x24\x61\x61'),envelope(b'\xa1\x18\x24\x42\xa5'),
  envelope(b'\xa1\x18\x24\x41\xa5\x00'),envelope(b'\xa1\x18\x24\x5f\x41\xa5\xff'),
  envelope(b'\xa1\x18\x24\x5a\xff\xff\xff\xff'),envelope(b'\xa1\x18\x24\x59'),b'\x00'*40961]
 for value in bad:
  try:validate_synthetic_export_envelope(value)
  except ValueError:pass
  else:raise AssertionError('invalid subset accepted')
  vectors+=1
 check_inputs(a.ramdisk);rejected=[]
 with tempfile.TemporaryDirectory(prefix='m3-storage-tamper-') as tmp:
  base=Path(tmp)
  for name in EXPECTED:
   dest=base/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((a.ramdisk/name).read_bytes())
  for name in EXPECTED:
   dest=base/name;raw=dest.read_bytes();bad=bytearray(raw);bad[-1]^=1;dest.write_bytes(bad)
   try:check_inputs(base)
   except ValueError:rejected.append(name)
   else:raise AssertionError('tampered file accepted')
   dest.write_bytes(raw)
 root=Path(__file__).resolve().parents[1]
 paths=[Path(__file__),root/'tools/audit_fuxi_m3_storage_contract.py']
 report=dict(result='passed',synthetic_vectors=vectors,modified_inputs_rejected=rejected,secret_output='none; model returns length and fixed metadata only',scope='No hardware or vendor-code execution, no real key/blob input',sources={str(x.relative_to(root)):hashlib.sha256(x.read_bytes()).hexdigest() for x in paths})
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
