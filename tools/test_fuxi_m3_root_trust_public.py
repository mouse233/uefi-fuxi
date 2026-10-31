#!/usr/bin/env python3
"""Narrow production COSE parser vs independent shape model; synthetic only."""
import argparse,hashlib,json,platform,random,shutil,subprocess,tempfile
from pathlib import Path
from collect_fuxi_m3_blob_public import Reader

def head(m,n):
 for limit,ai,w in ((24,0,0),(256,24,1),(65536,25,2),(1<<32,26,4),(1<<64,27,8)):
  if n<limit:return bytes([(m<<5)|(n if not w else ai)])+(n.to_bytes(w,'big') if w else b'')
 raise ValueError('bound')
def bs(b):return head(2,len(b))+b
def fixture(value=202610,*,locked=True,state=0,mac=bytes([0x5d])*32,protected=b'\xa1\x01\x05',unprotected=b'\xa0',tag=17,rtag=40001):
 payload=head(6,rtag)+b'\x85'+bs(bytes([0x31])*32)+(b'\xf5' if locked else b'\xf4')+head(0,state)+bs(bytes([0x22])*32)+head(0,value)
 cose=head(6,tag)+b'\x84'+bs(protected)+unprotected+bs(payload)+bs(mac)
 return b'\xa1'+head(0,36)+bs(cose)
def model(data):
 if not 0<len(data)<=256:return 'rejected'
 def reader(data):return Reader(lambda at,n:data[at:at+n],len(data))
 def need(r,m,n):
  if r.head()!=(m,n):raise ValueError('shape')
 def bstr(r):
  m,n=r.head()
  if m!=2:raise ValueError('bstr')
  return bytes(r.take(n))
 try:
  r=reader(data);need(r,5,1);need(r,0,36);c=reader(bstr(r))
  if r.at!=r.limit:raise ValueError('tail')
  need(c,6,17);need(c,4,4)
  if bstr(c)!=b'\xa1\x01\x05':raise ValueError('protected')
  need(c,5,0);p=reader(bstr(c));need(p,6,40001);need(p,4,5)
  if len(bstr(p))!=32 or p.head() not in ((7,20),(7,21)):raise ValueError('public fields')
  if p.uint()>3 or len(bstr(p))!=32:raise ValueError('state')
  value=p.uint()
  if value>0xffffffff or p.at!=p.limit or len(bstr(c))!=32 or c.at!=c.limit:raise ValueError('end')
  return str(value)
 except ValueError:return 'rejected'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--edk2',type=Path,required=True);p.add_argument('--vectors',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
 if platform.system()!='Linux':p.error('run in build container')
 root=Path(__file__).resolve().parents[1];native=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe';test=root/'tools/tests/m3_root_trust_public_host.c'
 vectors=json.loads(a.vectors.read_text());assert len(vectors)==11
 cases=[]
 for row in vectors:
  assert row['synthetic'] and not row['authenticated']
  raw=bytes.fromhex(row['response_hex']);assert raw==fixture(row['boot']);cases.append(raw)
 for v in (0,23,24,255,256,65535,65536,202607,202610,20261005,0xffffffff,1<<32):
  for locked in (False,True):
   for state in (0,1,2,3,4):cases.append(fixture(v,locked=locked,state=state))
 base=fixture()
 cases += [base[:n] for n in range(len(base))]
 cases += [base+b'\0',b'\xa2'+base[1:]+b'\0\0',fixture(tag=18),fixture(rtag=40000),fixture(protected=b'\xa1\x01\x06'),fixture(unprotected=b'\xa1\x01\x05')]
 cases += [fixture(mac=bytes(n)) for n in (0,1,31,33,64,200)]
 rng=random.Random(311)
 for _ in range(900):
  raw=bytearray(base)
  for _ in range(rng.randint(1,4)):raw[rng.randrange(len(raw))]=rng.randrange(256)
  cases.append(bytes(raw))
 want=[model(c) for c in cases]
 with tempfile.TemporaryDirectory(prefix='rootctx-public-') as tmp:
  exe=str(Path(tmp)/'test')
  subprocess.run([shutil.which('clang'),'-std=c11','-Wall','-Wextra','-Werror','-Wno-macro-redefined','-fshort-wchar','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(a.edk2/'MdePkg/Include'),'-I'+str(a.edk2/'MdePkg/Include/AArch64'),'-I'+str(native),str(test),'-o',exe],check=True)
  wire=b''.join(str(len(c)).encode()+b'\n'+c for c in cases)
  got=subprocess.check_output([exe],input=wire).decode().splitlines()
 assert len(got)==len(want)
 for i,(x,y) in enumerate(zip(got,want)):assert x==y,f'synthetic parser case {i}'
 files=[Path(__file__),test,native/'M3RootTrustPublic.h',root/'tools/collect_fuxi_m3_blob_public.py']
 report=dict(result='passed',cases=len(cases),accepted=sum(x!='rejected' for x in want),codec_vectors=11,vectors_sha256=hashlib.sha256(a.vectors.read_bytes()).hexdigest(),sanitizers=['address','undefined'],tail_guard='PROT_NONE',scope='Synthetic COSE shape/boot integer only. MAC/data values unverified, opaque fields not exported.',sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(cases),'ROOTCTX parser cases, 11 real-code synthetic codec vectors')
if __name__=='__main__':main()
