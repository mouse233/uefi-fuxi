#!/usr/bin/env python3
"""Collect non-secret Android version properties and vendor library digests; no writes to device."""
import argparse,datetime,hashlib,json,re,shutil,subprocess
from pathlib import Path

PROPS=('ro.product.device','ro.product.model','ro.build.fingerprint','ro.system.build.fingerprint',
 'ro.build.version.release','ro.build.version.security_patch','ro.vendor.build.security_patch',
 'ro.bootimage.build.version.security_patch','ro.build.version.incremental','ro.boot.slot_suffix')
LIBS=('/vendor/lib64/libqtikeymint.so','/vendor/lib64/libkeymasterdeviceutils.so',
 '/vendor/lib64/libqcbor.so','/vendor/lib64/libQSEEComAPI.so')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);p.add_argument('--adb',default='/opt/homebrew/bin/adb');p.add_argument('--root-hashes',action='store_true',help='use existing su only for vendor-library SHA256 reads');a=p.parse_args()
 if a.output.exists():raise SystemExit('refusing to overwrite existing capture')
 if not a.output.parent.is_dir():raise SystemExit('output parent must exist')
 ps=subprocess.run(['ps','-eo','pid=,args='],capture_output=True,text=True,check=True)
 for line in ps.stdout.splitlines():
  if any(x in line for x in ('test-usb-ram-full','usb-ram-send','boot-ram-window')):raise SystemExit('another device task is active')
 def adb(*args):
  c=subprocess.run([a.adb,'-s','fcde91e',*args],capture_output=True,text=True,timeout=20)
  if c.returncode:raise SystemExit('adb command failed: '+str(args)+' '+c.stderr.strip())
  return c.stdout.strip()
 if adb('get-state')!='device':raise SystemExit('fcde91e is not an authorized Android ADB device')
 props={key:adb('shell','getprop',key) for key in PROPS}
 if props['ro.product.device']!='fuxi':raise SystemExit('unexpected device product')
 digests={}
 for name in LIBS:
  value=adb('shell','/system/bin/su','-c','sha256sum '+name) if a.root_hashes else adb('shell','sha256sum',name)
  m=re.fullmatch(r'([0-9a-fA-F]{64})\s+(.+)',value)
  if not m or m.group(2)!=name:raise SystemExit('invalid digest response for '+name)
  digests[name]=m.group(1).lower()
 report={'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'serial':'fcde91e','props':props,'library_sha256':digests,
 'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'root_hashes':a.root_hashes,'scope':'Read-only Android properties and library digests; no partition, key, secret, reboot or device file writes.'}
 with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 print('Captured non-secret version properties and four vendor library digests:',a.output)
if __name__=='__main__':main()
