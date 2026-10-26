#!/usr/bin/env python3
"""Compile production EP0/stop code with delivered macro variants and sanitizers."""
import argparse, hashlib, json, pathlib, platform, subprocess, tempfile

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--edk2',type=pathlib.Path,required=True)
    p.add_argument('--report-dir',type=pathlib.Path,required=True)
    a=p.parse_args(); root=pathlib.Path(__file__).resolve().parents[1]
    src=root/'Silicon/Samsung/SamsungPkg/Drivers/UsbfnDwc3Dxe'
    inc=[src,root/'Silicon/Samsung/SamsungPkg/Include',a.edk2/'MdePkg/Include',
         a.edk2/'MdePkg/Include'/('AArch64' if platform.machine()=='aarch64' else 'X64')]
    base=['clang','-std=c11','-fshort-wchar','-Wall','-Wextra','-Werror',
          '-fsanitize=address,undefined',*[x for d in inc for x in ['-I',str(d)]]]
    variants=[['-DMDEPKG_NDEBUG'],['-DFUXI_USB_DMA32=1','-DFUXI_USB_EP0_TRACE=0'],
              ['-DFUXI_USB_DMA32=1','-DFUXI_USB_EP0_TRACE=1'],
              ['-DFUXI_USB_DMA32=1','-DFUXI_USB_EP0_TRACE=1','-DFUXI_USB_EP0_FORCERM=0']]
    a.report_dir.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='fuxi-usb-state-') as temp:
        for kind in ['ep0','stop']:
            fixture=root/f'tools/tests/dwc3_{kind}_host.c'; runs=[]
            for i,flags in enumerate(variants if kind=='ep0' else variants[:1]):
                binary=pathlib.Path(temp)/f'{kind}-{i}'
                command=base+flags+[str(fixture),'-o',str(binary)]
                subprocess.run(command,check=True)
                result=subprocess.run([str(binary)],capture_output=True,text=True,check=True)
                passed=[s[5:] for s in result.stdout.splitlines() if s.startswith('PASS ')]
                assert len(passed)>=(22 if kind=='ep0' else 9)
                runs.append(dict(defines=flags,command=command,passed=passed))
                print(f'PASS {kind} variant {i}: {len(passed)} cases',flush=True)
            paths=[src/'Dwc3Endpoint.c',src/'Dwc3Stop.c',src/'UsbfnDwc3Dxe.h',
                   root/'Silicon/Samsung/SamsungPkg/Include/Device/Dwc3.h',fixture,pathlib.Path(__file__).resolve()]
            report=dict(cases=len(runs[0]['passed']),runs=runs,
                        scope='production command/EP0 plus integrated stop timeout; simulated MMIO, no hardware claims',
                        sources={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in paths})
            (a.report_dir/f'{kind}-host.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__': main()
