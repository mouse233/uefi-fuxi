#!/usr/bin/env python3
"""Read independent mkfs/sload images. Never mounts or opens a block device."""
import argparse,hashlib,json,pathlib,platform,stat,subprocess,tempfile

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--edk2',type=pathlib.Path,required=True)
    p.add_argument('--tools',type=pathlib.Path,required=True,help='directory containing mkfs.f2fs and sload.f2fs')
    p.add_argument('--report',type=pathlib.Path,required=True);a=p.parse_args()
    r=pathlib.Path(__file__).resolve().parents[1];src=r/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
    tools={name:a.tools/name for name in ['mkfs.f2fs','sload.f2fs']}
    for path in tools.values():assert path.is_file()
    cc=['clang','-std=c11','-fshort-wchar','-Wall','-Wextra','-Werror','-fsanitize=address,undefined']
    for directory in [src,a.edk2/'MdePkg/Include',a.edk2/'MdePkg/Include'/('AArch64' if platform.machine()=='aarch64' else 'X64')]:cc+=['-I',str(directory)]
    commands=[];tests=[]
    with tempfile.TemporaryDirectory(prefix='fuxi-m2-tools-') as tmp:
        t=pathlib.Path(tmp);source=t/'source';(source/'dir').mkdir(parents=True)
        payloads={'test':bytes((i*29+7)%256 for i in range(8193)),'small':b'M2 format version\n','large':bytes(range(256))*(5*1024*1024//256)+b'last bytes'}
        for name,data in payloads.items():(source/'dir'/name).write_bytes(data)
        image=t/'metadata.img'
        with image.open('xb') as stream:stream.truncate(128*1024**2)
        assert stat.S_ISREG(image.stat().st_mode) and image.resolve().parent==t.resolve()
        for cmd in [[str(tools['mkfs.f2fs']),'-t','0','-O','encrypt,extra_attr,project_quota,verity',str(image)],
                    [str(tools['sload.f2fs']),'-f',str(source),str(image)]]:
            result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            commands.append(dict(command=cmd,exit_code=result.returncode,output=result.stdout))
            if result.returncode:raise RuntimeError(result.stdout)
        binary=t/'reader'
        subprocess.run(cc+[str(r/'tools/tests/fuxi_f2fs_files_host.c'),str(src/'DataReadOnly.c'),str(src/'F2fsReadOnly.c'),str(src/'F2fsFiles.c'),'-o',str(binary)],check=True)
        # Full small/multiblock files plus a far read requiring a direct node.
        for name,offset,length in [('test',0,8193),('small',0,len(payloads['small'])),('large',5*1024*1024-13,23)]:
            expected=t/'expected.bin';want=payloads[name][offset:offset+length];expected.write_bytes(want)
            subprocess.run([str(binary),str(image),'/dir/'+name,'0','0',str(offset),'0',str(expected),'0'],check=True)
            tests.append(dict(path='/dir/'+name,file_bytes=len(payloads[name]),offset=offset,read_bytes=length,read_sha256=hashlib.sha256(want).hexdigest()))
        with image.open('rb') as stream:stream.seek(1024+2180);feature=int.from_bytes(stream.read(4),'little')
        assert feature==0x499
    sources=[src/'F2fsFiles.c',src/'F2fsReadOnly.c',src/'F2fsReadOnly.h',src/'DataReadOnly.c',r/'tools/tests/fuxi_f2fs_files_host.c',pathlib.Path(__file__).resolve()]
    a.report.parent.mkdir(parents=True,exist_ok=True)
    a.report.write_text(json.dumps(dict(result='passed',feature=hex(feature),fixtures=len(tests),tests=tests,tools={name:dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for name,path in tools.items()},commands=commands,sources={str(path.relative_to(r)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}),indent=2)+'\n')
    print('PASS independent mkfs/sload feature=0x499: full small/multiblock files and direct-node far read')

if __name__=='__main__':main()
