#!/usr/bin/env python3
"""M2 draft fixtures independently encoded from Linux v5.15 disk-format fields."""
import argparse,hashlib,json,os,pathlib,platform,struct,subprocess,tempfile,zlib

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--edk2',type=pathlib.Path,required=True);p.add_argument('--report',type=pathlib.Path,required=True);a=p.parse_args()
    root=pathlib.Path(__file__).resolve().parents[1];src=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
    inc=[src,a.edk2/'MdePkg/Include',a.edk2/'MdePkg/Include'/('AArch64' if platform.machine()=='aarch64' else 'X64')]
    cc=['clang','-std=c11','-fshort-wchar','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',*[x for d in inc for x in ['-I',str(d)]]]
    err=lambda n:(1<<63)|n
    put=lambda b,o,v:struct.pack_into('<I',b,o,v)
    crc=lambda b:zlib.crc32(b,0xf2f52010^0xffffffff)^0xffffffff
    sb=bytearray(4096);s=memoryview(sb)[1024:]
    put(s,0,0xf2f52010);struct.pack_into('<HH',s,4,1,15)
    for off,val in [(8,12),(12,0),(16,12),(20,9),(24,1),(28,1),(44,20),(48,20),(52,2),(56,2),(60,2),(64,1),(68,13),(72,512),(76,512),(80,1536),(84,2560),(88,3584),(92,4096),(96,3),(100,1),(104,2)]:put(s,off,val)
    struct.pack_into('<Q',s,36,32768)
    def cp(version):
        b=bytearray(4096);struct.pack_into('<QQQ',b,0,version,6656,3)
        for off,val in [(132,1),(136,8),(140,3),(144,3),(148,1),(152,4),(156,64),(160,64),(164,4092)]:put(b,off,val)
        put(b,4092,crc(b[:4092]));return b
    def fixture():return {0:sb.copy(),1:sb.copy(),512:cp(1),519:cp(1),1024:cp(2),1031:cp(2)}
    cases=[('valid-newer-pack',fixture(),0,2,2560)]
    observed=fixture()
    for block in (0,1):put(observed[block],1024+2180,0x499)
    cases.append(('observed-metadata-499-bootstrap-only',observed,0,2,2560))
    def altered(name,block,offset,value,status,recrc=False):
        f=fixture();put(f[block],offset,value)
        if recrc:
            put(f[block],4092,crc(f[block][:4092]))
            if block==1024:f[1031]=f[block].copy()
        cases.append((name,f,status,1,2560))
    altered('bad-newer-crc-falls-back',1024,4092,0,0)
    altered('dirty-latest-does-not-use-old-clean',1024,132,0,err(3),True)
    altered('pack-tail-version-mismatch',1031,0,99,0,True)
    altered('pack-size-zero',1024,136,0,0,True)
    altered('oversized-bitmap',1024,160,4096,err(10),True)
    f=fixture();f[1][1024]^=1;cases.append(('superblocks-disagree',f,err(10),0,0))
    f=fixture();
    for block in (0,1):put(f[block],1024+2180,0x2000)
    cases.append(('unsupported-compression-feature',f,err(3),0,0))
    f=fixture();
    for block in (0,1):put(f[block],1024+1664,1)
    cases.append(('payload-extension-not-guessed',f,err(3),0,0))
    f=fixture();
    for block in (512,519,1024,1031):put(f[block],4092,0)
    cases.append(('both-checkpoints-corrupt',f,err(10),0,0))
    f=fixture();
    for block in (1024,1031):f[block][192+64]=0x80;put(f[block],4092,crc(f[block][:4092]))
    cases.append(('nat-version-bit-selects-second-copy',f,0,2,3072))
    f=fixture();f[512]=f[519]=cp((1<<64)-1);f[1024]=f[1031]=cp(0);cases.append(('checkpoint-version-wrap',f,0,2,2560))
    with tempfile.TemporaryDirectory(prefix='fuxi-f2fs-') as temp:
        t=pathlib.Path(temp);binary=t/'f2fs';proof=t/'proof'
        subprocess.run(cc+[str(root/'tools/tests/fuxi_read_proof_host.c'),str(src/'DataReadOnly.c'),'-o',str(proof)],check=True)
        subprocess.run([str(proof)],check=True)
        subprocess.run(cc+[str(root/'tools/tests/fuxi_f2fs_host.c'),str(src/'DataReadOnly.c'),str(src/'F2fsReadOnly.c'),'-o',str(binary)],check=True)
        for name,blocks,status,pack,nat in cases:
            image=t/'disk.img'
            with image.open('wb') as stream:
                stream.truncate(32768*4096)
                for block,data in blocks.items():stream.seek(block*4096);stream.write(data)
            subprocess.run([str(binary),str(image),hex(status),str(pack),str(nat),hex(struct.unpack_from('<I',blocks[0],1024+2180)[0])],check=True)
            print('PASS '+name,flush=True)
        with image.open('wb') as stream:
            stream.truncate(32768*4096)
            for block,data in fixture().items():stream.seek(block*4096);stream.write(data)
        subprocess.run([str(binary),str(image),hex(err(15)),'0','0','0'],
                       env={**os.environ,'F2R_FAIL_LBA':'1024'},check=True)
        print('PASS transport failure cannot authorize an older checkpoint',flush=True)
    files=[src/'F2fsReadOnly.c',src/'F2fsReadOnly.h',src/'DataReadOnly.c',src/'DataReadOnly.h',root/'tools/tests/fuxi_f2fs_host.c',root/'tools/tests/fuxi_read_proof_host.c',pathlib.Path(__file__).resolve()]
    a.report.parent.mkdir(parents=True,exist_ok=True)
    a.report.write_text(json.dumps(dict(result='passed',fixtures=len(cases)+1,scope='M2 draft bootstrap/NAT-read planning/dentry parser; no mount, journal resolution, decryption or hardware file read',sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}),indent=2)+'\n')

if __name__=='__main__':main()
