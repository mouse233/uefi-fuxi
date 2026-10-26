#!/usr/bin/env python3
"""Independent disk-format fixtures exercising production M2 file APIs."""
import argparse,copy,hashlib,json,os,pathlib,platform,struct,subprocess,tempfile,zlib

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--edk2',type=pathlib.Path,required=True);p.add_argument('--report',type=pathlib.Path,required=True);a=p.parse_args()
    root=pathlib.Path(__file__).resolve().parents[1];src=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
    def u16(b,o,v):struct.pack_into('<H',b,o,v)
    def u32(b,o,v):struct.pack_into('<I',b,o,v)
    def u64(b,o,v):struct.pack_into('<Q',b,o,v)
    def crc(b):return zlib.crc32(b,0xf2f52010^0xffffffff)^0xffffffff
    def footer(b,nid,ino,offset=0):u32(b,4072,nid);u32(b,4076,ino);u32(b,4080,offset<<3)
    def inode(nid,mode,size,inline=0x20):
        b=bytearray(4096);u16(b,0,mode);b[3]=inline;u32(b,12,1);u64(b,16,size)
        if inline&0x20:u16(b,360,24)
        footer(b,nid,nid);return b
    def entries(items,size=4096,inline=False):
        b=bytearray(size);slots=(size*8)//153 if inline else 214;off=size-slots*19 if inline else 30;pos=0
        for name,nid,kind in items:
            name=name.encode();used=(len(name)+7)//8
            for j in range(used):b[(pos+j)//8]|=1<<((pos+j)%8)
            u32(b,off+pos*11+4,nid);u16(b,off+pos*11+8,len(name));b[off+pos*11+10]=kind
            b[off+slots*11+pos*8:off+slots*11+pos*8+len(name)]=name;pos+=used
        return b
    def nat(b,nid,owner,address):
        off=(nid%455)*9;b[off]=1;u32(b,off+1,owner);u32(b,off+5,address)
    def cp(version,flags=1,total=8):
        b=bytearray(4096);u64(b,0,version)
        for off,val in [(132,flags),(136,total),(140,1),(156,64),(160,64),(164,4092)]:u32(b,off,val)
        u32(b,4092,crc(b[:4092]));return b
    data=bytes((i*37+11)%256 for i in range(5000))
    def fixture():
        sb=bytearray(4096);u32(sb,1024,0xf2f52010);u16(sb,1028,1)
        for off,val in [(8,12),(16,12),(20,9),(48,20),(52,2),(56,2),(60,2),(64,1),(68,13),(72,512),(76,512),(80,1536),(84,2560),(88,3584),(92,4096),(96,3),(100,1),(104,2),(2180,0x499)]:u32(sb,1024+off,val)
        u64(sb,1060,32768)
        f={0:sb,1:sb.copy(),512:cp(1),519:cp(1),1024:cp(2),1031:cp(2),1025:bytearray(4096),2560:bytearray(4096)}
        # Root uses block dentries, /dir uses inline dentries with extra attrs.
        f[4100]=inode(3,0x41ed,4096);u32(f[4100],384,4500)
        cap=(923-6-1)*4;f[4101]=inode(4,0x41ed,cap,0x24)
        f[4101][388:388+cap]=entries([('.',4,2),('..',3,2),('test',5,1)],cap,True)
        f[4500]=entries([('.',3,2),('..',3,2),('dir',4,2)])
        f[4102]=inode(5,0x81a4,len(data));u32(f[4102],384,4501);u32(f[4102],388,4502)
        f[4501]=bytearray(data[:4096]);f[4502]=bytearray(data[4096:]+bytes(8192-len(data)))
        nat(f[2560],3,3,4100);nat(f[2560],4,4,4101)
        nat(f[2560],5,5,4199) # deliberately stale; journal must override
        u16(f[1025],3584,1);u32(f[1025],3586,5);f[1025][3590]=2;u32(f[1025],3591,5);u32(f[1025],3595,4102)
        return f
    cases=[]
    def add(name,f=None,path='/dir/test',prep=0,lookup=0,offset=0,read=0,want=data,fail=None,listing=True):
        cases.append(dict(name=name,f=f if f is not None else fixture(),path=path,prep=prep,lookup=lookup,offset=offset,read=read,want=want,fail=fail,listing=listing))
    err=lambda n:(1<<63)|n
    add('journal-overrides-stale-table-and-whole-file')
    for flags in (0x41,0x281):
        f=fixture();f[1024]=f[1031]=cp(2,flags);add('clean-recovery-flags-'+hex(flags),f)
    add('unaligned-read-crosses-data-block',offset=4090,want=data[4090:4110])
    f=fixture();u32(f[4102],388,0);add('sparse-hole-is-zero',f,want=data[:4096]+bytes(904))
    f=fixture();f[4102]=inode(5,0x81a4,19,0x2b);f[4102][388:407]=b'inline metadata v1\n';add('inline-file-extra-attrs-inline-xattrs',f,want=b'inline metadata v1\n')
    f=fixture();f[4102][3]=0;u32(f[4102],360,4501);u32(f[4102],364,4502);add('inode-without-extra-attributes',f)
    # Walk both direct nodes, both indirect nodes and a nonzero double-indirect branch.
    for name,logical,chain in [
        ('first-direct-node',917,[(6,1,0)]),('second-direct-node',917+1018,[(6,2,0)]),
        ('first-indirect-node',917+2036,[(6,3,0),(7,4,0)]),
        ('second-indirect-node',917+2036+1018*1018,[(6,1022,0),(7,1023,0)]),
        ('double-indirect-nonzero-branch',917+2036+2*1018*1018+2*1018*1018+3*1018,
         [(6,2041,2),(7,2042+2*1019,3),(8,2043+2*1019+3,0)])]:
        f=fixture();start=logical*4096;u64(f[4102],16,start+19)
        slot=0 if len(chain)==1 and chain[0][1]==1 else 1 if len(chain)==1 else 2 if chain[0][1]==3 else 3 if chain[0][1]==1022 else 4
        u32(f[4102],4052+slot*4,6)
        for i,(nid,noff,childslot) in enumerate(chain):
            block=4110+i;f[block]=bytearray(4096);footer(f[block],nid,5,noff);nat(f[2560],nid,5,block)
            u32(f[block],childslot*4,chain[i+1][0] if i+1<len(chain) else 4501)
        add(name,f,offset=start,want=data[:19])
    f=fixture();u32(f[1025],3595,0);add('journal-tombstone-no-table-fallback',f,lookup=err(14))
    f=fixture();u16(f[1025],3584,39);add('journal-count-overflow',f,prep=err(10))
    f=fixture();u16(f[1025],3584,2);f[1025][3599:3612]=f[1025][3586:3599];add('duplicate-journal-nid',f,prep=err(10))
    f=fixture();u32(f[1025],3595,4095);add('journal-address-before-main',f,prep=err(10))
    f=fixture();f[1025][4091]=1;add('wrong-summary-type',f,prep=err(10))
    f=fixture();f[1025][:507]=f[1025][3584:4091];f[1024]=f[1029]=cp(2,5,6);add('compact-summary-journal',f)
    for name,offset,value in [('wrong-inode-nid',4072,99),('wrong-node-owner',4076,9),('wrong-node-offset',4080,8)]:
        f=fixture();u32(f[4102],offset,value);add(name,f,lookup=err(10))
    for name,advice,flags in [('encrypted-inode',4,0),('verity-inode',0x40,0),('compressed-inode',0,4),('casefold-directory',0,0x40000000)]:
        f=fixture();node=f[4100] if 'directory' in name else f[4102];node[2]=advice;u32(node,80,flags);add(name,f,lookup=err(3),listing=False)
    f=fixture();u16(f[4102],360,25);add('unaligned-extra-isize',f,lookup=err(3))
    f=fixture();u32(f[4102],384,0xffffffff);add('unwritten-address-not-plaintext',f,read=err(10))
    f=fixture();u32(f[4102],388,4095);add('bad-second-block-clears-first-block-output',f,read=err(10))
    add('second-block-io-error-clears-prefix',read=err(15),fail=4502)
    add('summary-io-failure',prep=err(15),fail=1025)
    add('inode-io-failure',lookup=err(15),fail=4102)
    f=fixture();cap=(923-6-1)*4;f[4101][388:388+cap]=entries([('.',4,2),('test',5,1),('test',5,1)],cap,True);add('duplicate-name-rejected',f,lookup=err(10))
    f=fixture();cap=(923-6-1)*4;f[4101][388:388+cap]=entries([('test',5,2)],cap,True);add('dentry-mode-mismatch',f,lookup=err(10))
    add('missing-path',path='/dir/missing',lookup=err(14))
    for path in ['/dir/../test','/dir//test','/dir/test/','relative']:
        add('reject-path-'+path,path=path,lookup=err(2))
    cc=['clang','-std=c11','-fshort-wchar','-Wall','-Wextra','-Werror','-fsanitize=address,undefined']
    inc=[src,a.edk2/'MdePkg/Include',a.edk2/'MdePkg/Include'/('AArch64' if platform.machine()=='aarch64' else 'X64')]
    cc += [x for d in inc for x in ['-I',str(d)]]
    with tempfile.TemporaryDirectory(prefix='fuxi-m2-files-') as temp:
        temp=pathlib.Path(temp);binary=temp/'files';image=temp/'disk.img';expected=temp/'expected.bin'
        subprocess.run(cc+[str(root/'tools/tests/fuxi_f2fs_files_host.c'),str(src/'DataReadOnly.c'),str(src/'F2fsReadOnly.c'),str(src/'F2fsFiles.c'),'-o',str(binary)],check=True)
        for case in cases:
            with image.open('wb') as stream:
                stream.truncate(32768*4096)
                for block,content in case['f'].items():
                    assert len(content)==4096,(case['name'],block,len(content));stream.seek(block*4096);stream.write(content)
            expected.write_bytes(case['want'])
            env={**os.environ};env.pop('F2R_FAIL_LBA',None)
            if case['fail'] is not None:env['F2R_FAIL_LBA']=str(case['fail'])
            subprocess.run([str(binary),str(image),case['path'],hex(case['prep']),hex(case['lookup']),str(case['offset']),hex(case['read']),str(expected),str(int(case['listing']))],env=env,check=True)
            print('PASS '+case['name'],flush=True)
    files=[src/'F2fsReadOnly.c',src/'F2fsReadOnly.h',src/'F2fsFiles.c',src/'DataReadOnly.c',root/'tools/tests/fuxi_f2fs_files_host.c',pathlib.Path(__file__).resolve()]
    a.report.parent.mkdir(parents=True,exist_ok=True)
    a.report.write_text(json.dumps(dict(result='passed',fixtures=len(cases),scope='production journal/node/path/directory/file reads on independently encoded images; no hardware or Android decryption',cases=[c['name'] for c in cases],sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}),indent=2)+'\n')

if __name__=='__main__':main()
