import argparse,pathlib,subprocess,tempfile,hashlib
root=pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--edk2',type=pathlib.Path,required=True)
args=parser.parse_args()
ufs=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe'
data=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
s=(ufs/'FuxiNativeUfsDxe.c').read_text()
start=s.index('STATIC EFI_STATUS FnuHashKeymaster(');end=s.index('\nSTATIC BOOLEAN mLun4Passed',start)
production=s[start:end]
harness=r'''
#include "DataReadOnly.h"
#include "UfsSha256.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static UINTN calls; static int fail_at;
static UINT8 contents[524288];
static EFI_STATUS readfn(VOID *c, UINT64 lba, UINTN blocks, VOID *buf) {
  (void)c; calls++; if (fail_at && calls==(UINTN)fail_at) return EFI_DEVICE_ERROR;
  assert(lba>=8 && lba+blocks<=136); memcpy(buf,contents+(lba-8)*4096,blocks*4096); return EFI_SUCCESS;
}
static INTN CompareMem(const VOID*a,const VOID*b,UINTN n) { return memcmp(a,b,n); }
static UINTN UnicodeSPrint(CHAR16 *out,UINTN size,const CHAR16 *fmt,...) { (void)fmt;assert(size>=6);out[0]='0';out[1]='0';out[2]=0;return 2; }
static void FnuLog(const CHAR16 *fmt,...) { (void)fmt; }
'''+production+r'''
int main(void){
 FDP_DISK d={0}; FDP_PARTITION p={0}; UINT8 scratch[65536], digest[32]; FNU_SHA256_CTX ctx;
 d.Read=readfn; d.BlockSize=4096; d.LastBlock=200; p.First=8;p.Last=135;p.Present=TRUE;
 for(UINTN i=0;i<sizeof(contents);i++) contents[i]=(UINT8)(i*7+i/251);
 FnuSha256Init(&ctx); FnuSha256Update(&ctx,contents,sizeof(contents)); FnuSha256Final(&ctx,digest);
 assert(FnuHashKeymaster(&d,&p,L"a=",digest,scratch)==EFI_SUCCESS && calls==8);
 calls=0; digest[0]^=1; assert(FnuHashKeymaster(&d,&p,L"a=",digest,scratch)==EFI_COMPROMISED_DATA && calls==8);
 calls=0; fail_at=3; assert(FnuHashKeymaster(&d,&p,L"a=",digest,scratch)==EFI_DEVICE_ERROR && calls==3);
 calls=0; fail_at=0;p.Last=134;assert(FnuHashKeymaster(&d,&p,L"a=",digest,scratch)==EFI_COMPROMISED_DATA && calls==0);
 puts("production hash path: match, mismatch, IO failure, geometry passed");return 0;
}
'''
edk=args.edk2.resolve()/'MdePkg/Include'
with tempfile.TemporaryDirectory() as t:
 c=pathlib.Path(t)/'test.c';c.write_text(harness);exe=pathlib.Path(t)/'test'
 subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fshort-wchar','-fsanitize=address,undefined','-I',str(edk),'-I',str(edk/'X64'),'-I',str(data),'-I',str(ufs),str(c),str(data/'DataReadOnly.c'),str(ufs/'UfsSha256.c'),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('production function SHA256',hashlib.sha256(production.encode()).hexdigest())
