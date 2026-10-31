// SPDX-License-Identifier: BSD-2-Clause-Patent
// Differential synthetic corpus. Guard page starts immediately after prefix.
#define _GNU_SOURCE
#include "M3BlobPublic.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
int main(void) {
  unsigned Prefix,Total;
  while(scanf("%u %u",&Prefix,&Total)==2) {
    assert(getchar()=='\n');
    assert(Prefix>0 && Prefix<=4096);
    UINT8 *Base=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(Base!=MAP_FAILED);
    UINT8 *Data=Base+4096-Prefix;
    assert(fread(Data,1,Prefix,stdin)==Prefix);
    assert(mprotect(Base+4096,4096,PROT_NONE)==0);
    FBP_PUBLIC Public;memset(&Public,0xa5,sizeof(Public));
    BOOLEAN Ok=FnuReadBlobPublic(Data,Total,&Public);
    if(!Ok) {
      FBP_PUBLIC Zero={0};assert(!memcmp(&Public,&Zero,sizeof(Public)));
      puts("rejected");
    } else {
      printf("%llu %zu",(unsigned long long)Public.Format,(size_t)Public.PrefixBytes);
      for(unsigned D=0;D<2;++D) {
        printf(" %u",Public.Domain[D].Present);
        for(unsigned K=0;K<5;++K)printf(" %u",Public.Domain[D].Value[K]);
        printf(" %u",Public.Domain[D].Fbe);
      }
      puts("");
    }
    assert(munmap(Base,8192)==0);
  }
  return 0;
}
