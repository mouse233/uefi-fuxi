// SPDX-License-Identifier: BSD-2-Clause-Patent
#define _GNU_SOURCE
#include "M3RootTrustPublic.h"
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
int main(void){
 unsigned N;
 while(scanf("%u",&N)==1){
  assert(getchar()=='\n'&&N<=4096);
  UINT8 *Base=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  assert(Base!=MAP_FAILED);UINT8 *Data=Base+4096-N;
  assert(fread(Data,1,N,stdin)==N);assert(mprotect(Base+4096,4096,PROT_NONE)==0);
  UINT32 Boot=0xa5a5a5a5;
  if(FnuReadRootTrustBoot(Data,N,&Boot))printf("%u\n",Boot);
  else{assert(Boot==0);puts("rejected");}
  assert(munmap(Base,8192)==0);
 }
 return 0;
}
