// SPDX-License-Identifier: BSD-2-Clause-Patent
// Arm SMMUv2 architectural register observations, not a DMA mapping policy.
#include "UsbSmmuAudit.h"
#ifdef FUXI_SMMU_UEFI
#include <Library/BaseMemoryLib.h>
#define CLEAR(p) ZeroMem((p),sizeof(*(p)))
#else
#include <string.h>
#define CLEAR(p) memset((p),0,sizeof(*(p)))
#endif
static FUA64 Pair(FUA_READ32 read,void *ctx,FUA32 at) {
  FUA32 lo=read(ctx,at),hi=read(ctx,at+4);
  return (FUA64)lo|((FUA64)hi<<32);
}
void FuaCapture(FUA_READ32 read,void *ctx,FUA32 aperture,FUA32 sid,FUA_REPORT *r) {
  FUA32 pages,extended;
  CLEAR(r);
  if(aperture<0x1000 || sid>0xffff) {r->Unsupported=1;return;}
  r->Id0=read(ctx,0x20);r->Id1=read(ctx,0x24);r->Cr0=read(ctx,0);
  r->Gfsr=read(ctx,0x48);
  // Restrict reads to architected groups: some Qcom hypervisors mishandle
  // accesses past group 127 even when a larger group count is advertised.
  if(r->Id0==0 || r->Id0==0xffffffff || r->Id1==0xffffffff ||
     !(r->Id0&(1u<<27))) {r->Unsupported=1;return;}
  r->Groups=r->Id0&255;r->Scanned=r->Groups>FUA_SCAN_LIMIT?FUA_SCAN_LIMIT:r->Groups;
  r->Partial=(r->Groups>r->Scanned);
  r->PageShift=(r->Id1&(1u<<31))?16:12;
  pages=1u<<(((r->Id1>>28)&7)+1);
  r->ContextBase=pages<<r->PageShift;r->ContextCount=r->Id1&255;
  extended=(r->Cr0&(1u<<3))!=0;
  if(extended && !(r->Id0&(1u<<8))) {r->Unsupported=1;return;}
  for(FUA32 i=0;i<r->Scanned;i++) {
    FUA32 smr=read(ctx,0x800+4*i),s2cr=read(ctx,0xc00+4*i);
    FUA32 valid=extended?(s2cr&(1u<<10)):(smr&(1u<<31));
    FUA32 mask=(smr>>16)&(extended?0xffff:0x7fff);
    FUA32 cb,base,gr1;
    FUA_MATCH *m;
    if(!valid || ((sid^(smr&0xffff))&~mask&0xffff)) continue;
    r->Matches++;
    if(r->Stored==FUA_MAX_MATCHES) {r->Partial=1;continue;}
    m=&r->Match[r->Stored++];m->Slot=i;m->Smr=smr;m->S2cr=s2cr;m->Context=s2cr&255;
    // BYPASS/FAULT/reserved routes do not identify a context to dereference.
    if(((s2cr>>16)&3)!=0) continue;
    cb=m->Context;base=r->ContextBase+(cb<<r->PageShift);gr1=1u<<r->PageShift;
    if(cb>=r->ContextCount || base>aperture || aperture-base<0x70 ||
       gr1+0x800+cb*4>aperture-4) {r->InvalidContext=1;continue;}
    m->Cbar=read(ctx,gr1+cb*4);m->Cba2r=read(ctx,gr1+0x800+cb*4);
    m->Sctlr=read(ctx,base);m->Tcr2=read(ctx,base+0x10);
    m->Ttbr0=Pair(read,ctx,base+0x20);m->Ttbr1=Pair(read,ctx,base+0x28);
    m->Tcr=read(ctx,base+0x30);m->Fsr=read(ctx,base+0x58);m->Far=Pair(read,ctx,base+0x60);
    m->ContextRead=1;
  }
}
