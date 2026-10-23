// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "UsbSmmuRoute.h"
#ifdef FUXI_SMMU_UEFI
#include <Library/BaseMemoryLib.h>
#define CLEAR(p) ZeroMem((p),sizeof(*(p)))
#else
#include <string.h>
#define CLEAR(p) memset((p),0,sizeof(*(p)))
#endif
#define USB_SMR 0x80000040u
#define USB_S2CR 0x000100ffu
static FUA32 Restore(FUA_READ32 read,FUR_WRITE32 write,void *ctx,FUR_STATE *s) {
  FUA32 smr=0x800+4*s->Slot,s2cr=0xc00+4*s->Slot;
  // Remove the valid match before restoring any stale context routing.
  write(ctx,smr,s->SavedSmr);
  s->ObservedSmr=read(ctx,smr);
  if(s->ObservedSmr!=s->SavedSmr) return FurRestoreFailed;
  write(ctx,s2cr,s->SavedS2cr);
  s->ObservedS2cr=read(ctx,s2cr);
  if(s->ObservedS2cr!=s->SavedS2cr) return FurRestoreFailed;
  s->Active=0;s->RestoreOk=1;return FurOk;
}
FUA32 FurInstall(FUA_READ32 read,FUR_WRITE32 write,void *ctx,FUR_STATE *s) {
  FUA32 id0,id1,cr0,groups,slot=FUA_SCAN_LIMIT,smr=0,s2cr=0,result;
  if(s->Active) return FurChanged;
  CLEAR(s);
  id0=read(ctx,0x20);id1=read(ctx,0x24);cr0=read(ctx,0);
  groups=id0&255;
  if(id0==0xffffffff || id1==0xffffffff || !(id0&(1u<<27)) ||
     !groups || groups>FUA_SCAN_LIMIT || (cr0&((1u<<3)|1u)) || !(cr0&(1u<<10))) return FurUnsafe;
  // Full scan is mandatory: an exact new match must not overlap any valid one.
  for(FUA32 i=0;i<groups;i++) {
    FUA32 m=read(ctx,0x800+4*i),v=read(ctx,0xc00+4*i);
    if(m&(1u<<31)) {
      FUA32 mask=(m>>16)&0x7fff;
      if(!((0x40^(m&0xffff))&~mask&0xffff)) return FurChanged;
    } else if(slot==FUA_SCAN_LIMIT) {slot=i;smr=m;s2cr=v;}
  }
  if(slot==FUA_SCAN_LIMIT) return FurNoSlot;
  s->Slot=slot;s->SavedSmr=smr;s->SavedS2cr=s2cr;
  if(read(ctx,0x20)!=id0 || read(ctx,0x24)!=id1 || read(ctx,0)!=cr0 ||
     read(ctx,0x800+4*slot)!=smr || read(ctx,0xc00+4*slot)!=s2cr) return FurChanged;
  // The SMR is still invalid. Test the route encoding before enabling a match.
  s->Touched=1;write(ctx,0xc00+4*slot,USB_S2CR);
  s->ObservedS2cr=read(ctx,0xc00+4*slot);s->TestS2cr=s->ObservedS2cr;
  if((s->ObservedS2cr&0xffffff00u)!=(USB_S2CR&0xffffff00u)) {
    result=Restore(read,write,ctx,s);return result?result:FurBypassRejected;
  }
  s->Active=1; // Conservatively retain ownership until rollback is verified.
  write(ctx,0x800+4*slot,USB_SMR);s->ObservedSmr=read(ctx,0x800+4*slot);s->TestSmr=s->ObservedSmr;
  if(s->ObservedSmr!=USB_SMR) {
    result=Restore(read,write,ctx,s);return result?result:FurSmrRejected;
  }
  // Re-read routing after activation, too: no STARTTRANSFER on a changed route.
  s->ObservedS2cr=read(ctx,0xc00+4*slot);s->TestS2cr=s->ObservedS2cr;
  if((s->ObservedS2cr&0xffffff00u)!=(USB_S2CR&0xffffff00u)) {
    result=Restore(read,write,ctx,s);return result?result:FurBypassRejected;
  }
  s->Active=1;return FurOk;
}
FUA32 FurRemove(FUA_READ32 read,FUR_WRITE32 write,void *ctx,FUR_STATE *s) {
  if(!s->Active) return FurOk;
  if(read(ctx,0x800+4*s->Slot)!=USB_SMR ||
     (read(ctx,0xc00+4*s->Slot)&0xffffff00u)!=(USB_S2CR&0xffffff00u)) return FurChanged;
  return Restore(read,write,ctx,s);
}
