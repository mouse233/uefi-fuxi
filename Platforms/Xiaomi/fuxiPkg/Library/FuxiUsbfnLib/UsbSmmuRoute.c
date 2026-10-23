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
static int RouteMatches(FUR_STATE *s,FUA32 actual) {
  return (s->DesiredS2cr==USB_S2CR)?
    ((actual&0xffffff00u)==(USB_S2CR&0xffffff00u)):(actual==s->DesiredS2cr);
}
static int ContextUnchanged(FUA_READ32 read,void *ctx,FUR_STATE *s) {
  return !s->ContextChecked || (read(ctx,s->ContextBase)==s->ContextSctlr &&
    read(ctx,((read(ctx,0x24)&(1u<<31))?0x10000u:0x1000u)+4*s->Context)==s->ContextCbar);
}
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
static FUA32 Install(FUA_READ32 read,FUR_WRITE32 write,void *ctx,FUR_STATE *s,int contextMode) {
  FUA32 id0,id1,cr0,groups,slot=FUA_SCAN_LIMIT,smr=0,s2cr=0,result;
  FUA32 used[8]={0};
  if(s->Active) return FurChanged;
  CLEAR(s);
  id0=read(ctx,0x20);id1=read(ctx,0x24);cr0=read(ctx,0);
  groups=id0&255;
  if(id0==0xffffffff || id1==0xffffffff || !(id0&(1u<<27)) ||
     !groups || groups>FUA_SCAN_LIMIT || (cr0&((1u<<3)|1u)) || !(cr0&(1u<<10))) return FurUnsafe;
  // Full scan is mandatory: an exact new match must not overlap any valid one.
  for(FUA32 i=0;i<groups;i++) {
    FUA32 m=read(ctx,0x800+4*i),v=read(ctx,0xc00+4*i);
    // Even inactive TRANS references are treated as reserved context ownership.
    if(((v>>16)&3)==0) used[(v&255)/32]|=1u<<(v&31);
    if(m&(1u<<31)) {
      FUA32 mask=(m>>16)&0x7fff;
      if(!((0x40^(m&0xffff))&~mask&0xffff)) return FurChanged;
    } else if(slot==FUA_SCAN_LIMIT) {slot=i;smr=m;s2cr=v;}
  }
  if(slot==FUA_SCAN_LIMIT) return FurNoSlot;
  s->Slot=slot;s->SavedSmr=smr;s->SavedS2cr=s2cr;
  s->DesiredS2cr=USB_S2CR;
  if(contextMode) {
    FUA32 shift=(id1&(1u<<31))?16:12,first=(1u<<(((id1>>28)&7)+1))<<shift;
    FUA32 count=id1&255,gr1=1u<<shift;
    for(FUA32 n=count;n>1;n--) {
      FUA32 bank=n-1,base=first+(bank<<shift),cbar,sctlr;
      if((used[bank/32]&(1u<<(bank&31))) || base>0x100000-4 ||
         gr1+bank*4>0x100000-4) continue;
      cbar=read(ctx,gr1+4*bank);
      if(((cbar>>16)&3)!=1) continue; // Existing S1 translation / S2 bypass only.
      sctlr=read(ctx,base);
      if(sctlr&1) continue; // Never turn off or reconfigure an active context.
      s->Context=bank;s->ContextBase=base;s->ContextCbar=cbar;s->ContextSctlr=sctlr;
      s->ContextChecked=1;s->DesiredS2cr=bank;break; // TRANS to an existing disabled context.
    }
    if(!s->ContextChecked) return FurNoContext;
    if(!ContextUnchanged(read,ctx,s)) return FurChanged;
  }
  if(read(ctx,0x20)!=id0 || read(ctx,0x24)!=id1 || read(ctx,0)!=cr0 ||
     read(ctx,0x800+4*slot)!=smr || read(ctx,0xc00+4*slot)!=s2cr) return FurChanged;
  // The SMR is still invalid. Test the route encoding before enabling a match.
  s->Touched=1;write(ctx,0xc00+4*slot,s->DesiredS2cr);
  s->ObservedS2cr=read(ctx,0xc00+4*slot);s->TestS2cr=s->ObservedS2cr;
  if(!RouteMatches(s,s->ObservedS2cr)) {
    result=Restore(read,write,ctx,s);return result?result:FurBypassRejected;
  }
  if(!ContextUnchanged(read,ctx,s)) {
    result=Restore(read,write,ctx,s);return result?result:FurChanged;
  }
  s->Active=1; // Conservatively retain ownership until rollback is verified.
  write(ctx,0x800+4*slot,USB_SMR);s->ObservedSmr=read(ctx,0x800+4*slot);s->TestSmr=s->ObservedSmr;
  if(s->ObservedSmr!=USB_SMR) {
    result=Restore(read,write,ctx,s);return result?result:FurSmrRejected;
  }
  // Re-read routing after activation, too: no STARTTRANSFER on a changed route.
  s->ObservedS2cr=read(ctx,0xc00+4*slot);s->TestS2cr=s->ObservedS2cr;
  if(!RouteMatches(s,s->ObservedS2cr)) {
    result=Restore(read,write,ctx,s);return result?result:FurBypassRejected;
  }
  if(!ContextUnchanged(read,ctx,s)) {
    result=Restore(read,write,ctx,s);return result?result:FurChanged;
  }
  s->Active=1;return FurOk;
}
FUA32 FurInstall(FUA_READ32 read,FUR_WRITE32 write,void *ctx,FUR_STATE *s) {
  return Install(read,write,ctx,s,0);
}
FUA32 FurInstallViaContext(FUA_READ32 read,FUR_WRITE32 write,void *ctx,FUR_STATE *s) {
  return Install(read,write,ctx,s,1);
}
FUA32 FurRemove(FUA_READ32 read,FUR_WRITE32 write,void *ctx,FUR_STATE *s) {
  if(!s->Active) return FurOk;
  if(read(ctx,0x800+4*s->Slot)!=USB_SMR ||
     !RouteMatches(s,read(ctx,0xc00+4*s->Slot))) return FurChanged;
  return Restore(read,write,ctx,s);
}
