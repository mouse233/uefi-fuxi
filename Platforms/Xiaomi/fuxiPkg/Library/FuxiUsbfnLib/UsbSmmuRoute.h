// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef FUXI_USB_SMMU_ROUTE_H
#define FUXI_USB_SMMU_ROUTE_H
#include "UsbSmmuAudit.h"
typedef void (*FUR_WRITE32)(void *Context,FUA32 Offset,FUA32 Value);
enum { FurOk=0,FurUnsafe,FurNoSlot,FurChanged,FurBypassRejected,FurSmrRejected,FurRestoreFailed,FurNoContext };
typedef struct {
  FUA32 Slot,SavedSmr,SavedS2cr,Active,Touched,ObservedSmr,ObservedS2cr,RestoreOk,TestSmr,TestS2cr;
  FUA32 DesiredS2cr,Context,ContextBase,ContextCbar,ContextSctlr,ContextChecked;
} FUR_STATE;
// Only SID 0x40, one previously invalid SMR, no global or context-bank writes.
FUA32 FurInstall(FUA_READ32 Read,FUR_WRITE32 Write,void *Context,FUR_STATE *State);
FUA32 FurInstallViaContext(FUA_READ32 Read,FUR_WRITE32 Write,void *Context,FUR_STATE *State);
// Caller must halt USB before removing a route. A changed route is not overwritten.
FUA32 FurRemove(FUA_READ32 Read,FUR_WRITE32 Write,void *Context,FUR_STATE *State);
#endif
