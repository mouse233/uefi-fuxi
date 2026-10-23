// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef FUXI_USB_SMMU_AUDIT_H
#define FUXI_USB_SMMU_AUDIT_H
#ifdef FUXI_SMMU_UEFI
#include <Uefi.h>
typedef UINT32 FUA32;
typedef UINT64 FUA64;
#else
#include <stdint.h>
typedef uint32_t FUA32;
typedef uint64_t FUA64;
#endif
#define FUA_MAX_MATCHES 4
#define FUA_SCAN_LIMIT 128
// An observation API: intentionally has no register-write or DMA callback.
typedef FUA32 (*FUA_READ32)(void *Context, FUA32 Offset);
typedef struct {
  FUA32 Slot, Smr, S2cr, Context, ContextRead;
  FUA32 Cbar, Cba2r, Sctlr, Tcr, Tcr2, Fsr;
  FUA64 Ttbr0, Ttbr1, Far;
} FUA_MATCH;
typedef struct {
  FUA32 Id0, Id1, Cr0, Gfsr, Groups, Scanned, Matches, Stored;
  FUA32 PageShift, ContextBase, ContextCount, Partial, Unsupported, InvalidContext;
  FUA_MATCH Match[FUA_MAX_MATCHES];
} FUA_REPORT;
void FuaCapture(FUA_READ32 Read, void *Context, FUA32 ApertureBytes,
                FUA32 StreamId, FUA_REPORT *Report);
#endif
