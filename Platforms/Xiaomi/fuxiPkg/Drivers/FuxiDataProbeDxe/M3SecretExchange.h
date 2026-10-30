// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef FUXI_M3_SECRET_EXCHANGE_H
#define FUXI_M3_SECRET_EXCHANGE_H
#include "M3KeyMintBackend.h"

#define FSE_RESUME_LIMIT 8U
#define FSE_CALL_LIMIT (FKR_UPDATE_LIMIT+3U)
typedef enum { FseEmpty, FseBound, FseBusy, FseQuarantined, FseClosed } FSE_STATE;
typedef struct {
  FSE_STATE State;
  UINT8 *Page;
  UINT64 Physical, Bridge;
  UINTN RegisteredBytes;
  UINT32 App;
  UINTN Calls, Resumes;
} FSE_CONTEXT;

// Explicitly compiled only with FUXI_M3_SECRET_EXCHANGE=1. Caller must have
// created this same live bridge, loaded and verified this same TEE app, stopped
// UFS/DMA, and established ownership/cache/identity mapping in this boot.
// LeaseVerified is an assertion; no production entrypoint supplies it yet.
// New zeroed CPU context, exclusive low-4GiB identity-mapped shared allocation.
EFI_STATUS FseInitialize(FSE_CONTEXT *Context, UINT8 *Page, UINT64 Physical,
                         UINTN RegisteredBytes, UINT64 Bridge, UINT32 App,
                         BOOLEAN LeaseVerified);
// Actual ArmCallSmc/cache adapter for FKM_EXCHANGE. No logger or allocator.
EFI_STATUS FseExchange(VOID *Context, UINT8 *Shared, UINTN InputBytes,
                       UINTN OutputBytes, FKM_RETURN *Result);
// Publish a verified CPU wipe and revoke further calls before the owner starts
// app/loader/env release and bridge deletion. Does not release any remote object,
// delete the bridge or free pages. All of those still require terminal proofs.
// Unknown exchange/backend/operation ownership refuses this cleanup permission.
EFI_STATUS FsePermitCleanup(FSE_CONTEXT *Context, FKM_CONTEXT *Backend);
#endif
