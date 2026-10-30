// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef FUXI_M3_KEYMINT_BACKEND_H
#define FUXI_M3_KEYMINT_BACKEND_H
#include "M3KeyRecovery.h"

#define FKM_MESSAGE_BYTES 0x15000U
#define FKM_SHARED_BYTES 0x16000U
#define FKM_REQUEST_LIMIT 8192U

// Exchange performs exactly one IQSEEComCompat sendRequest (op0/counts0x424),
// including bounded continuation of that same interrupted SMC, cache maintenance
// and physical/bridge checks. It must never log buffers or initiate a new request
// on error. The four raw return registers are separate from TA status.
// This library supplies no live SMC callback and no allocation/registration API.
typedef struct { UINT64 A0, A1, A2, A3; } FKM_RETURN;
typedef EFI_STATUS (*FKM_EXCHANGE)(VOID *Context, UINT8 *Shared,
                                  UINTN InputBytes, UINTN OutputBytes,
                                  FKM_RETURN *Result);
typedef struct {
  UINT8 *Shared;
  UINTN SharedBytes;
  UINT32 App;
  FKM_EXCHANGE Exchange;
  VOID *ExchangeContext;
  BOOLEAN Ready, Quarantined;
  UINT64 Handle;
  UINT8 Request[FKM_REQUEST_LIMIT];
  UINTN RequestBytes;
  UINT32 Fault; // non-secret rejection category only, never buffer bytes
  // Validated outer response metadata only; never payload bytes or handles.
  BOOLEAN ResponseHeaderSeen;
  UINT32 ResponseStatus, ResponsePayloadBytes, ResponseWireBytes;
} FKM_CONTEXT;

// New zeroed, exclusively owned CPU context and an independently allocated,
// already registered/verified shared range required. All input/output/callback
// storage must be disjoint. No concurrent calls or callback reentry.
// SessionVerified asserts the pinned A17 AIDL TEE route and live app/bridge
// ownership, not merely a successful query or table membership. No production
// caller currently establishes this. Binding seed remains FkrPrepare's gate.
EFI_STATUS FkmInitialize(FKM_CONTEXT *Context, UINT32 App, UINT8 *Shared,
                         UINTN SharedBytes, FKM_EXCHANGE Exchange,
                         VOID *ExchangeContext, BOOLEAN SessionVerified,
                         FKR_OPS *Ops);
// CPU-only CBOR request encoder and strict success-response decoder, exposed
// for independent vendor codec comparison. No data pointers until full parse.
EFI_STATUS FkmEncode(FKR_STAGE Stage, CONST FKR_BEGIN_REQUEST *Begin,
                     UINT64 Handle, CONST UINT8 *Input, UINTN InputBytes,
                     UINT8 *Request, UINTN Capacity, UINTN *Bytes);
EFI_STATUS FkmDecode(FKR_STAGE Stage, CONST UINT8 *Payload, UINTN Bytes,
                     FKR_REPLY *Reply, CONST UINT8 **Output, UINTN *OutputBytes);
// Non-secret version fields of a stored key blob, read through one read-only
// getKeyCharacteristics (0x2109). Only OS version/patch integers are reported;
// no other authorization-set value is retained or logged.
typedef struct {
  BOOLEAN HaveOsVersion, HaveOsPatchLevel;
  UINT32 OsVersion, OsPatchLevel, TagsScanned;
} FKM_CHARACTERISTICS;
EFI_STATUS FkmProbeCharacteristics(FKM_CONTEXT *Context, CONST UINT8 *Blob,
                                   UINTN BlobBytes, FKM_CHARACTERISTICS *Out);
#endif
