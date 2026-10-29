// SPDX-License-Identifier: BSD-2-Clause-Patent
// Existing-key recovery core. No allocator, logger, SMC, write or key-generation API.
#ifndef FUXI_M3_KEY_RECOVERY_H
#define FUXI_M3_KEY_RECOVERY_H
#include <Uefi.h>

#define FKR_SECDISCARDABLE_BYTES 16384U
#define FKR_BLOB_LIMIT 4096U
#define FKR_ENCRYPTED_LIMIT 4096U
#define FKR_SEED_LIMIT 64U
#define FKR_NONCE_BYTES 12U
#define FKR_TAG_BYTES 16U
#define FKR_UPDATE_LIMIT 16U

typedef enum {
  FkrVersionFile, FkrSecdiscardableFile, FkrKeymasterBlobFile, FkrEncryptedKeyFile
} FKR_FILE;
// Whole regular-file CPU copy only. Refuse oversize/short reads. These buffers
// must never be registered for DMA/secure-world access by this callback.
typedef EFI_STATUS (*FKR_READ_FILE)(VOID *Context, FKR_FILE File, VOID *Buffer,
                                   UINTN Capacity, UINTN *Bytes);
typedef enum {
  FkrEmpty, FkrPrepared, FkrActive, FkrRecovered, FkrFailed, FkrQuarantined
} FKR_STATE;
typedef enum { FkrRead, FkrBegin, FkrUpdate, FkrFinish, FkrAbort, FkrComplete } FKR_STAGE;

typedef struct {
  UINT32 Purpose;    // 1 = decrypt; separate from the authorization parameters.
  UINT32 BlockMode;  // 32 = GCM
  UINT32 Padding;    // 1 = NONE
  UINT32 MacBits;    // 128
  CONST UINT8 *Blob;
  UINTN BlobBytes;
  CONST UINT8 *ApplicationId;
  UINTN ApplicationIdBytes;
  CONST UINT8 *Nonce;
  UINTN NonceBytes;
} FKR_BEGIN_REQUEST;

// This is CPU-only parsed metadata, not a wire/SMCI structure. The adapter must
// independently validate transport, TA status, lengths and operation ownership.
// Terminal=FALSE means a shared-buffer/command completion doubt: stop immediately,
// preserve the entire workspace and adapter allocations, no abort/retry/wipe.
typedef struct {
  BOOLEAN Terminal;
  BOOLEAN OperationClosed;
  INT32 KeyMintStatus;
  UINT64 Handle;
  UINTN Consumed, Produced;
} FKR_REPLY;
typedef EFI_STATUS (*FKR_BEGIN_CALL)(VOID *Context, CONST FKR_BEGIN_REQUEST *Request,
                                    FKR_REPLY *Reply);
typedef EFI_STATUS (*FKR_UPDATE_CALL)(VOID *Context, UINT64 Handle,
                                     CONST UINT8 *Input, UINTN Bytes,
                                     UINT8 *Output, UINTN Capacity, FKR_REPLY *Reply);
typedef EFI_STATUS (*FKR_FINISH_CALL)(VOID *Context, UINT64 Handle,
                                     UINT8 *Output, UINTN Capacity, FKR_REPLY *Reply);
typedef EFI_STATUS (*FKR_ABORT_CALL)(VOID *Context, UINT64 Handle, FKR_REPLY *Reply);
typedef struct {
  VOID *Context;
  FKR_BEGIN_CALL Begin;
  FKR_UPDATE_CALL Update;
  FKR_FINISH_CALL Finish;
  FKR_ABORT_CALL Abort;
} FKR_OPS;

typedef struct {
  FKR_STATE State;
  FKR_STAGE Stage;
  EFI_STATUS Status;
  INT32 KeyMintStatus;
  UINT64 Handle;
  UINTN BlobBytes, EncryptedBytes, ApplicationIdBytes, CandidateBytes;
  UINT8 Secdiscardable[FKR_SECDISCARDABLE_BYTES];
  UINT8 Blob[FKR_BLOB_LIMIT];
  UINT8 Encrypted[FKR_ENCRYPTED_LIMIT];
  UINT8 ApplicationId[64U + FKR_SEED_LIMIT];
  UINT8 Candidate[FKR_ENCRYPTED_LIMIT];
  FKR_BEGIN_REQUEST Request;
} FKR_WORK;

// New, zero-initialized, exclusively owned workspace required. Inputs, binding
// seed, callback contexts and workspace must be disjoint, no callback reentry.
// Supports metadata kEmptyAuthentication only; never credential/CE recovery.
// BindingChecked means the caller has independently established the actual seed
// context (including an empty seed). It is an assertion, not evidence itself;
// no production caller currently supplies it. Unknown binding must be refused.
EFI_STATUS FkrPrepare(FKR_WORK *Work, FKR_READ_FILE Read, VOID *ReadContext,
                       BOOLEAN BindingChecked, CONST UINT8 *Seed, UINTN SeedBytes);
// Callback core only: no live KeyMint backend is supplied by this interface.
// A backend may succeed only after actual GCM finish verification. Update output
// remains private until that success. Reject upgrades/all nonzero TA statuses.
EFI_STATUS FkrRecoverExisting(FKR_WORK *Work, CONST FKR_OPS *Ops);
// Returns no pointer/length until the operation closed AND finish verified.
EFI_STATUS FkrGetRecovered(CONST FKR_WORK *Work, CONST UINT8 **Data, UINTN *Bytes);
// Refuse active or quarantined workspaces. Caller must retain these allocations
// across unknown completion; a reset must not erase memory still remotely owned.
EFI_STATUS FkrReset(FKR_WORK *Work);
// Specialized independent SHA-512: padded personalization || exact 16KiB input.
EFI_STATUS FkrHashSecdiscardable(CONST UINT8 *Data, UINTN Bytes, UINT8 Digest[64]);
#endif
