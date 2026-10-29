// SPDX-License-Identifier: BSD-2-Clause-Patent
// Independently implemented from fixed recovery interface facts. No vendor code.
#include "M3KeyRecovery.h"

STATIC VOID Erase(VOID *Memory, UINTN Bytes) {
  volatile UINT8 *P = Memory;
  while (Bytes-- != 0) *P++ = 0;
}
STATIC VOID Copy(VOID *Dst, CONST VOID *Src, UINTN Bytes) {
  UINT8 *D = Dst; CONST UINT8 *S = Src;
  while (Bytes-- != 0) *D++ = *S++;
}
STATIC VOID EraseMaterials(FKR_WORK *W) {
  Erase(W->Secdiscardable, sizeof(W->Secdiscardable));
  Erase(W->Blob, sizeof(W->Blob));
  Erase(W->Encrypted, sizeof(W->Encrypted));
  Erase(W->ApplicationId, sizeof(W->ApplicationId));
  Erase(W->Candidate, sizeof(W->Candidate));
  Erase(&W->Request, sizeof(W->Request));
  W->BlobBytes = W->EncryptedBytes = W->ApplicationIdBytes = W->CandidateBytes = 0;
  W->Handle = 0;
}
EFI_STATUS FkrReset(FKR_WORK *W) {
  if (W == NULL) return EFI_INVALID_PARAMETER;
  if (W->State == FkrActive || W->State == FkrQuarantined) return EFI_ACCESS_DENIED;
  Erase(W, sizeof(*W));
  return EFI_SUCCESS;
}
STATIC EFI_STATUS Failed(FKR_WORK *W, EFI_STATUS Status) {
  EraseMaterials(W);
  W->State = FkrFailed;
  W->Status = Status;
  return Status;
}
STATIC EFI_STATUS Quarantine(FKR_WORK *W) {
  // Do not erase, free, issue another call, or expose a candidate buffer.
  W->State = FkrQuarantined;
  W->Status = EFI_NOT_READY;
  return EFI_NOT_READY;
}
EFI_STATUS FkrPrepare(FKR_WORK *W, FKR_READ_FILE Read, VOID *Context,
                       BOOLEAN BindingChecked, CONST UINT8 *Seed, UINTN SeedBytes) {
  EFI_STATUS Status;
  UINTN Bytes = 0;
  UINT8 Version = 0;
  if (W == NULL) return EFI_INVALID_PARAMETER;
  if (W->State != FkrEmpty) return EFI_ACCESS_DENIED;
  W->Stage = FkrRead;
  if (Read == NULL || SeedBytes > FKR_SEED_LIMIT || (SeedBytes != 0 && Seed == NULL))
    return Failed(W, EFI_INVALID_PARAMETER);
  if (!BindingChecked) return Failed(W, EFI_NOT_READY);
  Status = Read(Context, FkrVersionFile, &Version, 1, &Bytes);
  if (EFI_ERROR(Status)) return Failed(W, Status);
  if (Bytes != 1 || Version != '1') return Failed(W, EFI_UNSUPPORTED);
  Bytes = 0;
  Status = Read(Context, FkrSecdiscardableFile, W->Secdiscardable,
                  sizeof(W->Secdiscardable), &Bytes);
  if (EFI_ERROR(Status)) return Failed(W, Status);
  if (Bytes != FKR_SECDISCARDABLE_BYTES) return Failed(W, EFI_BAD_BUFFER_SIZE);
  Status = FkrHashSecdiscardable(W->Secdiscardable, Bytes, W->ApplicationId);
  Erase(W->Secdiscardable, sizeof(W->Secdiscardable));
  if (EFI_ERROR(Status)) return Failed(W, Status);
  // Fixed metadata caller passes kEmptyAuthentication. No secret or HAT is
  // synthesized. Binding seed is explicit and independently checked by caller.
  if (SeedBytes != 0) Copy(W->ApplicationId + 64, Seed, SeedBytes);
  W->ApplicationIdBytes = 64 + SeedBytes;
  Status = Read(Context, FkrKeymasterBlobFile, W->Blob, sizeof(W->Blob), &W->BlobBytes);
  if (EFI_ERROR(Status)) return Failed(W, Status);
  if (W->BlobBytes == 0 || W->BlobBytes > sizeof(W->Blob))
    return Failed(W, EFI_BAD_BUFFER_SIZE);
  Status = Read(Context, FkrEncryptedKeyFile, W->Encrypted,
                  sizeof(W->Encrypted), &W->EncryptedBytes);
  if (EFI_ERROR(Status)) return Failed(W, Status);
  if (W->EncryptedBytes <= FKR_NONCE_BYTES + FKR_TAG_BYTES ||
      W->EncryptedBytes > sizeof(W->Encrypted)) return Failed(W, EFI_BAD_BUFFER_SIZE);
  W->Request.Purpose = 1;
  W->Request.BlockMode = 32;
  W->Request.Padding = 1;
  W->Request.MacBits = 128;
  W->Request.Blob = W->Blob; W->Request.BlobBytes = W->BlobBytes;
  W->Request.ApplicationId = W->ApplicationId;
  W->Request.ApplicationIdBytes = W->ApplicationIdBytes;
  W->Request.Nonce = W->Encrypted; W->Request.NonceBytes = FKR_NONCE_BYTES;
  W->State = FkrPrepared; W->Status = EFI_SUCCESS;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS AbortFailed(FKR_WORK *W, CONST FKR_OPS *Ops, EFI_STATUS Status) {
  FKR_REPLY Reply;
  EFI_STATUS AbortStatus;
  W->Stage = FkrAbort;
  Erase(&Reply, sizeof(Reply));
  AbortStatus = Ops->Abort(Ops->Context, W->Handle, &Reply);
  if (!Reply.Terminal || EFI_ERROR(AbortStatus) || Reply.KeyMintStatus != 0 ||
      !Reply.OperationClosed) return Quarantine(W);
  return Failed(W, Status);
}

EFI_STATUS FkrRecoverExisting(FKR_WORK *W, CONST FKR_OPS *Ops) {
  EFI_STATUS Status;
  FKR_REPLY Reply;
  UINTN InputBytes, ExpectedBytes, Offset = 0, Calls = 0;
  if (W == NULL || Ops == NULL || Ops->Begin == NULL || Ops->Update == NULL ||
      Ops->Finish == NULL || Ops->Abort == NULL) return EFI_INVALID_PARAMETER;
  if (W->State != FkrPrepared) return EFI_ACCESS_DENIED;
  if (W->EncryptedBytes <= FKR_NONCE_BYTES + FKR_TAG_BYTES ||
      W->EncryptedBytes > sizeof(W->Encrypted) || W->BlobBytes == 0 ||
      W->BlobBytes > sizeof(W->Blob) || W->ApplicationIdBytes < 64 ||
      W->ApplicationIdBytes > sizeof(W->ApplicationId) || W->CandidateBytes != 0 ||
      W->Handle != 0 || W->Request.Purpose != 1 || W->Request.BlockMode != 32 ||
      W->Request.Padding != 1 || W->Request.MacBits != 128 ||
      W->Request.Blob != W->Blob || W->Request.BlobBytes != W->BlobBytes ||
      W->Request.ApplicationId != W->ApplicationId ||
      W->Request.ApplicationIdBytes != W->ApplicationIdBytes ||
      W->Request.Nonce != W->Encrypted || W->Request.NonceBytes != FKR_NONCE_BYTES)
    return Failed(W, EFI_INVALID_PARAMETER);
  InputBytes = W->EncryptedBytes - FKR_NONCE_BYTES;
  ExpectedBytes = InputBytes - FKR_TAG_BYTES;
  W->State = FkrActive; W->Stage = FkrBegin;
  Erase(&Reply, sizeof(Reply));
  Status = Ops->Begin(Ops->Context, &W->Request, &Reply);
  if (!Reply.Terminal) return Quarantine(W);
  W->KeyMintStatus = Reply.KeyMintStatus;
  if (EFI_ERROR(Status) || Reply.KeyMintStatus != 0) {
    if (Reply.Handle != 0) return Quarantine(W); // untrusted failure handle
    return Failed(W, EFI_ERROR(Status) ? Status : EFI_DEVICE_ERROR);
  }
  W->Handle = Reply.Handle;
  if (W->Handle == 0 || Reply.OperationClosed || Reply.Consumed != 0 || Reply.Produced != 0)
    return Quarantine(W);
  W->Stage = FkrUpdate;
  while (Offset < InputBytes && Calls++ < FKR_UPDATE_LIMIT) {
    Erase(&Reply, sizeof(Reply));
    Status = Ops->Update(Ops->Context, W->Handle, W->Encrypted + FKR_NONCE_BYTES + Offset,
                         InputBytes - Offset, W->Candidate + W->CandidateBytes,
                         ExpectedBytes - W->CandidateBytes, &Reply);
    if (!Reply.Terminal) return Quarantine(W);
    W->KeyMintStatus = Reply.KeyMintStatus;
    if (EFI_ERROR(Status) || Reply.KeyMintStatus != 0) {
      if (Reply.OperationClosed) return Failed(W, EFI_ERROR(Status) ? Status : EFI_DEVICE_ERROR);
      return AbortFailed(W, Ops, EFI_ERROR(Status) ? Status : EFI_DEVICE_ERROR);
    }
    if (Reply.OperationClosed) return Failed(W, EFI_PROTOCOL_ERROR);
    if (Reply.Consumed == 0 || Reply.Consumed > InputBytes - Offset ||
        Reply.Produced > ExpectedBytes - W->CandidateBytes)
      return AbortFailed(W, Ops, EFI_PROTOCOL_ERROR);
    Offset += Reply.Consumed; W->CandidateBytes += Reply.Produced;
  }
  if (Offset != InputBytes) return AbortFailed(W, Ops, EFI_ABORTED);
  W->Stage = FkrFinish;
  Erase(&Reply, sizeof(Reply));
  Status = Ops->Finish(Ops->Context, W->Handle, W->Candidate + W->CandidateBytes,
                       ExpectedBytes - W->CandidateBytes, &Reply);
  if (!Reply.Terminal) return Quarantine(W);
  W->KeyMintStatus = Reply.KeyMintStatus;
  if (EFI_ERROR(Status) || Reply.KeyMintStatus != 0) {
    if (Reply.OperationClosed) return Failed(W, EFI_ERROR(Status) ? Status : EFI_DEVICE_ERROR);
    return AbortFailed(W, Ops, EFI_ERROR(Status) ? Status : EFI_DEVICE_ERROR);
  }
  if (!Reply.OperationClosed) return Quarantine(W);
  if (Reply.Consumed != 0 || Reply.Produced > ExpectedBytes - W->CandidateBytes)
    return Failed(W, EFI_PROTOCOL_ERROR);
  W->CandidateBytes += Reply.Produced;
  if (W->CandidateBytes != ExpectedBytes) return Failed(W, EFI_PROTOCOL_ERROR);
  W->Handle = 0;
  Erase(W->Blob, sizeof(W->Blob)); Erase(W->Encrypted, sizeof(W->Encrypted));
  Erase(W->ApplicationId, sizeof(W->ApplicationId)); Erase(&W->Request, sizeof(W->Request));
  W->BlobBytes = W->EncryptedBytes = W->ApplicationIdBytes = 0;
  W->State = FkrRecovered; W->Stage = FkrComplete; W->Status = EFI_SUCCESS;
  return EFI_SUCCESS;
}

EFI_STATUS FkrGetRecovered(CONST FKR_WORK *W, CONST UINT8 **Data, UINTN *Bytes) {
  if (Data == NULL || Bytes == NULL) return EFI_INVALID_PARAMETER;
  *Data = NULL; *Bytes = 0;
  if (W == NULL) return EFI_INVALID_PARAMETER;
  if (W->State != FkrRecovered || W->Stage != FkrComplete || W->Handle != 0 ||
      W->Status != EFI_SUCCESS || W->CandidateBytes == 0 ||
      W->CandidateBytes > FKR_ENCRYPTED_LIMIT - FKR_NONCE_BYTES - FKR_TAG_BYTES)
    return EFI_NOT_READY;
  *Data = W->Candidate; *Bytes = W->CandidateBytes;
  return EFI_SUCCESS;
}
