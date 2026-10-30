// SPDX-License-Identifier: BSD-2-Clause-Patent
// Fixed existing-key recovery only. No material/prefix/digest logging.
#if FUXI_M3_KEY_RECOVERY
#include "../FuxiDataProbeDxe/M3KeyRecoveryF2fs.h"
#include "../FuxiDataProbeDxe/M3SecretExchange.h"
typedef struct { FKM_CONTEXT Backend; FSE_CONTEXT Exchange; } FNU_RECOVERY_SESSION;
STATIC FKR_WORK *mRecoveryWork;
STATIC FNU_RECOVERY_SESSION *mRecoverySession;
STATIC EFI_STATUS mRecoveryStatus=EFI_NOT_READY;
STATIC BOOLEAN mRecoveryRetained, mRecoveryVersionOk, mRecoveryAttempted;

STATIC VOID FnuDropRecoveryInput(VOID) {
  if(mRecoveryRetained || mRecoveryWork==NULL)return;
  if(EFI_ERROR(FkrReset(mRecoveryWork))) { mRecoveryRetained=TRUE;return; }
  FreePool(mRecoveryWork);mRecoveryWork=NULL;
}
STATIC VOID FnuPrepareRecovery(CONST FDP_DISK *Disk,CONST FDP_PARTITION *Part,VOID *Scratch) {
  F2R_VOLUME *Volume=NULL;FKR_F2FS_CONTEXT Reader;
  if(mPoisoned || !mReady || mRecoveryWork!=NULL || !Part->Present)return;
  FNU_STAGE("m3-recovery-read");
  mRecoveryWork=AllocateZeroPool(sizeof(*mRecoveryWork));Volume=AllocateZeroPool(sizeof(*Volume));
  if(mRecoveryWork==NULL || Volume==NULL) { mRecoveryStatus=EFI_OUT_OF_RESOURCES;goto Done; }
  mRecoveryStatus=F2rPrepare(Disk,Part,Volume,Scratch,F2R_WORK_BYTES);
  if(EFI_ERROR(mRecoveryStatus))goto Done;
  Reader.Volume=Volume;Reader.Work=Scratch;Reader.WorkBytes=F2R_WORK_BYTES;
  // This flag is accepted by the builder only with the pinned real Android
  // state2/empty-vector capture, never from a synthetic collector test.
  mRecoveryStatus=FkrPrepare(mRecoveryWork,FkrReadF2fsFile,&Reader,TRUE,NULL,0);
  if(!EFI_ERROR(mRecoveryStatus) &&
     (mRecoveryWork->BlobBytes!=208 || mRecoveryWork->EncryptedBytes!=276 ||
      mRecoveryWork->ApplicationIdBytes!=64))mRecoveryStatus=EFI_MEDIA_CHANGED;
Done:
  if(Volume!=NULL) { ZeroMem(Volume,sizeof(*Volume));FreePool(Volume); }
  ZeroMem(Scratch,F2R_WORK_BYTES);
  if(EFI_ERROR(mRecoveryStatus))FnuDropRecoveryInput();
  FnuLog(L"FUXIM3 RECOVERY prepared=%r binding=%08x; no material output",mRecoveryStatus,(UINT32)FUXI_M3_BINDING_TAG);
}
STATIC EFI_STATUS FnuRunRecovery(UINT64 Raw,UINT8 *Page,UINTN Bytes,UINT64 Bridge,UINT32 App,BOOLEAN StorageStopped) {
  EFI_STATUS Result,ResetStatus;UINTN RecoveredBytes=0;CONST UINT8 *Recovered=NULL;
  UINT32 State,Stage;INT32 KeyMintStatus;
  if(!StorageStopped || !mRecoveryVersionOk || EFI_ERROR(mRecoveryStatus) ||
     mRecoveryWork==NULL || mRecoveryWork->State!=FkrPrepared) { mRecoveryStatus=EFI_NOT_READY;return mRecoveryStatus; }
  mRecoverySession=AllocateZeroPool(sizeof(*mRecoverySession));
  if(mRecoverySession==NULL) { mRecoveryStatus=EFI_OUT_OF_RESOURCES;return mRecoveryStatus; }
  Result=FseInitialize(&mRecoverySession->Exchange,Page,Raw,Bytes,Bridge,App,TRUE);
  if(!EFI_ERROR(Result)) {
    FKR_OPS Ops;
    Result=FkmInitialize(&mRecoverySession->Backend,App,Page,FKM_SHARED_BYTES,
                          FseExchange,&mRecoverySession->Exchange,TRUE,&Ops);
    if(!EFI_ERROR(Result)) {
      FNU_STAGE("m3-key-recovery");
      FnuLog(L"FUXIM3 RECOVERY begin: decrypt existing key; no persistence");
      mRecoveryAttempted=TRUE;
      Result=FkrRecoverExisting(mRecoveryWork,&Ops);
      State=(UINT32)mRecoveryWork->State;Stage=(UINT32)mRecoveryWork->Stage;
      KeyMintStatus=mRecoveryWork->KeyMintStatus;
      if(mRecoveryWork->State==FkrQuarantined || mRecoveryWork->State==FkrActive ||
         mRecoverySession->Backend.Quarantined || mRecoverySession->Exchange.State==FseQuarantined) {
        mRecoveryRetained=TRUE;
      } else {
        if(!EFI_ERROR(Result))Result=FkrGetRecovered(mRecoveryWork,&Recovered,&RecoveredBytes);
        // This candidate validates recovery only: do not hash/export the output.
        // Wipe it before permitting app/bridge cleanup; ICE/convert is later.
        ResetStatus=FkrReset(mRecoveryWork);
        if(EFI_ERROR(ResetStatus) || EFI_ERROR(FsePermitCleanup(&mRecoverySession->Exchange,&mRecoverySession->Backend))) {
          mRecoveryRetained=TRUE;Result=EFI_NOT_READY;
        }
      }
      FnuLog(L"FUXIM3 RECOVERY result=%r state=%u stage=%u km=%d bytes=%u retained=%u",
             Result,State,Stage,KeyMintStatus,(UINT32)RecoveredBytes,(UINT32)mRecoveryRetained);
      FnuLog(L"FUXIM3 RECOVERY fault=%u exchange=%u commands=%u resumes=%u",
             mRecoverySession->Backend.Fault,(UINT32)mRecoverySession->Exchange.State,
             (UINT32)mRecoverySession->Exchange.Calls,(UINT32)mRecoverySession->Exchange.Resumes);
      FnuLog(L"FUXIM3 RECOVERY response-header=%u status=%08x payload-bytes=%u wire-bytes=%u",
             (UINT32)mRecoverySession->Backend.ResponseHeaderSeen,
             mRecoverySession->Backend.ResponseStatus,
             mRecoverySession->Backend.ResponsePayloadBytes,
             mRecoverySession->Backend.ResponseWireBytes);
    }
  }
  if(!mRecoveryRetained) {
    ZeroMem(mRecoverySession,sizeof(*mRecoverySession));FreePool(mRecoverySession);mRecoverySession=NULL;
    FnuDropRecoveryInput();
  }
  mRecoveryStatus=Result;return Result;
}
#endif
