// SPDX-License-Identifier: BSD-2-Clause-Patent
// One read-only getKeyCharacteristics (0x2109) for the stored metadata key.
// Only the non-secret OS version/patch integers are reported.
#if FUXI_M3_CHARACTERISTICS_PROBE
#include "../FuxiDataProbeDxe/M3KeyMintBackend.h"
STATIC EFI_STATUS FnuProbeCharacteristics(FKM_CONTEXT *Backend, CONST FKR_WORK *Work) {
  EFI_STATUS Status; FKM_CHARACTERISTICS Chars;
  if(Backend==NULL || Work==NULL || Work->State!=FkrPrepared)return EFI_NOT_READY;
  FNU_STAGE("m3-characteristics");
  FnuLog(L"FUXIM3 CHARACTERISTICS begin once: read-only blob version fields");
  ZeroMem(&Chars,sizeof(Chars));
  // Any failed probe stops this session. The backend retains its registered
  // page/request and withholds partial version fields on response rejection.
  Status=FkmProbeCharacteristics(Backend,Work->Blob,Work->BlobBytes,
                                 Work->ApplicationId,Work->ApplicationIdBytes,&Chars);
  FnuLog(L"FUXIM3 CHARACTERISTICS result=%r status=%08x payload=%u wire=%u scanned=%u",
         Status,Backend->ResponseStatus,Backend->ResponsePayloadBytes,
         Backend->ResponseWireBytes,Chars.TagsScanned);
  FnuLog(L"FUXIM3 CHARACTERISTICS os-version=%u present=%u os-patch=%u present=%u",
         Chars.OsVersion,(UINT32)Chars.HaveOsVersion,
         Chars.OsPatchLevel,(UINT32)Chars.HaveOsPatchLevel);
  return Status;
}
#endif
