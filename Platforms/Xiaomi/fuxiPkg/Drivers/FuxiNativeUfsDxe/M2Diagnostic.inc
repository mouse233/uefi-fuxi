// SPDX-License-Identifier: BSD-2-Clause-Patent
// Included by the native UFS adapter; no independent transport or DMA owner.
#if FUXI_UFS_M2_FILES
STATIC EFI_STATUS mM2Status = EFI_NOT_READY;
STATIC EFI_STATUS M2Entry(VOID *Context, CONST CHAR8 *Name, UINTN Length,
                           UINT32 Inode, UINT8 Type) {
  UINTN *Count=Context,I,Limit=Length; CHAR8 Text[97];
  if (*Count>=16) return EFI_ABORTED;
  if (Limit>96) Limit=96;
  for (I=0; I<Limit; ++I) Text[I]=(Name[I]>=32 && Name[I]<127)?Name[I]:'?';
  Text[Limit]=0; ++*Count;
  FnuLog(L"FUXIM2 root[%u] nid=%u type=%u name=%a clipped=%u",
         (UINT32)*Count,Inode,(UINT32)Type,Text,(UINT32)(Limit!=Length));
  return EFI_SUCCESS;
}
STATIC VOID RunM2(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Metadata,
                   VOID *Work, VOID *Data) {
  F2R_VOLUME *Volume=NULL; F2R_FILE *File=NULL;
  UINTN Count=0,Bytes,Request,I; UINT64 Offset=0;
  FNU_SHA256_CTX Hash; UINT8 Digest[32]; CHAR16 Hex[65];
  STATIC CONST CHAR16 Digits[]=L"0123456789abcdef";
  // A small non-secret vold format-version file. Existence is not assumed;
  // Not Found is recorded without choosing a different file or claiming success.
  STATIC CONST CHAR8 Path[]="/vold/metadata_encryption/key/version";
  if (mPoisoned || !Metadata->Present) return;
  FNU_STAGE("m2-metadata");
  Volume=AllocateZeroPool(sizeof(*Volume)); File=AllocateZeroPool(sizeof(*File));
  if (!Volume || !File) { mM2Status=EFI_OUT_OF_RESOURCES; goto Done; }
  mM2Status=F2rPrepare(Disk,Metadata,Volume,Work,F2R_WORK_BYTES);
  FnuLog(L"FUXIM2 prepare=%r",mM2Status);
  FnuLog(L"FUXIM2 selected-pack=%u cp-flags=%08x",Volume->SelectedPack,Volume->CheckpointFlags);
  if (EFI_ERROR(mM2Status)) goto Done;
  FnuLog(L"FUXIM2 feature=%08x pack=%u cp-version=%lx journal=%u",
         Volume->Features,Volume->SelectedPack,Volume->CheckpointVersion,(UINT32)Volume->NatJournalCount);
  mM2Status=F2rLookup(Volume,"/",File,Work,F2R_WORK_BYTES);
  FnuLog(L"FUXIM2 root-open=%r",mM2Status);
  if (EFI_ERROR(mM2Status)) goto Done;
  mM2Status=F2rListDirectory(File,M2Entry,&Count,Work,F2R_WORK_BYTES);
  FnuLog(L"FUXIM2 root-list=%r entries=%u limit=16",mM2Status,(UINT32)Count);
  if (EFI_ERROR(mM2Status) && mM2Status!=EFI_ABORTED) goto Done;
  mM2Status=F2rLookup(Volume,Path,File,Work,F2R_WORK_BYTES);
  FnuLog(L"FUXIM2 lookup=%r path=%a",mM2Status,Path);
  if (EFI_ERROR(mM2Status)) goto Done;
  FnuLog(L"FUXIM2 file nid=%u bytes=%lu inline=%u",File->Inode,File->Bytes,(UINT32)((File->Inline&2)!=0));
  if (File->Mode!=0x8000 || File->Bytes>SIZE_1MB) { mM2Status=EFI_UNSUPPORTED; goto Done; }
  FnuSha256Init(&Hash);
  while (Offset<File->Bytes) {
    Request=(File->Bytes-Offset>4096)?4096:(UINTN)(File->Bytes-Offset);
    mM2Status=F2rReadFile(File,Offset,Data,Request,&Bytes,Work,F2R_WORK_BYTES);
    if (EFI_ERROR(mM2Status)) goto Done;
    if (Bytes!=Request) { mM2Status=EFI_DEVICE_ERROR; goto Done; }
    FnuSha256Update(&Hash,Data,Bytes); Offset+=Bytes;
  }
  FnuSha256Final(&Hash,Digest);
  for (I=0; I<32; ++I) { Hex[I*2]=Digits[Digest[I]>>4]; Hex[I*2+1]=Digits[Digest[I]&15]; }
  Hex[64]=0;
  FnuLog(L"FUXIM2 file-read=Success bytes=%lu",Offset);
  FnuLog(L"FUXIM2 file-sha256=%s",Hex);
Done:
  FnuLog(L"FUXIM2 result=%r read-bytes=%lu; no Android decryption",mM2Status,Offset);
  ZeroMem(Data,4096);
  if (File) { ZeroMem(File,sizeof(*File)); FreePool(File); }
  if (Volume) { ZeroMem(Volume,sizeof(*Volume)); FreePool(Volume); }
}
#endif
