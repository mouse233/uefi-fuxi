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
  // Existing non-secret aconfig map observed in A17 TWRP: 10527 bytes.
  // Full hash is reported only after all non-inline blocks are read.
  STATIC CONST CHAR8 Path[]="/aconfig/maps/system.package.map";
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
#if FUXI_UFS_LUN4_KEYS
  {
    STATIC CONST UINT8 Expected[32] = {0x14,0xf3,0xd8,0x67,0x54,0x23,0x91,0x7e,0x38,0x3a,0x71,0xc9,0x36,0xf4,0xd9,0xa8,0x1a,0x29,0x48,0x0f,0x34,0xae,0x3c,0x55,0x0e,0x0f,0x4c,0x34,0xe5,0x3a,0x09,0x91};
    if (Offset != 10527 || CompareMem(Digest,Expected,sizeof(Expected)) != 0) {
      mM2Status=EFI_COMPROMISED_DATA;
      FnuLog(L"FUXIM2 pinned-file mismatch; stop before LUN4");
      goto Done;
    }
  }
#endif
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
