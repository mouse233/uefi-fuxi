// SPDX-License-Identifier: BSD-2-Clause-Patent
// Included by the native UFS adapter; no independent transport or DMA owner.
// Metadata key-directory discovery: read-only listing and hashing of the
// KeyMint storage-key files under /vold/metadata_encryption. It opens regular
// files only, never uses a key, never calls SMC/TA and never decrypts.
#if FUXI_M3_METADATA_KEY
#define M3K_MAX_ENTRIES 6U
#define M3K_MAX_FILE_BYTES 8192U
#define M3K_MAX_HASHED 3U
typedef struct {
  CHAR8 Name[M3K_MAX_ENTRIES][256];
  UINTN Length[M3K_MAX_ENTRIES];
  UINT32 Inode[M3K_MAX_ENTRIES];
  UINT8 Type[M3K_MAX_ENTRIES];
  UINTN Count;
} M3K_LIST;

STATIC EFI_STATUS mM3KeyStatus = EFI_NOT_READY;
STATIC UINTN mM3KeyFiles;

// Directory iteration must not read blocks with the same workspace, so names
// are collected first and opened only after F2rListDirectory returns.
STATIC EFI_STATUS M3KCollect(VOID *Context, CONST CHAR8 *Name, UINTN Length,
                             UINT32 Inode, UINT8 Type) {
  M3K_LIST *List = Context;
  UINTN I;
  if (List->Count >= M3K_MAX_ENTRIES) return EFI_ABORTED;
  if (Length == 0 || Length > 255) return EFI_VOLUME_CORRUPTED;
  if ((Length == 1 && Name[0] == '.') ||
      (Length == 2 && Name[0] == '.' && Name[1] == '.')) return EFI_SUCCESS;
  for (I = 0; I < Length; ++I)
    if (Name[I] < 32 || Name[I] > 126) return EFI_VOLUME_CORRUPTED;
  for (I = 0; I < Length; ++I) List->Name[List->Count][I] = Name[I];
  // Rows are reused across listings; without this terminator a shorter name
  // keeps the tail of the previous one in the log.
  List->Name[List->Count][Length] = 0;
  List->Length[List->Count] = Length;
  List->Inode[List->Count] = Inode;
  List->Type[List->Count] = Type;
  ++List->Count;
  return EFI_SUCCESS;
}

STATIC VOID M3KHex(CHAR16 Hex[65], CONST UINT8 Digest[32]) {
  STATIC CONST CHAR16 Digits[] = L"0123456789abcdef";
  UINTN I;
  for (I = 0; I < 32; ++I) {
    Hex[I * 2] = Digits[Digest[I] >> 4];
    Hex[I * 2 + 1] = Digits[Digest[I] & 15];
  }
  Hex[64] = 0;
}

// Files above the limit are reported by size only: this diagnostic never
// streams an unbounded blob into the console or the cached report.
STATIC EFI_STATUS M3KHashFile(CONST F2R_VOLUME *Volume, CONST CHAR8 *Path,
                              VOID *Data, VOID *Work) {
  F2R_FILE File;
  FNU_SHA256_CTX Hash;
  UINT8 Digest[32], Sample[16];
  CHAR16 Hex[65];
  UINTN Read, Offset = 0, I;
  EFI_STATUS Status;
  Status = F2rLookup(Volume, Path, &File, Work, F2R_WORK_BYTES);
  if (EFI_ERROR(Status)) {
    FnuLog(L"FUXIM3 KEY file=%a open=%r", Path, Status);
    return Status;
  }
  FnuLog(L"FUXIM3 KEY file=%a mode=%04x bytes=%lu inline=%u", Path,
         (UINT32)File.Mode, File.Bytes, (UINT32)((File.Inline & 2) != 0));
  if (File.Mode != 0x8000) return EFI_UNSUPPORTED;
  if (File.Bytes > M3K_MAX_FILE_BYTES) {
    FnuLog(L"FUXIM3 KEY oversize=%a bytes=%lu limit=%u; not read", Path,
           File.Bytes, (UINT32)M3K_MAX_FILE_BYTES);
    return EFI_BAD_BUFFER_SIZE;
  }
  FnuSha256Init(&Hash);
  while (Offset < File.Bytes) {
    UINTN Request = (UINTN)(File.Bytes - Offset) > 4096 ? 4096 : (UINTN)(File.Bytes - Offset);
    Status = F2rReadFile(&File, Offset, Data, Request, &Read, Work, F2R_WORK_BYTES);
    if (EFI_ERROR(Status) || Read != Request) {
      FnuLog(L"FUXIM3 KEY read=%a result=%r bytes=%u", Path, Status, (UINT32)Read);
      ZeroMem(Data, 4096);
      return EFI_DEVICE_ERROR;
    }
    FnuSha256Update(&Hash, Data, Read);
    Offset += Read;
  }
  FnuSha256Final(&Hash, Digest);
  M3KHex(Hex, Digest);
  FnuLog(L"FUXIM3 KEY read=Success bytes=%lu", Offset);
  FnuLog(L"FUXIM3 KEY sha256=%a %s", Path, Hex);
  // The version file is public, small and identifies the blob format version.
  if (File.Bytes > 0 && File.Bytes <= sizeof(Sample)) {
    Status = F2rReadFile(&File, 0, Sample, (UINTN)File.Bytes, &Read, Work, F2R_WORK_BYTES);
    if (!EFI_ERROR(Status) && Read == File.Bytes) {
      CHAR16 Text[64];
      UINTN At = 0;
      for (I = 0; I < Read && At + 3 < ARRAY_SIZE(Text); ++I)
        At += (UINTN)UnicodeSPrint(Text + At, (ARRAY_SIZE(Text) - At) * sizeof(CHAR16),
                                   L"%02x", (UINT32)Sample[I]);
      Text[At] = 0;
      FnuLog(L"FUXIM3 KEY prefix=%a %s", Path, Text);
    }
  }
  ZeroMem(Sample, sizeof(Sample));
  ZeroMem(Data, 4096);
  return EFI_SUCCESS;
}

STATIC VOID RunM3Key(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Metadata,
                     VOID *Work, VOID *Data) {
  F2R_VOLUME *Volume = NULL;
  F2R_FILE *Dir = NULL;
  M3K_LIST *List = NULL;
  CHAR8 Path[512];
  UINTN I, At, Hashed = 0;
  EFI_STATUS Status;
  // Fixed, non-secret locations from the A17 TWRP metadata layout.
  STATIC CONST CHAR8 VoldPath[] = "/vold";
  STATIC CONST CHAR8 EncPath[] = "/vold/metadata_encryption";
  STATIC CONST CHAR8 KeyPath[] = "/vold/metadata_encryption/key";
  if (mPoisoned || !Metadata->Present) return;
  FNU_STAGE("m3-key-discovery");
  Volume = AllocateZeroPool(sizeof(*Volume));
  Dir = AllocateZeroPool(sizeof(*Dir));
  List = AllocateZeroPool(sizeof(*List));
  if (!Volume || !Dir || !List) { mM3KeyStatus = EFI_OUT_OF_RESOURCES; goto Done; }
  mM3KeyStatus = F2rPrepare(Disk, Metadata, Volume, Work, F2R_WORK_BYTES);
  FnuLog(L"FUXIM3 KEY prepare=%r pack=%u feature=%08x", mM3KeyStatus,
         Volume->SelectedPack, Volume->Features);
  if (EFI_ERROR(mM3KeyStatus)) goto Done;
  Status = F2rLookup(Volume, VoldPath, Dir, Work, F2R_WORK_BYTES);
  FnuLog(L"FUXIM3 KEY dir=%a open=%r", VoldPath, Status);
  if (EFI_ERROR(Status) || Dir->Mode != 0x4000) { mM3KeyStatus = EFI_NOT_FOUND; goto Done; }
  List->Count = 0;
  Status = F2rListDirectory(Dir, M3KCollect, List, Work, F2R_WORK_BYTES);
  FnuLog(L"FUXIM3 KEY dir=%a list=%r entries=%u limit=%u", VoldPath, Status,
         (UINT32)List->Count, (UINT32)M3K_MAX_ENTRIES);
  if (EFI_ERROR(Status) && Status != EFI_ABORTED) { mM3KeyStatus = Status; goto Done; }
  Status = F2rLookup(Volume, EncPath, Dir, Work, F2R_WORK_BYTES);
  FnuLog(L"FUXIM3 KEY dir=%a open=%r", EncPath, Status);
  if (EFI_ERROR(Status) || Dir->Mode != 0x4000) { mM3KeyStatus = EFI_NOT_FOUND; goto Done; }
  List->Count = 0;
  Status = F2rListDirectory(Dir, M3KCollect, List, Work, F2R_WORK_BYTES);
  FnuLog(L"FUXIM3 KEY dir=%a list=%r entries=%u limit=%u", EncPath, Status,
         (UINT32)List->Count, (UINT32)M3K_MAX_ENTRIES);
  if (EFI_ERROR(Status) && Status != EFI_ABORTED) { mM3KeyStatus = Status; goto Done; }
  for (I = 0; I < List->Count; ++I)
    FnuLog(L"FUXIM3 KEY entry=%a nid=%u type=%u", List->Name[I],
           List->Inode[I], (UINT32)List->Type[I]);
  Status = F2rLookup(Volume, KeyPath, Dir, Work, F2R_WORK_BYTES);
  FnuLog(L"FUXIM3 KEY key-path=%a open=%r mode=%04x", KeyPath, Status,
         (UINT32)(EFI_ERROR(Status) ? 0 : Dir->Mode));
  if (EFI_ERROR(Status)) { mM3KeyStatus = Status; goto Done; }
  if (Dir->Mode == 0x8000) {
    mM3KeyStatus = M3KHashFile(Volume, KeyPath, Data, Work);
    if (!EFI_ERROR(mM3KeyStatus)) { ++Hashed; ++mM3KeyFiles; }
    goto Done;
  }
  if (Dir->Mode != 0x4000) { mM3KeyStatus = EFI_UNSUPPORTED; goto Done; }
  List->Count = 0;
  Status = F2rListDirectory(Dir, M3KCollect, List, Work, F2R_WORK_BYTES);
  FnuLog(L"FUXIM3 KEY dir=%a list=%r entries=%u limit=%u", KeyPath, Status,
         (UINT32)List->Count, (UINT32)M3K_MAX_ENTRIES);
  if (EFI_ERROR(Status) && Status != EFI_ABORTED) { mM3KeyStatus = Status; goto Done; }
  for (I = 0; I < List->Count; ++I) {
    FnuLog(L"FUXIM3 KEY entry=%a nid=%u type=%u", List->Name[I],
           List->Inode[I], (UINT32)List->Type[I]);
    if (List->Type[I] != 1 || Hashed >= M3K_MAX_HASHED) continue;
    At = 0;
    while (KeyPath[At] != 0 && At + 2 < sizeof(Path)) { Path[At] = KeyPath[At]; ++At; }
    if (At + 1 >= sizeof(Path)) { mM3KeyStatus = EFI_BUFFER_TOO_SMALL; goto Done; }
    Path[At++] = '/';
    for (UINTN J = 0; J < List->Length[I] && At + 1 < sizeof(Path); ++J) Path[At++] = List->Name[I][J];
    Path[At] = 0;
    Status = M3KHashFile(Volume, Path, Data, Work);
    if (!EFI_ERROR(Status)) { ++Hashed; ++mM3KeyFiles; }
  }
  mM3KeyStatus = EFI_SUCCESS;
Done:
  FnuLog(L"FUXIM3 KEY result=%r hashed=%u total=%u; no key use, no SMC, no decrypt",
         mM3KeyStatus, (UINT32)Hashed, (UINT32)mM3KeyFiles);
  ZeroMem(Data, 4096);
  if (List) { ZeroMem(List, sizeof(*List)); FreePool(List); }
  if (Dir) { ZeroMem(Dir, sizeof(*Dir)); FreePool(Dir); }
  if (Volume) { ZeroMem(Volume, sizeof(*Volume)); FreePool(Volume); }
}
#endif
