// SPDX-License-Identifier: BSD-2-Clause-Patent
// C1 reads a wrapped blob into a registered page. It never invokes a TA.
#if FUXI_M3_BRIDGE_BLOB
#define M3B_BLOB_BYTES 208U
STATIC CONST UINT8 mM3BlobExpectedSha[32] = {
  0x9a,0x57,0xf0,0x1a,0xf0,0xb8,0xc9,0x83,0x6c,0xdf,0x04,0xf9,0xab,0xc2,0xf8,0x3a,
  0xd2,0x1b,0xaf,0x94,0x52,0x7b,0x2c,0x80,0xb1,0x8b,0x06,0xf0,0x4a,0xb2,0x32,0x1e
};

STATIC VOID M3BHex(CHAR16 *Text, CONST UINT8 *Data, UINTN Bytes) {
  STATIC CONST CHAR16 Digits[] = L"0123456789abcdef";
  UINTN I;
  for (I = 0; I < Bytes; ++I) {
    Text[I * 2] = Digits[Data[I] >> 4];
    Text[I * 2 + 1] = Digits[Data[I] & 15];
  }
  Text[Bytes * 2] = 0;
}

STATIC EFI_STATUS FnuBridgeReadBlob(CONST FDP_DISK *Disk,
                                    CONST FDP_PARTITION *Metadata, VOID *Work,
                                    VOID *Page, UINTN Capacity,
                                    CONST UINT8 ExpectedSha[32]) {
  F2R_VOLUME *Volume = NULL;
  F2R_FILE *File = NULL;
  EFI_STATUS Status = EFI_INVALID_PARAMETER;
  UINTN Got = 0, I;
  UINT8 Version = 0, Digest[32], PageDigest[32];
  FNU_SHA256_CTX Hash;
  CHAR16 Hex[65];
  if (!Disk || !Metadata || !Work || !Page || Capacity != 8192 || !ExpectedSha)
    return Status;
  ZeroMem(Page, Capacity);
  Volume = AllocateZeroPool(sizeof(*Volume));
  File = AllocateZeroPool(sizeof(*File));
  if (!Volume || !File) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  Status = F2rPrepare(Disk, Metadata, Volume, Work, F2R_WORK_BYTES);
  FnuLog(L"FUXIM3 BLOB prepare=%r pack=%u feature=%08x", Status,
         Volume->SelectedPack, Volume->Features);
  if (EFI_ERROR(Status)) goto Done;
  Status = F2rLookup(Volume, "/vold/metadata_encryption/key/version", File,
                     Work, F2R_WORK_BYTES);
  if (EFI_ERROR(Status)) goto Done;
  if (File->Mode != 0x8000 || File->Bytes != 1) { Status = EFI_UNSUPPORTED; goto Done; }
  Status = F2rReadFile(File, 0, &Version, 1, &Got, Work, F2R_WORK_BYTES);
  if (EFI_ERROR(Status)) goto Done;
  if (Got != 1 || Version != '1') { Status = EFI_COMPROMISED_DATA; goto Done; }
  Status = F2rLookup(Volume, "/vold/metadata_encryption/key/keymaster_key_blob",
                     File, Work, F2R_WORK_BYTES);
  if (EFI_ERROR(Status)) goto Done;
  FnuLog(L"FUXIM3 BLOB file bytes=%lu mode=%04x inline=%u", File->Bytes,
         (UINT32)File->Mode, (UINT32)((File->Inline & 2) != 0));
  if (File->Mode != 0x8000 || File->Bytes != M3B_BLOB_BYTES) {
    Status = EFI_BAD_BUFFER_SIZE; goto Done;
  }
  // F2FS copies from its own bounded read workspace into the registered page.
  Status = F2rReadFile(File, 0, Page, M3B_BLOB_BYTES, &Got, Work, F2R_WORK_BYTES);
  if (EFI_ERROR(Status)) goto Done;
  if (Got != M3B_BLOB_BYTES) { Status = EFI_DEVICE_ERROR; goto Done; }
  FnuSha256Init(&Hash);
  FnuSha256Update(&Hash, Page, Got);
  FnuSha256Final(&Hash, Digest);
  for (I = 0; I < sizeof(Digest); ++I)
    if (Digest[I] != ExpectedSha[I]) { Status = EFI_CRC_ERROR; goto Done; }
  FnuCacheCiv(&mOps, Page, Capacity);
  FnuSha256Init(&Hash);
  FnuSha256Update(&Hash, Page, Got);
  FnuSha256Final(&Hash, PageDigest);
  for (I = 0; I < sizeof(Digest); ++I)
    if (PageDigest[I] != Digest[I]) { Status = EFI_CRC_ERROR; goto Done; }
  M3BHex(Hex, PageDigest, sizeof(PageDigest));
  FnuLog(L"FUXIM3 BLOB page-sha256=%s bytes=%u match=1", Hex, (UINT32)Got);
  M3BHex(Hex, Page, 32);
  FnuLog(L"FUXIM3 BLOB prefix32=%s", Hex);
  Status = EFI_SUCCESS;
Done:
  FnuLog(L"FUXIM3 BLOB read=%r; registered page, no TA, no decrypt", Status);
  if (EFI_ERROR(Status)) { ZeroMem(Page, Capacity); FnuCacheCiv(&mOps, Page, Capacity); }
  ZeroMem(Digest, sizeof(Digest));
  ZeroMem(PageDigest, sizeof(PageDigest));
  ZeroMem(Hex, sizeof(Hex));
  if (File) { ZeroMem(File, sizeof(*File)); FreePool(File); }
  if (Volume) { ZeroMem(Volume, sizeof(*Volume)); FreePool(Volume); }
  return Status;
}
#endif
