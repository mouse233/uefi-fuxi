// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DataReadOnly.h"

STATIC UINT32 Le32(CONST UINT8 *P) {
  return (UINT32)P[0] | ((UINT32)P[1] << 8) |
         ((UINT32)P[2] << 16) | ((UINT32)P[3] << 24);
}
STATIC UINT64 Le64(CONST UINT8 *P) {
  return (UINT64)Le32(P) | ((UINT64)Le32(P + 4) << 32);
}
STATIC BOOLEAN Zero(CONST UINT8 *P, UINTN Bytes) {
  UINTN I;
  for (I = 0; I < Bytes; ++I) if (P[I] != 0) return FALSE;
  return TRUE;
}
STATIC BOOLEAN NameIs(CONST UINT8 *P, CONST CHAR8 *Name) {
  UINTN I;
  for (I = 0; Name[I] != 0; ++I) {
    if (I >= 36 || P[2 * I] != (UINT8)Name[I] || P[2 * I + 1] != 0) return FALSE;
  }
  return Zero(P + 2 * I, (36 - I) * 2);
}
STATIC BOOLEAN DiskValid(CONST FDP_DISK *Disk) {
  return Disk != NULL && Disk->Read != NULL &&
         Disk->LastBlock != MAX_UINT64 && Disk->LastBlock >= 5 &&
         Disk->BlockSize >= 512 && Disk->BlockSize <= FDP_MAX_BLOCK_SIZE &&
         (Disk->BlockSize & (Disk->BlockSize - 1)) == 0;
}
UINT32 FdpCrc32(CONST VOID *Data, UINTN Bytes) {
  CONST UINT8 *P = Data;
  UINT32 Crc = 0xffffffffU;
  UINTN I;
  UINTN Bit;
  for (I = 0; I < Bytes; ++I) {
    Crc ^= P[I];
    for (Bit = 0; Bit < 8; ++Bit)
      Crc = (Crc >> 1) ^ ((Crc & 1) ? 0xedb88320U : 0);
  }
  return ~Crc;
}
EFI_STATUS FdpReadGpt(CONST FDP_DISK *Disk, VOID *Scratch, UINTN ScratchBytes,
                      FDP_PARTITIONS *Partitions) {
  UINT8 *P = Scratch;
  UINT32 HeaderBytes, HeaderCrc, Count, EntryBytes, EntriesCrc;
  UINT64 FirstUsable, LastUsable, EntriesLba, ArrayBytes, ArrayBlocks;
  UINTN I, J;
  EFI_STATUS Status;
  FDP_PARTITIONS Found = {0};
  if (Partitions == NULL) return EFI_INVALID_PARAMETER;
  *Partitions = Found;
  if (!DiskValid(Disk) || P == NULL || ScratchBytes < FDP_SCRATCH_BYTES)
    return EFI_INVALID_PARAMETER;
  Status = Disk->Read(Disk->Context, 1, 1, P);
  if (EFI_ERROR(Status)) return Status;
  // Read buffers are untrusted; do not use packed-struct/unaligned dereferences.
  if (Le64(P) != 0x5452415020494645ULL || Le32(P + 8) != 0x00010000U ||
      Le32(P + 20) != 0) return EFI_VOLUME_CORRUPTED;
  HeaderBytes = Le32(P + 12);
  if (HeaderBytes < 92 || HeaderBytes > Disk->BlockSize) return EFI_VOLUME_CORRUPTED;
  HeaderCrc = Le32(P + 16);
  P[16] = P[17] = P[18] = P[19] = 0;
  if (FdpCrc32(P, HeaderBytes) != HeaderCrc) return EFI_CRC_ERROR;
  if (Le64(P + 24) != 1 || Le64(P + 32) != Disk->LastBlock || Zero(P + 56, 16))
    return EFI_VOLUME_CORRUPTED;
  FirstUsable = Le64(P + 40);
  LastUsable = Le64(P + 48);
  EntriesLba = Le64(P + 72);
  Count = Le32(P + 80);
  EntryBytes = Le32(P + 84);
  EntriesCrc = Le32(P + 88);
  if (Count == 0 || Count > 128 || EntryBytes < 128 || EntryBytes > 1024 ||
      (EntryBytes & 7) != 0) return EFI_UNSUPPORTED;
  ArrayBytes = (UINT64)Count * EntryBytes;
  ArrayBlocks = (ArrayBytes + Disk->BlockSize - 1) / Disk->BlockSize;
  if (ArrayBytes > FDP_MAX_GPT_BYTES || EntriesLba < 2 ||
      EntriesLba > Disk->LastBlock || ArrayBlocks > Disk->LastBlock - EntriesLba ||
      FirstUsable < EntriesLba + ArrayBlocks || FirstUsable > LastUsable ||
      LastUsable >= Disk->LastBlock || Disk->LastBlock - LastUsable <= ArrayBlocks)
    return EFI_VOLUME_CORRUPTED;
  Status = Disk->Read(Disk->Context, EntriesLba, (UINTN)ArrayBlocks, P);
  if (EFI_ERROR(Status)) return Status;
  if (FdpCrc32(P, (UINTN)ArrayBytes) != EntriesCrc) return EFI_CRC_ERROR;
  for (I = 0; I < Count; ++I) {
    CONST UINT8 *Entry = P + I * EntryBytes;
    FDP_PARTITION *Selected = NULL;
    UINT64 First, Last;
    if (Zero(Entry, 16)) continue;
    First = Le64(Entry + 32);
    Last = Le64(Entry + 40);
    if (Zero(Entry + 16, 16) || First < FirstUsable || Last > LastUsable || First > Last)
      return EFI_VOLUME_CORRUPTED;
    for (J = 0; J < I; ++J) {
      CONST UINT8 *Other = P + J * EntryBytes;
      UINTN K;
      BOOLEAN SameGuid = TRUE;
      if (Zero(Other, 16)) continue;
      if (First <= Le64(Other + 40) && Le64(Other + 32) <= Last)
        return EFI_VOLUME_CORRUPTED;
      for (K = 0; K < 16; ++K)
        if (Entry[16 + K] != Other[16 + K]) SameGuid = FALSE;
      if (SameGuid) return EFI_VOLUME_CORRUPTED;
    }
    if (NameIs(Entry + 56, "metadata")) Selected = &Found.Metadata;
    if (NameIs(Entry + 56, "userdata")) Selected = &Found.Userdata;
    if (Selected != NULL) {
      if (Selected->Present) return EFI_VOLUME_CORRUPTED;
      Selected->First = First;
      Selected->Last = Last;
      Selected->Present = TRUE;
    }
  }
  // No partially validated partition identity escapes on any earlier failure.
  *Partitions = Found;
  return (Found.Metadata.Present || Found.Userdata.Present) ? EFI_SUCCESS : EFI_NOT_FOUND;
}
EFI_STATUS FdpReadPartition(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Partition,
                            UINT64 RelativeLba, UINTN Blocks, VOID *Buffer) {
  UINT64 Count;
  if (!DiskValid(Disk) || Partition == NULL || Buffer == NULL || Blocks == 0 ||
      !Partition->Present || Partition->First > Partition->Last ||
      Partition->Last > Disk->LastBlock || Blocks > FDP_MAX_GPT_BYTES / Disk->BlockSize)
    return EFI_INVALID_PARAMETER;
  Count = Partition->Last - Partition->First + 1;
  if (RelativeLba >= Count || Blocks > Count - RelativeLba) return EFI_BAD_BUFFER_SIZE;
  return Disk->Read(Disk->Context, Partition->First + RelativeLba, Blocks, Buffer);
}
EFI_STATUS FdpInspectF2fs(CONST VOID *First4k, UINTN Bytes,
                         UINT64 PartitionBytes, FDP_F2FS_GEOMETRY *Geometry) {
  CONST UINT8 *P;
  UINT32 LogSector, LogPerBlock, Cp, Sit, Nat, Ssa, Main;
  UINT64 Blocks;
  FDP_F2FS_GEOMETRY Found = {0};
  if (Geometry == NULL) return EFI_INVALID_PARAMETER;
  *Geometry = Found;
  if (First4k == NULL || Bytes < 4096) return EFI_INVALID_PARAMETER;
  P = (CONST UINT8 *)First4k + 1024;
  if (Le32(P) != 0xf2f52010U) return EFI_NOT_FOUND;
  LogSector = Le32(P + 8);
  LogPerBlock = Le32(P + 12);
  if (LogSector < 9 || LogSector > 12 || LogPerBlock > 3 ||
      LogSector + LogPerBlock != 12 || Le32(P + 16) != 12 || Le32(P + 20) != 9)
    return EFI_UNSUPPORTED;
  Blocks = Le64(P + 36);
  Cp = Le32(P + 76); Sit = Le32(P + 80); Nat = Le32(P + 84);
  Ssa = Le32(P + 88); Main = Le32(P + 92);
  if (Blocks < 1024 || Blocks > PartitionBytes / 4096 ||
      Cp < 2 || Sit <= Cp || Nat <= Sit || Ssa <= Nat || Main <= Ssa ||
      Main >= Blocks || Le32(P + 96) < 3 || Le32(P + 100) != 1 || Le32(P + 104) != 2)
    return EFI_VOLUME_CORRUPTED;
  Found.Blocks = Blocks;
  Found.RootInode = Le32(P + 96);
  Found.CheckpointBlock = Cp;
  Found.NatBlock = Nat;
  Found.MainBlock = Main;
  *Geometry = Found;
  return EFI_SUCCESS;
}
EFI_STATUS FdpMakeAvailabilityQuery(UINT32 Subject, BOOLEAN Smc64, UINT64 Args[8]) {
  UINTN I;
  if (Args == NULL) return EFI_INVALID_PARAMETER;
  for (I = 0; I < 8; ++I) Args[I] = 0;
  if (Subject != FDP_SCM_INFO_AVAIL && Subject != FDP_SCM_ICE_SET &&
      Subject != FDP_SCM_ICE_CLEAR && Subject != FDP_SCM_ICE_DERIVE)
    return EFI_ACCESS_DENIED;
  Args[0] = Smc64 ? 0xc2000601U : 0x82000601U; // Fast INFO/IS_CALL_AVAIL only.
  Args[1] = 1; // One scalar argument; no shared memory or key material.
  Args[2] = Subject;
  return EFI_SUCCESS;
}
EFI_STATUS FdpDecodeAvailability(UINT64 Result0, UINT64 Result1, BOOLEAN *Available) {
  if (Available == NULL) return EFI_INVALID_PARAMETER;
  *Available = FALSE;
  // Interrupted/busy/unsupported and malformed results remain indeterminate.
  if (Result0 != 0) return EFI_NOT_READY;
  if (Result1 > 1) return EFI_PROTOCOL_ERROR;
  *Available = (BOOLEAN)(Result1 == 1);
  return EFI_SUCCESS;
}
