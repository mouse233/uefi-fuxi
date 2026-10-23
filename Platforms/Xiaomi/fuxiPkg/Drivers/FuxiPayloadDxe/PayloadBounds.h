/** @file
  Bounds and identity checks for the opt-in fuxi FAT diagnostic payload.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#ifndef FUXI_PAYLOAD_BOUNDS_H_
#define FUXI_PAYLOAD_BOUNDS_H_

#include <Base.h>

#define FUXI_PAYLOAD_SIZE  (192U * 1024U * 1024U)
#define FUXI_INITRD_LIMIT  (224U * 1024U * 1024U)

STATIC
BOOLEAN
FuxiContainsRange (UINT64 Base, UINT64 Size, UINT64 Address, UINT64 Length)
{
  if ((Size == 0) || (Length == 0) || (Size > MAX_UINT64 - Base) || (Address < Base)) {
    return FALSE;
  }

  return ((Address - Base < Size) && (Length <= Size - (Address - Base)));
}

STATIC
UINT32
FuxiLe16 (CONST UINT8 *Bytes)
{
  return (UINT32)Bytes[0] | ((UINT32)Bytes[1] << 8);
}

STATIC
UINT32
FuxiLe32 (CONST UINT8 *Bytes)
{
  return FuxiLe16 (Bytes) | (FuxiLe16 (Bytes + 2) << 16);
}

STATIC
BOOLEAN
FuxiBytesEqual (CONST UINT8 *Left, CONST CHAR8 *Right, UINTN Length)
{
  UINTN Index;
  for (Index = 0; Index < Length; Index++) {
    if (Left[Index] != (UINT8)Right[Index]) {
      return FALSE;
    }
  }

  return TRUE;
}

// Discovery tag plus a structural FAT16 check. Identity is diagnostic, not
// authentication; a duplicate candidate is refused by the caller.
//
// This used to be a byte-exact BPB of the 4 MiB diagnostic image that
// tools/make_fuxi_payload.py emitted. The real payload is the 192 MiB volume the
// unixnu driver makes with mformat, whose geometry mtools chooses itself
// (reserved sectors 32, two FATs, four sectors per cluster, the FS type field
// left blank), so an exact BPB cannot be written down. What replaces it is the
// one identity the size pins: the BPB must describe exactly FUXI_PAYLOAD_SIZE
// bytes. The OEM name carries the tag, which the boot-image packager writes.
// Remaining is checked before reading any BPB field.
STATIC
BOOLEAN
FuxiPayloadHeader (CONST UINT8 *Bytes, UINTN Remaining)
{
  UINT32  Total;
  UINT8   PerCluster;

  if ((Remaining < FUXI_PAYLOAD_SIZE) ||
      (Bytes[0] != 0xEB) || (Bytes[2] != 0x90) ||
      !FuxiBytesEqual (Bytes + 3, "FUXIPAYL", 8)) {
    return FALSE;
  }

  PerCluster = Bytes[13];
  if ((FuxiLe16 (Bytes + 11) != 512) || (PerCluster == 0) || (PerCluster > 128) ||
      ((PerCluster & (PerCluster - 1)) != 0) || (FuxiLe16 (Bytes + 14) == 0) ||
      (FuxiLe16 (Bytes + 14) > 64) || (FuxiLe16 (Bytes + 16) < 1) ||
      (FuxiLe16 (Bytes + 16) > 2) || (Bytes[21] != 0xF8) ||
      (Bytes[510] != 0x55) || (Bytes[511] != 0xAA)) {
    return FALSE;
  }

  Total = FuxiLe16 (Bytes + 19);
  if (Total == 0) {
    Total = FuxiLe32 (Bytes + 32);
  }

  return ((UINT64)Total * 512 == FUXI_PAYLOAD_SIZE);
}

// ABL concatenates vendor ramdisk bytes without sector alignment. Search every
// byte, never assuming the FAT starts at initrd-start or a 512-byte boundary.
// Ambiguous matches fail closed. The caller must validate the physical span.
STATIC
BOOLEAN
FuxiFindPayload (CONST UINT8 *Bytes, UINTN Length, UINTN *PayloadOffset)
{
  UINTN   Offset;
  UINTN   Found;
  BOOLEAN Present;

  if ((Length < FUXI_PAYLOAD_SIZE) || (Length > FUXI_INITRD_LIMIT)) {
    return FALSE;
  }

  Found = 0;
  Present = FALSE;
  for (Offset = 0; Offset <= Length - FUXI_PAYLOAD_SIZE; Offset++) {
    if ((Bytes[Offset] != 0xEB) || !FuxiPayloadHeader (Bytes + Offset, Length - Offset)) {
      continue;
    }

    if (Present) {
      return FALSE;
    }

    Found = Offset;
    Present = TRUE;
  }

  if (Present) {
    *PayloadOffset = Found;
  }

  return Present;
}

#endif
