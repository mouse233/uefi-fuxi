/** @file
  Publish only the opt-in FAT diagnostic payload as read-only BlockIo.

  This driver does not add RAM to GCD, start vendor hardware, or enable
  DarwinBoot. Both FDT and initrd must fit in the existing mapped, reserved
  Kernel descriptor. An invalid/unmapped argument leaves the menu available.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/FdtLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MemoryMapLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>
#include "PayloadBounds.h"

#define FDT_HEADER_BYTES  40
#define FDT_SIZE_LIMIT    (2U * 1024U * 1024U)

#pragma pack(1)
typedef struct {
  VENDOR_DEVICE_PATH        Vendor;
  EFI_DEVICE_PATH_PROTOCOL  End;
} PAYLOAD_DEVICE_PATH;
#pragma pack()

STATIC PAYLOAD_DEVICE_PATH mDevicePath = {
  {
    { HARDWARE_DEVICE_PATH, HW_VENDOR_DP, { sizeof (VENDOR_DEVICE_PATH), 0 } },
    { 0xBF1816A2, 0x090B, 0x4B20, { 0xA5, 0xDD, 0x23, 0xB4, 0x31, 0x6F, 0xA8, 0x47 } }
  },
  { END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, { sizeof (EFI_DEVICE_PATH_PROTOCOL), 0 } }
};

STATIC UINT8               *mPayload;
STATIC EFI_BLOCK_IO_MEDIA  mMedia;

STATIC EFI_STATUS EFIAPI
PayloadReset (EFI_BLOCK_IO_PROTOCOL *This, BOOLEAN ExtendedVerification)
{
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI
PayloadRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId, EFI_LBA Lba, UINTN BufferSize, VOID *Buffer)
{
  if (MediaId != mMedia.MediaId) {
    return EFI_MEDIA_CHANGED;
  }

  if (BufferSize == 0) {
    return EFI_SUCCESS;
  }

  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((BufferSize % 512) != 0) {
    return EFI_BAD_BUFFER_SIZE;
  }

  if ((Lba > mMedia.LastBlock) || (BufferSize / 512 > mMedia.LastBlock + 1 - Lba)) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (Buffer, mPayload + (UINTN)Lba * 512, BufferSize);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI
PayloadWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId, EFI_LBA Lba, UINTN BufferSize, VOID *Buffer)
{
  return EFI_WRITE_PROTECTED;
}

STATIC EFI_STATUS EFIAPI
PayloadFlush (EFI_BLOCK_IO_PROTOCOL *This)
{
  return EFI_SUCCESS;
}

STATIC EFI_BLOCK_IO_PROTOCOL mBlockIo = {
  EFI_BLOCK_IO_PROTOCOL_REVISION, &mMedia,
  PayloadReset, PayloadRead, PayloadWrite, PayloadFlush
};

STATIC BOOLEAN
InsideKernel (UINT64 Address, UINT64 Length)
{
  EFI_MEMORY_REGION_DESCRIPTOR *Regions;
  UINT8                         Count;
  UINTN                         Index;

  GetMemoryMap (&Regions, &Count);
  for (Index = 0; Index < Count; Index++) {
    // This is the captured ABL load window, not arbitrary RAM or MMIO.
    if ((AsciiStrCmp (Regions[Index].Name, "Kernel") == 0) &&
        (Regions[Index].Address == 0xA8000000) && (Regions[Index].Length == 0x10000000) &&
        (Regions[Index].ResourceType == SYS_MEM) &&
        (Regions[Index].MemoryType == EfiReservedMemoryType) &&
        (Regions[Index].HobOption == AddMem)) {
      return FuxiContainsRange (Regions[Index].Address, Regions[Index].Length, Address, Length);
    }
  }

  return FALSE;
}

EFI_STATUS EFIAPI
FuxiPayloadDxeEntry (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_HOB_GUID_TYPE  *Hob;
  UINT64             Dtb;
  UINT32             DtbSize;
  VOID              *Fdt;
  INT32              Chosen;
  INT32              StartLength;
  INT32              EndLength;
  CONST VOID        *StartProp;
  CONST VOID        *EndProp;
  UINT64             Start;
  UINT64             End;
  UINTN              Offset;
  EFI_HANDLE         Handle;
  EFI_STATUS         Status;

  Hob = GetFirstGuidHob (&gSiliciumEntryArgHobGuid);
  if ((Hob == NULL) || (GET_GUID_HOB_DATA_SIZE (Hob) < sizeof (UINT64))) {
    DEBUG ((DEBUG_WARN, "FUXIPAY: no valid entry-argument HOB\n"));
    return EFI_SUCCESS;
  }

  Dtb = ReadUnaligned64 (GET_GUID_HOB_DATA (Hob));
  DEBUG ((DEBUG_WARN, "FUXIPAY: entry x0=0x%lx\n", Dtb));
  if (((Dtb & 3) != 0) || !InsideKernel (Dtb, FDT_HEADER_BYTES)) {
    DEBUG ((DEBUG_WARN, "FUXIPAY: FDT header outside mapped reserved Kernel window; skipped\n"));
    return EFI_SUCCESS;
  }

  if (SwapBytes32 (ReadUnaligned32 ((VOID *)(UINTN)Dtb)) != 0xD00DFEED) {
    return EFI_SUCCESS;
  }

  DtbSize = SwapBytes32 (ReadUnaligned32 ((VOID *)(UINTN)(Dtb + 4)));
  if ((DtbSize < FDT_HEADER_BYTES) || (DtbSize > FDT_SIZE_LIMIT) || !InsideKernel (Dtb, DtbSize)) {
    DEBUG ((DEBUG_WARN, "FUXIPAY: FDT size/range rejected\n"));
    return EFI_SUCCESS;
  }

  // Parse a bounded private copy; leave the raw entry HOB and original DT alone.
  Fdt = AllocateCopyPool (DtbSize, (VOID *)(UINTN)Dtb);
  if (Fdt == NULL) {
    return EFI_SUCCESS;
  }

  if (FdtCheckHeader (Fdt) != 0) {
    FreePool (Fdt);
    return EFI_SUCCESS;
  }

  Chosen = FdtPathOffset (Fdt, "/chosen");
  if (Chosen < 0) {
    FreePool (Fdt);
    return EFI_SUCCESS;
  }

  StartProp = FdtGetProp (Fdt, Chosen, "linux,initrd-start", &StartLength);
  EndProp = FdtGetProp (Fdt, Chosen, "linux,initrd-end", &EndLength);
  if ((StartProp == NULL) || (EndProp == NULL) ||
      ((StartLength != 4) && (StartLength != 8)) || ((EndLength != 4) && (EndLength != 8))) {
    FreePool (Fdt);
    DEBUG ((DEBUG_WARN, "FUXIPAY: no valid initrd in /chosen\n"));
    return EFI_SUCCESS;
  }

  Start = (StartLength == 8) ? SwapBytes64 (ReadUnaligned64 (StartProp)) : SwapBytes32 (ReadUnaligned32 (StartProp));
  End = (EndLength == 8) ? SwapBytes64 (ReadUnaligned64 (EndProp)) : SwapBytes32 (ReadUnaligned32 (EndProp));
  FreePool (Fdt);
  if ((End <= Start) || (End - Start > FUXI_INITRD_LIMIT) || !InsideKernel (Start, End - Start)) {
    DEBUG ((DEBUG_WARN, "FUXIPAY: initrd 0x%lx..0x%lx outside allowed range\n", Start, End));
    return EFI_SUCCESS;
  }

  if (!FuxiFindPayload ((UINT8 *)(UINTN)Start, (UINTN)(End - Start), &Offset)) {
    DEBUG ((DEBUG_WARN, "FUXIPAY: no unique diagnostic FAT in initrd 0x%lx..0x%lx\n", Start, End));
    return EFI_SUCCESS;
  }

  mPayload = AllocateCopyPool (FUXI_PAYLOAD_SIZE, (VOID *)(UINTN)(Start + Offset));
  if (mPayload == NULL) {
    return EFI_SUCCESS;
  }

  mMedia.MediaId = 1;
  mMedia.MediaPresent = TRUE;
  mMedia.ReadOnly = TRUE;
  mMedia.BlockSize = 512;
  mMedia.IoAlign = 1;
  mMedia.LastBlock = FUXI_PAYLOAD_SIZE / 512 - 1;
  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle, &gEfiDevicePathProtocolGuid, &mDevicePath,
                  &gEfiBlockIoProtocolGuid, &mBlockIo, NULL);
  DEBUG ((DEBUG_WARN, "FUXIPAY: FAT offset=0x%lx size=0x%x readonly, install=%r\n", Offset, FUXI_PAYLOAD_SIZE, Status));
  if (EFI_ERROR (Status)) {
    FreePool (mPayload);
    mPayload = NULL;
  }

  return EFI_SUCCESS;
}
