/** @file
  Bring-up probe: locate the UniXNU payload volume in physical memory.

  The payload is a FAT32 volume labelled FUXIESP. Walking a fixed address range
  faults on unmapped device memory, so only descriptors from the UEFI memory map
  that describe ordinary RAM are scanned.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/CpuLib.h>

STATIC
BOOLEAN
LooksLikePayload (
  IN CONST UINT8  *Page
  )
{
  if ((Page[510] != 0x55) || (Page[511] != 0xAA)) {
    return FALSE;
  }

  return (CompareMem (Page + 0x47, "FUXIESP", 7) == 0);
}

STATIC
BOOLEAN
Scannable (
  IN EFI_MEMORY_TYPE  Type
  )
{
  return (Type == EfiConventionalMemory) || (Type == EfiLoaderData) ||
         (Type == EfiBootServicesData) || (Type == EfiLoaderCode) ||
         (Type == EfiBootServicesCode);
}

EFI_STATUS
EFIAPI
FuxiProbeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS             Status;
  EFI_MEMORY_DESCRIPTOR  *Map;
  UINTN                  MapSize;
  UINTN                  MapKey;
  UINTN                  DescriptorSize;
  UINT32                 DescriptorVersion;
  UINTN                  Index;
  UINTN                  Count;
  UINT64                 Address;
  UINT8                  *Page;
  UINTN                  Hits;
  UINT8                  Label[12];

  // Dispatched with Depex TRUE this can run before the console drivers are
  // up; give them a few seconds so ClearScreen and Print actually land.
  gBS->Stall (4000000);

  // The DXE log would scroll this away; clear first and stop the boot.
  gST->ConOut->ClearScreen (gST->ConOut);
  Print (L"FUXIPROBE: walking the memory map for FUXIESP\n");

  MapSize = 0;
  Status  = gBS->GetMemoryMap (&MapSize, NULL, &MapKey, &DescriptorSize, &DescriptorVersion);
  MapSize += 8 * DescriptorSize;
  Map      = AllocatePool (MapSize);
  if (Map == NULL) {
    Print (L"FUXIPROBE: no memory for the map\n");
    return EFI_SUCCESS;
  }

  Status = gBS->GetMemoryMap (&MapSize, Map, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (EFI_ERROR (Status)) {
    Print (L"FUXIPROBE: GetMemoryMap failed %r\n", Status);
    return EFI_SUCCESS;
  }

  Count = MapSize / DescriptorSize;
  Hits  = 0;

  for (Index = 0; Index < Count; Index++) {
    EFI_MEMORY_DESCRIPTOR *Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Index * DescriptorSize);

    if (!Scannable (Entry->Type)) {
      continue;
    }

    for (Address = Entry->PhysicalStart;
         Address + 4096 <= Entry->PhysicalStart + (Entry->NumberOfPages << 12);
         Address += 4096) {
      Page = (UINT8 *)(UINTN)Address;
      if (!LooksLikePayload (Page)) {
        continue;
      }

      CopyMem (Label, Page + 0x47, 11);
      Label[11] = 0;
      Print (L"FUXIPROBE: hit at %lx label=%a type=%u\n", Address, Label, Entry->Type);

      Hits++;
      if (Hits >= 8) {
        break;
      }
    }

    if (Hits >= 8) {
      break;
    }
  }

  if (Hits == 0) {
    Print (L"FUXIPROBE: no FUXIESP volume in mapped RAM (%lu regions)\n", (UINT64)Count);
  } else {
    Print (L"FUXIPROBE: %lu hits\n", (UINT64)Hits);
  }

  // The boot manager clears the screen, so halt here with the result visible.
  Print (L"FUXIPROBE: halted for observation, power-cycle to continue\n");
  CpuDeadLoop ();

  return EFI_SUCCESS;
}
