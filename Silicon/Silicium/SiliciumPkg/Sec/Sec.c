/**
  Copyright (c) 2011-2017, ARM Limited. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/PcdLib.h>
#include <Library/DebugLib.h>
#include <Library/PrePiLib.h>
#include <Library/DebugAgentLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SerialPortLib.h>
#include <Library/PlatformSecLib.h>
#include <Library/PrePiHobListPointerLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/MemoryMapHelperLib.h>
#include <Library/TimerLib.h>
#include <Library/HobLib.h>

#include "Sec.h"
#include "SecFdt.h"

// First argument (x0) of the previous stage, saved by ModuleEntryPoint.S
extern UINT64  gSecEntryArg0;

// The library constructors ProcessLibraryConstructorList () runs for this module, in its generated order, called one by one so the screen
// shows which one a stall is in (an entry here that the generated list lacks fails to link, which is the check).
// Helper.S: clean and invalidate every data cache level by set/way (see there).
extern VOID SecCleanInvalidateDataCacheAll (VOID);

extern RETURN_STATUS EFIAPI BaseDebugLibSerialPortConstructor (VOID);
extern RETURN_STATUS EFIAPI ExtractGuidedSectionLibConstructor (VOID);
extern RETURN_STATUS EFIAPI ArmMmuBaseLibConstructor (VOID);
extern RETURN_STATUS EFIAPI LzmaDecompressLibConstructor (VOID);

// Walks the HOB list with a bound, so a zero-length or runaway entry is reported instead of looping forever in the constructors and in
// the FV decompression that follow (both search the list).
STATIC
VOID
CheckHobList (VOID)
{
  EFI_PEI_HOB_POINTERS  Hob;
  UINTN                 Count = 0;

  Hob.Raw = GetHobList ();
  while (!END_OF_HOB_LIST (Hob)) {
    if (Hob.Header->HobLength < sizeof (EFI_HOB_GENERIC_HEADER) || Count >= 16384) {
      DEBUG ((EFI_D_ERROR, "SEC: HOB list broken at entry %u: type 0x%x length %u\n", (UINT32)Count, (UINT32)Hob.Header->HobType, (UINT32)Hob.Header->HobLength));
      return;
    }

    Count++;
    Hob.Raw = GET_NEXT_HOB (Hob);
  }

  DEBUG ((EFI_D_WARN, "SEC: HOB list ok, %u entries\n", (UINT32)Count));
}

#ifndef MDEPKG_NDEBUG
STATIC
VOID
ClearFrameBuffer (VOID)
{
  EFI_MEMORY_REGION_DESCRIPTOR FrameBufferRegion;

  // Locate "Display Reserved" Memory Region
  LocateMemoryRegionByName ("Display Reserved", &FrameBufferRegion);
  LocateMemoryRegionByName ("Display_Reserved", &FrameBufferRegion);

  // Clear Memory Region
  if (FrameBufferRegion.Address != 0 && FrameBufferRegion.Length != 0) {
    ZeroMem ((VOID *)FrameBufferRegion.Address, FrameBufferRegion.Length);
  }
}

STATIC
VOID
PrintFirmwareVersion (VOID)
{
  // Clear Frame Buffer
  ClearFrameBuffer ();

  // Print UEFI Version Message
  DEBUG ((EFI_D_WARN, "\n"));
  DEBUG ((EFI_D_WARN, "Project Silicium for %a %a\n",            FixedPcdGetPtr (PcdSmbiosSystemManufacturer), FixedPcdGetPtr (PcdSmbiosSystemModel)));
  DEBUG ((EFI_D_WARN, "Firmware Version %s Build at %a on %a\n", PcdGetPtr (PcdFirmwareVersionString), __TIME__, __DATE__));
  DEBUG ((EFI_D_WARN, "\n"));
}
#endif

STATIC
EFI_STATUS
InitializeMemory (VOID)
{
  EFI_STATUS                    Status;
  EFI_MEMORY_REGION_DESCRIPTOR  UefiMemoryRegion;
  EFI_HOB_HANDOFF_INFO_TABLE   *HobList;

  // Locate "DXE Heap" Memory Region
  LocateMemoryRegionByName ("DXE Heap", &UefiMemoryRegion);
  LocateMemoryRegionByName ("DXE_Heap", &UefiMemoryRegion);

  // Save UEFI Memory Details
  UINTN UefiMemoryBase = UefiMemoryRegion.Address;
  UINTN UefiMemorySize = UefiMemoryRegion.Length;

  // Verify UEFI Memory Base
  if (UefiMemoryBase == 0 && UefiMemorySize == 0) {
    DEBUG ((EFI_D_ERROR, "Failed to Locate \"DXE Heap\" Memory Region!\n"));
    return EFI_NOT_FOUND;
  }

  // Initialize HOB List
  HobList = HobConstructor ((VOID *)UefiMemoryBase, UefiMemorySize, (VOID *)UefiMemoryBase, (VOID *)(UefiMemoryBase + UefiMemorySize));
  PrePeiSetHobList (HobList);

  // Initialize MMU & Memory HOBs
  Status = MemoryPeim (UefiMemoryBase, UefiMemorySize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Build Stack HOB
  BuildStackHob (FixedPcdGet64 (PcdCPUCoresStackBase), FixedPcdGet32 (PcdCPUCorePrimaryStackSize));

  return EFI_SUCCESS;
}

STATIC
VOID
SecMain (VOID)
{
  EFI_STATUS Status;

  // Do Platform Specific Initialization
  PlatformInitialize ();

#ifndef MDEPKG_NDEBUG
  // Initialize Serial Port
  Status = SerialPortInitialize ();
  if (EFI_ERROR (Status)) {
    return;
  }

  // Print Firmware Version
  PrintFirmwareVersion ();

  // Report the saved entry argument before InitializeMemory changes page
  // tables. This is a raw diagnostic value; do not dereference it here.
  DEBUG ((EFI_D_WARN, "SEC: stage 3 entry x0=0x%lx (not dereferenced)\n", gSecEntryArg0));

  // Initialize Debug Agent
  InitializeDebugAgent (DEBUG_AGENT_INIT_POSTMEM_SEC, NULL, NULL);
  SaveAndSetDebugTimerInterrupt (TRUE);
#endif

  // Initialize Memory
  Status = InitializeMemory ();
  if (EFI_ERROR (Status)) {
    return;
  }

  DEBUG ((EFI_D_WARN, "SEC: memory HOBs done\n"));

  // Build CPU HOB
  BuildCpuHob (ArmGetPhysicalAddressBits (), PcdGet8 (PcdPrePiCpuIoSize));

  // Set the Boot Mode
  SetBootMode (BOOT_WITH_DEFAULT_SETTINGS);

  // Initialize Platform HOBs
  Status = PlatformPeim ();
  DEBUG ((EFI_D_WARN, "SEC: platform HOBs done (%r)\n", Status));
  if (EFI_ERROR (Status)) {
    return;
  }

  // Pass on what the previous stage handed over in x0 (a DT address for a
  // Linux-style boot loader), so a DXE driver can use it.
  {
    UINT64                        EntryArg = gSecEntryArg0;
    EFI_MEMORY_REGION_DESCRIPTOR  *Regions;
    UINT8                         RegionCount;

    GetMemoryMap (&Regions, &RegionCount);

    //
    // Reserve the device tree the previous stage handed over in x0.
    //
    // Nothing else marks those bytes as owned, so DXE treats them as free
    // memory and may map images over them. Historical upstream reports used
    // 0xC5B1D0 for both a tree and DarwinBoot; that value is not a measured
    // entry register from this phone. Validate the actual entry argument
    // rather than assuming the same location on another boot.
    //
    // InitializeMemory has already enabled the MMU. Even reading the magic
    // faults if x0 is outside this platform's page tables. A historical
    // address report is not a mapping. Reserving a HOB cannot make it readable.
    if ((EntryArg != 0) && ((EntryArg & 3) == 0) &&
        IsMappedFdtRange (Regions, RegionCount, EntryArg, 2 * sizeof (UINT32))) {
      UINT32  DtMagic = SwapBytes32 (*(UINT32 *)(UINTN)EntryArg);
      UINT32  DtSize  = SwapBytes32 (*(UINT32 *)(UINTN)(EntryArg + 4));

      if ((DtMagic == 0xD00DFEED) && (DtSize > 0x1000) && (DtSize < 0x400000)) {
        //
        // BuildMemoryAllocationHob requires a page-aligned base and a length
        // that is a multiple of EFI_PAGE_SIZE. Round the range outwards and
        // verify the entire reservation, not just the two header words.
        //
        UINT64  DtBase = EntryArg & ~(UINT64)(EFI_PAGE_SIZE - 1);
        UINT64  DtEnd  = (EntryArg + DtSize + EFI_PAGE_SIZE - 1) & ~(UINT64)(EFI_PAGE_SIZE - 1);

        if (IsMappedFdtRange (Regions, RegionCount, DtBase, DtEnd - DtBase)) {
          BuildMemoryAllocationHob (DtBase, DtEnd - DtBase, EfiReservedMemoryType);
          DEBUG ((EFI_D_WARN, "SEC: reserved DT 0x%lx..0x%lx\n", DtBase, DtEnd));
        } else {
          DEBUG ((EFI_D_WARN, "SEC: DT range 0x%lx..0x%lx outside mapped RAM; not reserved\n", DtBase, DtEnd));
        }
      }
    }

    if ((EntryArg != 0) && !IsMappedFdtRange (Regions, RegionCount, EntryArg, 2 * sizeof (UINT32))) {
      DEBUG ((EFI_D_WARN, "SEC: DT header 0x%lx outside mapped RAM; not dereferenced\n", EntryArg));
    }

    // This HOB retains the raw boot argument for diagnostics. Consumers still
    // need to validate/map or copy it before use; it is not an FDT mapping.
    BuildGuidDataHob (&gSiliciumEntryArgHobGuid, &EntryArg, sizeof (EntryArg));
  }

  CheckHobList ();

  // Run Library Cconstructors
  DEBUG ((EFI_D_WARN, "SEC: constructor debug\n"));
  BaseDebugLibSerialPortConstructor ();
  {
    RETURN_STATUS  GuidedStatus;
    RETURN_STATUS  LzmaStatus;

    DEBUG ((EFI_D_WARN, "SEC: constructor guided-section\n"));
    GuidedStatus = ExtractGuidedSectionLibConstructor ();
    DEBUG ((EFI_D_WARN, "SEC: constructor mmu\n"));
    ArmMmuBaseLibConstructor ();
    DEBUG ((EFI_D_WARN, "SEC: constructor lzma\n"));
    LzmaStatus = LzmaDecompressLibConstructor ();
    DEBUG ((EFI_D_WARN, "SEC: constructors done guided=%r lzma=%r\n", GuidedStatus, LzmaStatus));
    DEBUG ((EFI_D_WARN, "SEC: fd base=0x%lx size=0x%x sig=%c%c%c%c\n",
            (UINT64)FixedPcdGet64 (PcdFdBaseAddress),
            (UINT32)FixedPcdGet32 (PcdFdSize),
            ((CHAR8 *)(UINTN)FixedPcdGet64 (PcdFdBaseAddress))[0x28],
            ((CHAR8 *)(UINTN)FixedPcdGet64 (PcdFdBaseAddress))[0x29],
            ((CHAR8 *)(UINTN)FixedPcdGet64 (PcdFdBaseAddress))[0x2A],
            ((CHAR8 *)(UINTN)FixedPcdGet64 (PcdFdBaseAddress))[0x2B]));
  }
  CheckHobList ();

  // Decompress all FVs
  Status = DecompressFirstFv ();
  DEBUG ((EFI_D_WARN, "SEC: FV decompressed (%r)\n", Status));
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Failed to Decompress FV! Status = %r\n", Status));
    return;
  }

  // Load DXE Core
  DEBUG ((EFI_D_WARN, "SEC: loading DXE core\n"));
  Status = LoadDxeCoreFromFv (NULL, 0);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Failed to Load DXE Core! Status = %r\n", Status));
  }
}

VOID
SecEntry (VOID)
{
  // The previous stage ran with its caches on. Clean and invalidate them before anything else: the UEFI writes its HOB tables and heap with
  // the MMU and caches off, and lines the previous stage left would hide those writes (or be written back over them) once the caches are on.
  SecCleanInvalidateDataCacheAll ();

  // Disable Data Cache
  ArmDisableDataCache ();

  // Invalidate Instruction Cache
  ArmInvalidateInstructionCache ();

  // Enable Instruction Cache
  ArmEnableInstructionCache ();

  // Write back and invalidate Stack & UEFI FD D-Cache. A plain invalidate would discard what the entry code just stored there
  // (live stack frames, gSecEntryArg0) if the previous stage left the data cache on.
  WriteBackInvalidateDataCacheRange ((VOID *)FixedPcdGet64 (PcdCPUCoresStackBase), FixedPcdGet32 (PcdCPUCorePrimaryStackSize));
  WriteBackInvalidateDataCacheRange ((VOID *)FixedPcdGet64 (PcdFdBaseAddress),     FixedPcdGet32 (PcdFdSize));

  // Verify Exception Vector Table
  ASSERT (((UINTN)SecVectorTable & ARM_VECTOR_TABLE_ALIGNMENT) == 0);

  // Enable new Exception Vector Table
  ArmWriteVBar ((UINTN)SecVectorTable);

  // Enter Main SEC Function
  SecMain ();
}
