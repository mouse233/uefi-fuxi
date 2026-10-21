/** @file
  Conservative bounds check before SEC dereferences a handed-over FDT.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#ifndef SILICIUM_SEC_FDT_H_
#define SILICIUM_SEC_FDT_H_

#include <Library/MemoryMapLib.h>

// MemoryPeim only maps descriptors other than HobOnlyNoCacheSetting. A HOB
// reservation alone does not create a page-table entry. Require the complete
// range to fit in one mapped RAM descriptor; do not probe MMIO or invent RAM
// below PcdSystemMemoryBase based on an untrusted x0 value.
STATIC
BOOLEAN
IsMappedFdtRange (
  IN CONST EFI_MEMORY_REGION_DESCRIPTOR  *Regions,
  IN UINT8                               Count,
  IN UINT64                              Address,
  IN UINT64                              Length
  )
{
  UINTN  Index;

  if ((Address == 0) || (Length == 0) || (Address > MAX_UINT64 - Length)) {
    return FALSE;
  }

  for (Index = 0; Index < Count; Index++) {
    CONST EFI_MEMORY_REGION_DESCRIPTOR  *Region = &Regions[Index];
    UINT64                              Offset;

    if ((Region->HobOption == HobOnlyNoCacheSetting) ||
        ((Region->ResourceType != SYS_MEM) && (Region->ResourceType != MEM_RES)) ||
        (Address < Region->Address) ||
        (Region->Length > MAX_UINT64 - Region->Address)) {
      continue;
    }

    Offset = Address - Region->Address;
    if ((Offset < Region->Length) && (Length <= Region->Length - Offset)) {
      return TRUE;
    }
  }

  return FALSE;
}

#endif
