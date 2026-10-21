// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exercise the exact SEC range predicate with native EDK II types.
#include "../../Silicon/Silicium/SiliciumPkg/Sec/SecFdt.h"
#include <assert.h>
#include <stdio.h>

int main (void)
{
  EFI_MEMORY_REGION_DESCRIPTOR Regions[] = {
    { .Address = 0xBAB00000, .Length = 0x0D1C0000, .HobOption = AddMem, .ResourceType = SYS_MEM },
    { .Address = 0x80000000, .Length = 0x01200000, .HobOption = HobOnlyNoCacheSetting, .ResourceType = MEM_RES },
    { .Address = 0x0B000000, .Length = 0x04000000, .HobOption = AddDev, .ResourceType = MMAP_IO },
    { .Address = 0xA7100000, .Length = 0x00300000, .HobOption = AddMem, .ResourceType = SYS_MEM },
    { .Address = 0x100000000ULL, .Length = 0x200000, .HobOption = AddMem, .ResourceType = MEM_RES },
    { .Address = MAX_UINT64 - 0x1000, .Length = 0x2000, .HobOption = AddMem, .ResourceType = SYS_MEM }
  };
  UINT8 Count = sizeof (Regions) / sizeof (Regions[0]);

  assert (!IsMappedFdtRange (Regions, Count, 0xC5B1D0, 8));
  assert (!IsMappedFdtRange (Regions, Count, 0xC5B000, 0x20000));
  assert (IsMappedFdtRange (Regions, Count, 0xBAB001D0, 8));
  assert (IsMappedFdtRange (Regions, Count, 0xBAB00000, 0x20000));
  assert (IsMappedFdtRange (Regions, Count, 0xA7100000, 0x300000));
  assert (!IsMappedFdtRange (Regions, Count, 0xA73FFFFC, 8));
  assert (!IsMappedFdtRange (Regions, Count, 0xA7400000, 8));
  assert (!IsMappedFdtRange (Regions, Count, 0x80000000, 8));
  assert (!IsMappedFdtRange (Regions, Count, 0xC400000, 8));
  assert (IsMappedFdtRange (Regions, Count, 0x100001000ULL, 0x10000));
  assert (!IsMappedFdtRange (Regions, Count, 0, 8));
  assert (!IsMappedFdtRange (Regions, Count, 0xBAB00000, 0));
  assert (!IsMappedFdtRange (Regions, Count, MAX_UINT64 - 4, 8));
  assert (!IsMappedFdtRange (Regions, Count, MAX_UINT64 - 0x800, 8));
  assert (!IsMappedFdtRange (Regions, 0, 0xBAB00000, 8));
  puts ("SEC FDT range checks: 15 assertions passed");
  return 0;
}
