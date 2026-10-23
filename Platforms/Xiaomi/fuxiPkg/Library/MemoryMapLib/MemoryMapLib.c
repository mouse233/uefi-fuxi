// SPDX-License-Identifier: BSD-3-Clause
//
// fuxiPkg/Library/MemoryMapLib — Xiaomi 13 (SM8550 / kalama)
//
// Initial reference: `uefiplatLA.cfg`, extracted upstream from a fuxi
// `xbl_config_a` (HyperOS OS3.0.319.0.WPCCNXM). This phone's xbl_config_b
// now independently confirms the low address/extent pairs; see
// docs/fuxi-abl-handoff.md. The reference file carries
// `MaxMemoryRegions = 74` and 28 original `[MemoryMap]` entries. This port
// splits the FD window and changes allocation/HOB policy; it is not a verbatim
// copy of every attribute. The source is the vendor firmware table, not Linux DTS.
//
// The UEFI allocation block in this capture matches sheng's. This is not
// evidence that all SM8550 boards, fuxi RAM variants or firmware revisions
// share the same layout. Validate a new device capture before changing it:
//
//   0xA7000000  1 MiB  FD Reserved
//   0xA7400000  2 MiB  UEFI FD Reserved
//   0xA7100000  3 MiB  UEFI FD          <- FD_BASE / FD_SIZE
//   0xA7600000  4 KiB  CPU Vectors
//   0xA7601000  ...    Info Blk / MMU PageTables / Log Buffer
//   0xA760D000  ...    UEFI Stack   (matches fuxi.dsc PcdCPUCoresStackBase)
//
// The vendor table above stops at 4 GiB. The banks above 4 GiB are not in it,
// and they are not a property of the SM8550 reference either: ABL rewrites
// /memory from the detected DDR size at boot. This unit is the 24 GB variant,
// and its live tree reports 23.62 GiB in nine banks (see the block further
// down). The 12 GB banks the upstream tree carries are a template, not this
// phone's layout.
//
// SPDX header above; original table from Qualcomm's uefiplatLA.cfg.
#include <Library/MemoryMapLib.h>

STATIC EFI_MEMORY_REGION_DESCRIPTOR gMemoryDescriptor[] = {
  // The general-purpose pool must come first: SEC allocates the FV-image
  // decompression buffer from the TCB before it writes DXE heap HOBs, and
  // an allocator that hands out the FD region would overwrite the very data
  // it is decoding (that surfaced as 'Decompress Failed - Invalid Parameter').
  {"DXE Heap",          0xBAB00000, 0x0D1C0000, AddMem,   SYS_MEM, SYS_MEM_CAP, Conv,   WRITE_BACK_XN},

  // ---- firmware-owned reservations ----
  {"NOMAP",             0x80000000, 0x01200000, HobOnlyNoCacheSetting,    MEM_RES, UNCACHEABLE, Reserv, UNCACHED_UNBUFFERED_XN},
  {"RSRV0",             0x81200000, 0x00800000, AddMem,   SYS_MEM, SYS_MEM_CAP, Reserv, WRITE_BACK_XN},
  {"XBL DT",            0x81A00000, 0x00040000, AddMem,   SYS_MEM, SYS_MEM_CAP, Reserv, WRITE_BACK_XN},
  {"XBL Ramdump",       0x81A40000, 0x001C0000, AddMem,   MEM_RES, UNCACHEABLE, Reserv, UNCACHED_UNBUFFERED_XN},
  {"AOP",               0x81C00000, 0x000A0000, AddMem,   MEM_RES, UNCACHEABLE, Reserv, UNCACHED_UNBUFFERED_XN},
  {"SMEM",              0x81D00000, 0x00200000, AddMem,   MEM_RES, UNCACHEABLE, Reserv, UNCACHED_UNBUFFERED_XN},
  {"RSRV1",             0x86E00000, 0x02A00000, AddMem,   MEM_RES, SYS_MEM_CAP, Reserv, WRITE_BACK_XN},
  {"PIL Reserved",      0x89800000, 0x19280000, AddMem,   MEM_RES, UNCACHEABLE, Reserv, UNCACHED_UNBUFFERED_XN},
  {"Display Demura",    0xA2A80000, 0x02B00000, AddMem,   MEM_RES, SYS_MEM_CAP, Reserv, WRITE_THROUGH_XN},
  {"RSRV2",             0xA5580000, 0x00B80000, AddMem,   MEM_RES, SYS_MEM_CAP, Reserv, WRITE_BACK_XN},
  {"DBI Dump",          0xA6100000, 0x00F00000, NoHob,    MMAP_IO, INITIALIZED, Conv,  UNCACHED_UNBUFFERED_XN},
  {"TZApps Reserved",   0xD8800000, 0x08A00000, AddMem, MEM_RES, UNCACHEABLE, Reserv, UNCACHED_UNBUFFERED_XN},
  {"RSRV3",             0xEEB00000, 0x04B00000, AddMem,   MEM_RES, SYS_MEM_CAP, Reserv, WRITE_BACK_XN},
  {"NOMAP",             0xFF800000, 0x00800000, HobOnlyNoCacheSetting,    MEM_RES, UNCACHEABLE, Reserv, UNCACHED_UNBUFFERED_XN},

  // ---- UEFI allocation block ----
  {"FD Reserved",       0xA7000000, 0x00100000, AddMem,   SYS_MEM, SYS_MEM_CAP, Reserv, WRITE_BACK},
  {"UEFI FD",           0xA7100000, 0x00300000, AddMem,   SYS_MEM, SYS_MEM_CAP, Reserv, WRITE_BACK},
  {"UEFI FD Reserved",  0xA7400000, 0x00200000, AddMem,   SYS_MEM, SYS_MEM_CAP, Reserv, WRITE_BACK},
  {"CPU Vectors",       0xA7600000, 0x00001000, AddMem,   SYS_MEM, SYS_MEM_CAP, BsData, WRITE_BACK},
  {"Info Blk",          0xA7601000, 0x00001000, AddMem,   SYS_MEM, SYS_MEM_CAP, RtData, WRITE_BACK_XN},
  {"MMU PageTables",    0xA7602000, 0x00003000, AddMem,   SYS_MEM, SYS_MEM_CAP, BsData, WRITE_BACK_XN},
  {"Log Buffer",        0xA7605000, 0x00008000, AddMem,   SYS_MEM, SYS_MEM_CAP, RtData, WRITE_BACK_XN},
  {"UEFI Stack",        0xA760D000, 0x00040000, AddMem,   SYS_MEM, SYS_MEM_CAP, BsData, WRITE_BACK_XN},
  {"SEC Heap",          0xA764D000, 0x0008C000, AddMem,   SYS_MEM, SYS_MEM_CAP, BsData, WRITE_BACK_XN},
  {"Sched Heap",        0xA76D9000, 0x00400000, AddMem,   SYS_MEM, SYS_MEM_CAP, BsData, WRITE_BACK_XN},
  {"FV Region",         0xA7AD9000, 0x00400000, AddMem,   SYS_MEM, SYS_MEM_CAP, BsData, WRITE_BACK_XN},
  {"UEFI RESV",         0xA7ED9000, 0x00127000, AddMem,   SYS_MEM, SYS_MEM_CAP, BsData, WRITE_BACK_XN},

  // ---- handed to the next payload ----
  // 0xA8000000..0xB8000000 is the vendor kernel loading window. BootShim
  // relocates the FD to 0xA7100000; later XNU ownership needs its own audit.
  {"Kernel",            0xA8000000, 0x10000000, AddMem,   SYS_MEM, SYS_MEM_CAP, Reserv, WRITE_BACK_XN},

  // ---- the ABL frame buffer fuxi keeps scanning out ----
  // Identical to /reserved-memory/splash_region in the live device tree, and to
  // sheng's hand-patched dtb_node. SimpleFbDxe publishes a GOP on top of it.
  {"Display Reserved",  0xB8000000, 0x02B00000, AddMem,   MEM_RES, SYS_MEM_CAP, Reserv, WRITE_THROUGH_XN},

  // ---- DRAM above 4 GiB: the XNU kernel window ----
  // Measured 2026-10-22 from /memory/reg of this unit's live device tree
  // (boot-tests/2026-10-22-darwinboot-stage/device-adb/). Nine banks, 23.62 GiB:
  //
  //   0x80000000  + 0x00E00000     0x811D0000  + 0x56E30000
  //   0xD8140000  + 0x00020000     0xD8800000  + 0x0        (degenerate)
  //   0xE7CB0000  + 0x18350000     0x880000000 + 0x35B00000
  //   0x8C0000000 + 0x140000000    0xA00000000 + 0x400000000
  //   0x8B5D00000 + 0x001E00000
  //
  // Only the 5 GiB bank at 0x8C0000000 is published, and as conventional
  // memory. DarwinBoot's AllocateWindow needs a single EfiConventionalMemory
  // run of at least the requested window plus the low bits of the kernel link
  // address (0x4000). This bank is the first that is big enough, and
  // /proc/iomem on the same unit shows its whole span as System RAM with no
  // reservation inside it. The low 4 GiB cannot supply that run: the vendor
  // "Kernel" window below is exactly 256 MiB, which is 16 KiB short of what
  // the 0x4000 offset requires.
  //
  // Deliberately not published yet -- nothing here needs them, and each
  // carries reservations that would have to be subtracted first:
  //   0xA00000000 + 0x400000000   reserved from 0xDDB900000 upward
  //   0x880000000 + 0x35B00000    free, but separate and smaller
  //   0x8B5D00000 + 0x001E00000   free, 30 MiB
  // An XNU window larger than 5 GiB has to bring them in.
  {"XNU Window",        0x8C0000000, 0x140000000, AddMem,  SYS_MEM, SYS_MEM_CAP, Conv,   WRITE_BACK_XN},
  // The full-OS RAM-root experiment publishes the free prefix of the 16 GiB
  // bank. The reservation starts at 0xDDB900000, so 0x3DB900000 bytes remain.
  // This is the first UEFI description of this DRAM; touching it is the
  // experiment. Keep it last so the firmware's own pool stays in low memory.
  {"XNU High",          0xA00000000, 0x3DB900000, AddMem,  SYS_MEM, SYS_MEM_CAP, Conv,   WRITE_BACK_XN},

  // ---- MMIO register regions ----
  // uefiplatLA.cfg only lists DDR in [MemoryMap]; the register apertures live
  // in a separate section and have to be mapped here, or every device driver
  // takes a translation fault on its first register read. FuxiKeyInputDxe hit
  // exactly that: SPMI sits at 0x0C400000, inside the AOSS aperture.
  {"IPC_ROUTER_TOP",    0x00400000, 0x00100000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"SECURITY CONTROL",  0x00780000, 0x00007000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"QUP",               0x00800000, 0x00300000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"PRNG_CFG_PRNG",     0x010C0000, 0x0000C000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"CRYPTO0 CRYPTO",    0x01DC0000, 0x00040000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"CORE_TOP_CSR",      0x01F00000, 0x00100000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"PERIPH_SS",         0x08800000, 0x00100000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"USB",               0x0A600000, 0x00200000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"AOSS",              0x0B000000, 0x04000000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"TLMM",              0x0F000000, 0x01000000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"SMMU",              0x15000000, 0x00200000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"APSS_HM",           0x17000000, 0x02000000, AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE},
  {"IMEM Base",         0x14680000, 0x0002A000, NoHob,  MMAP_IO, INITIALIZED, Conv,   NS_DEVICE},
  {"IMEM Cookie Base",  0x146AA000, 0x00016000, AddDev, MMAP_IO, INITIALIZED, Conv,   NS_DEVICE},
};

VOID
GetMemoryMap (
  OUT EFI_MEMORY_REGION_DESCRIPTOR **MemoryDescriptor,
  OUT UINT8                         *MemoryDescriptorCount)
{
  *MemoryDescriptor      = gMemoryDescriptor;
  *MemoryDescriptorCount = ARRAY_SIZE (gMemoryDescriptor);
}
