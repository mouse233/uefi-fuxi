# fuxi ABL -> BootShim -> SEC handoff audit, 2026-10-21

## Scope and evidence levels

This audit follows the failed temporary boot and successful recovery to slot b.
The phone was running Android with `sys.boot_completed=1` before and after the
reads. ADB/root reads copied the current `abl_b` and `xbl_config_b` directly to
the host. No reboot, test boot, partition image write or boot-control write was
performed during this audit. Raw firmware and disassembly remain private.

Three different kinds of evidence must remain distinct:

1. **Device bytes, statically inspected:** the current b-slot ABL was unpacked
   into its AArch64 LinuxLoader PE. The RVA references below identify code in
   that exact PE; they do not prove that the failed boot reached that code.
2. **Public reference source:** Qualcomm's published edk2 code, accessed through
   the CodeLinaro mirror at commit
   `99532df4b02e16f9ecdbf9ddd6c910fe0be58a5d` (`uefi.lnx.3.0.r17-rel`). It helps
   identify functions and structures; it is not Xiaomi's exact source tree.
3. **Runtime evidence:** the prior host transfer/error log, warning photograph,
   and recovered Android captures. No failed-run PC/x0/EL dump exists.

The allowlisted hashes, selected instructions and address comparisons are in
[`evidence/fuxi-abl-handoff-20261021.json`](evidence/fuxi-abl-handoff-20261021.json).

## What the boot command does

The public [`CmdBoot`](https://github.com/CodeLinaro-mirror/la_abl_tianocore_edk2/blob/99532df4b02e16f9ecdbf9ddd6c910fe0be58a5d/QcomModulePkg/Library/FastbootLib/FastbootCmds.c#L2818)
places the downloaded image in `BootInfo.Images[0]` under the name `boot`,
handles the multislot state, calls `LoadImageAndAuth`, acknowledges the command,
stops USB, clears the development-image flag and calls `BootLinux`.

The device PE contains the corresponding `ClearUnbootable` call at RVA
`0x8974c` (target `0x24790`), the subsequent authentication-wrapper call at
`0x89760`, and the `BootLinux` call at `0x897d8` (target `0x6ef0`). The slot
helper includes clearing a bit in the selected partition attributes. This is
another reason temporary boot must not be described as unable to affect
boot-control metadata. It does not establish which path produced the earlier
observed b-unbootable/a-active state.

USB is stopped before `BootLinux` in the reference path. Therefore the prior
`usb_read failed` cannot locate the failure relative to gzip decoding, DTB
selection, boot-services shutdown or the first instruction of the payload.
An acknowledgement alone also cannot prove execution of those later stages.

## Where the v3/v4 device tree comes from

The AOSP [boot image header definition](https://source.android.com/docs/core/architecture/bootloader/boot-image-header)
moves DTB data to `vendor_boot` for v3/v4. Qualcomm's
[`DTBImgCheckAndAppendDT`](https://github.com/CodeLinaro-mirror/la_abl_tianocore_edk2/blob/99532df4b02e16f9ecdbf9ddd6c910fe0be58a5d/QcomModulePkg/Library/BootLib/BootLinux.c#L429)
implements separate paths:

| Android header | Primary DTB source in the inspected path |
| --- | --- |
| v0/v1 | Kernel-field appended DTB, using the gzip/kernel boundary |
| v2 | Explicit boot-image DTB section |
| v3/v4 | `vendor_boot` DTB section, after its page-aligned vendor ramdisk |

The current Xiaomi PE confirms the v3/v4 dataflow at RVAs
`0xae7c..0xaef0`: it uses the vendor image pointer (`BootParamlist+0x20`),
computes its DTB section offset from page size and vendor ramdisk size, reads
the vendor DTB size at header offset `0x834`, and selects that image as the
input buffer. It then selects the SoC DTB and, on the valid DTBO path, applies
the board overlay. Error/fallback paths exist and must not be treated as a
reliable alternative packaging contract.

Consequently, `gzip(BootShim + FD) + Resources/DTBs/fuxi.dtb` inside a v3 kernel
field does **not** establish that its appended tree is the tree given to UEFI.
Updating only that bundled 12 GB capture is not an evidenced fix for this
failure. The downloaded boot image is also not an isolated set of all boot
inputs: the selected slot's vendor/overlay inputs matter.

The recovered b-slot vendor image has 17 DTBs and its DTBO image has 12
entries. Android reports index 11 for both. Applying that pair offline succeeds
but leaves memory/board placeholders and a generic Kalama model. The reference
[`UpdateDeviceTree`](https://github.com/CodeLinaro-mirror/la_abl_tianocore_edk2/blob/99532df4b02e16f9ecdbf9ddd6c910fe0be58a5d/QcomModulePkg/Library/BootLib/UpdateDeviceTree.c#L937)
updates RAM from firmware protocols, DDR details, splash memory and `/chosen`
properties. This explains why overlay merging alone does not recreate the
live tree. Xiaomi may add further fixups; their exact effects were not all
reconstructed here.

## How the payload is placed and called

In [`UpdateBootParams`](https://github.com/CodeLinaro-mirror/la_abl_tianocore_edk2/blob/99532df4b02e16f9ecdbf9ddd6c910fe0be58a5d/QcomModulePkg/Library/BootLib/BootLinux.c#L143),
the kernel window comes from XBL variables, with a fallback to platform
defaults. The gzip path uses the 64-bit load offset of `0x80000`; the raw
ARM64-image path can add the image header's `text_offset`. The device PE
confirms the gzip conditional at `0x9eb8..0x9f00`. Do not remove compression
while leaving BootShim's current absolute-looking `text_offset=0xA7100000`
and assume the placement will remain the same. The Linux ARM64 specification
defines this field as an offset from an aligned RAM base, not a firmware
destination address.

ABL decompresses the payload, selects/updates a DTB, prepares hardware and
shuts down its boot services. The final AArch64 call in the device PE is:

```text
RVA 0x8ce4: ldr x8, [sp, #0x290]  ; KernelLoadAddr
...
RVA 0x8cf0: ldr x0, [sp, #0x2a8]  ; DeviceTreeLoadAddr
RVA 0x8cf4: mov x3, xzr
RVA 0x8cf8: mov x1, x3
RVA 0x8cfc: mov x2, x3
RVA 0x8d00: blr x8
```

This agrees with the [ARM64 Linux entry contract](https://docs.kernel.org/arch/arm64/booting.html):
`x0` is the physical DTB address and `x1..x3` are zero. It is static evidence of
the calling convention, not a recovered register dump from the failed run.

BootShim's machine code does not modify x0. It relocates the FD to
`0xA7100000`, maintains instruction visibility and branches there. The FV reset
branch also preserves x0. SEC first keeps it in x20 across cache maintenance,
then stores it in `gSecEntryArg0` before platform assembly initialization.
Consumers must still validate/map/reserve the DTB before dereferencing it.

## What the actual XBL configuration validates

The current phone's `xbl_config_b` independently confirms these address/extent
pairs in the port: Kernel, DXE Heap, Display Reserved, UEFI Stack, CPU Vectors,
MMU PageTables and all 14 register apertures (20 comparisons). This is about
base/length agreement, not a proof that every port HOB/cache attribute is right.

The vendor FD window is `0xA7000000 + 0x00400000`; the port deliberately splits
it into a lower reserved 1 MiB and a 3 MiB FD at `0xA7100000`. Their combined
extent matches. The current high-RAM variant therefore does not by itself
justify moving these low firmware regions or expanding GCD RAM.

For illustration only, taking the XBL config Kernel window literally and
applying the observed v3 ramdisk sizes gives:

```text
Kernel window         0xA8000000 + 0x10000000
gzip BootShim entry   0xA8080000
v3 ramdisk address    0xB73C5000
v3 DTB/x0 address     0xB71C4000
```

These are a model, not observed failed-run values. Runtime XBL variables,
slot selection or Xiaomi-specific handling may differ. In particular the
historical upstream `0x00C5B1D0` claim must not be represented as an x0
measurement from this phone.

## Next diagnostic boundary

The remaining question is whether the failure is before the final ABL call,
inside BootShim/early SEC, or during the return/reboot path. The warning screen
alone does not answer it. The next explicitly approved hardware session needs
screen recording from before launch, the exact image hash, complete pre-test
slot flags and the earliest SEC output. A DEBUG-only log of the saved x0,
before `InitializeMemory` enables the MMU, is added so that a future run can
provide a real entry value without dereferencing it.

No header-version switch, DTB replacement, RAM expansion, vendor_boot change,
logging partition write or new device boot is justified or performed by this
static audit. The parked failed image is not made safe by these findings.
