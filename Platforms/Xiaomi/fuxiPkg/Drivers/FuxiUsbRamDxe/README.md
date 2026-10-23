# Experimental fuxi USB RAM receiver

Opt in with `FUXI_USB_RAM_RECEIVER=1` (default off). This diagnostic stays in
UEFI and exposes no partition-write or kernel-handoff operation. It uses the
shared DWC3 controller with a fuxi adapter that inherits ABL PHY/clocks; cold
SM8550 USB initialization is not implemented.

Hardware status, 2026-10-23: initial image reaches the receiver and reads
GSNPSID `33313130`, then resets before successful USB enumeration. The next
image adds S0–S12 traces around run/stop, PHY/core reset and event-ring setup.
Its first fastboot boot attempt reports a USB disconnect. A second attempt
boots successfully; the user reports S12 (core initialization complete), then
a black screen and reboot to Android. No hardware data transfer has passed.
S13–S19 and bounded endpoint command/DMA-address traces now cover the next
stages. Initial EP0 SETUP submission errors propagate instead of attaching
after a failed arm. This does not establish the reboot cause. Host protocol
tests alone do not qualify the controller or PHY.

`RamBulk.c` is the portable protocol engine. Its allocation/hash callbacks are
implemented by `FuxiUsbRamDxe.c`. The Python sender, production-engine tests,
firmware verifier and build wrapper are in the device repository:
[USB Bulk workflow and wire format](https://github.com/mouse233/unixnu-fuxi/blob/feat/ramdisk-test/diagnostics/ram-root/usb-bulk.md).

Receiver object allocations are retained only while this diagnostic owns the
UEFI session. Future XNU use requires explicit reserved-memory layout and a
loader handoff; EfiLoaderData allocations alone do not provide that contract.

The pre-DMA read-only audit now parks intentionally before STARTTRANSFER.
Hardware capture: ID0=4c017e69 ID1=60000046 CR0=00290406 GFSR=0, 105 groups,
no nonsecure SID 0x40 match, CLIENTPD=0/USFCFG=1. The missing route is consistent
with a fault on first DMA, but no DMA fault syndrome or exception PC was captured.
The audit has no MMIO-write callback and does not turn SMMU bypass encodings into
claims of working DMA. Its 14 ASan/UBSan host cases cover bounds, normal/extended
SMRs, masked/ambiguous matches, 4/64 KiB register pages and incomplete scans.

`FUXI_USB_TRY_SID_ROUTE=1` opts into a separate library instance. It requires a
complete normal-ID scan, CLIENTPD=0, USFCFG=1, no existing SID0040 match and a
free SMR. It programs only that slot's S2CR/SMR, validates both readbacks and
allows the first DMA only after success. Default mode remains read-only.
BYPASS rejection (including Qualcomm BYPASS-to-FAULT emulation) triggers a
verified rollback and pre-DMA park. Failed rollback retains explicit uncertain
ownership. StopController halts USB before route removal; removal refuses a
changed route. No global SMMU or context-bank configuration is written.
The production route transaction has 12 additional ASan/UBSan host cases;
register readback success alone does not qualify DMA or USB enumeration.

Hardware route trial: slot 0 BYPASS request 000100ff reads back 000200ff
(FAULT). The transaction returns FurBypassRejected, verifies restoration of
SMR=00000060/S2CR=00020000 and parks before DMA. The encoding quirk is observed
on this unit; a disabled, unreferenced S1/S2-bypass context is the next option.

The current opt-in route trial uses TRANS to a pre-existing disabled context:
all TRANS references (including invalid SMRs) reserve their bank; bank 0 is
left alone. A candidate must be within the 1 MiB aperture, have CBAR.TYPE=1
(S1 translation/S2 bypass), and SCTLR.M=0. No context register is modified.
S2CR readback must preserve the exact CBNDX; context and route are rechecked
before DMA. A changed context causes rollback, and no candidate returns code 7.
The original BYPASS transaction remains in regression tests. Route-engine host
coverage is now 20 scenarios; physical DMA through the context path is unproven.

Hardware result for the enabled context route: SID 0x40 was pointed at the
disabled bank 5 (CBAR=000100FF, SCTLR=000000E0) and the S2CR readback kept the
exact CBNDX, but the initial EP0 STARTTRANSFER was then rejected with controller
status 1. No receiver enumerated. The failure paths now print a read-only
snapshot (GFSR, GFSYNR0..2, route slot, context SCTLR/CBAR/FSR/FAR, DWC3
DSTS/GSTS/DCTL/GEVNTCOUNT and pending event dwords) so an SMMU abort can be
told apart from a controller-side rejection; the snapshot writes no register,
clears no fault and consumes no event.

Follow-up hardware run: the same route was accepted with GFSR=0 after install,
the initial EP0 STARTTRANSFER succeeded (the earlier status-1 rejection did not
reproduce), the controller reached RUN_STOP and the receiver waited for
1209:0001. The host still saw no device and no USB attach event, so link
bring-up - not the route - is now the blocking layer. A post-RUN_STOP sampler
reports DSTS link state, connect speed, SOF number, DCTL, GUSB2PHYCFG and
GEVNTCOUNT for two seconds, printing only on change.
