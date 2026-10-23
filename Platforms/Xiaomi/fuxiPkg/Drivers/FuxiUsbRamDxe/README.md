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
