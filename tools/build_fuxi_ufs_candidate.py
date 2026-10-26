#!/usr/bin/env python3
"""Build the M1 receiver-only candidate with the native UFS diagnostic.

Runs inside unixnu-fuxi-build-arm64, reuses the shared unixnu orchestration,
and adds the feat/twrp-data-uefi switches on top of the reference receiver
image. The result is a boot image with no OS payload: FuxiNativeUfsDxe runs
its read-only UFS takeover diagnostic during DXE dispatch, then the receiver waits
for a transfer that never comes. No phone command is issued here.

--without-ufs and --usb-ep0-trace produce the A/B variants that isolate the
EP0 ENDTRANSFER timeout; both are recorded in candidate.json.
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True,
                        help="checkout providing the unixnu framework (scripts/unixnu)")
    parser.add_argument("--device", type=Path, required=True,
                        help="device repository holding board.toml")
    parser.add_argument("--edk2", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ufs-report-hold-seconds", type=int, default=20,
                        help="photo hold before USB (0..60 seconds, default 20)")
    parser.add_argument("--without-ufs", action="store_true",
                        help="skip the UFS diagnostic entirely: receiver-only baseline")
    parser.add_argument("--usb-ep0-trace", choices=["0", "1"], default="0",
                        help="FUXI_USB_EP0_TRACE; 0 matches the accepted M1 candidates")
    parser.add_argument("--usb-ep0-forcerm", choices=["0", "1"], default="1",
                        help="FUXI_USB_EP0_FORCERM; 0 ends EP0 without ForceRM "
                             "(upstream dwc3_ep0_end_control_data behavior)")
    parser.add_argument("--sources-only", action="store_true",
                        help="only regenerate sources.json from the current tree")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in ("aarch64", "arm64", "x86_64", "AMD64"):
        parser.error("the candidate firmware build must run in unixnu-fuxi-build-arm64")
    if not 0 <= args.ufs_report_hold_seconds <= 60:
        parser.error("--ufs-report-hold-seconds must be between 0 and 60")
    hold = 0 if args.without_ufs else args.ufs_report_hold_seconds
    uefi = Path(__file__).resolve().parents[1]
    if args.sources_only:
        write_sources(uefi, args.output.resolve())
        return
    base, device, edk2, out = [x.resolve() for x in [args.base, args.device, args.edk2, args.output]]
    sys.path.insert(0, str(base / "scripts"))
    from unixnu import cli, firmware, bootimg, tree
    from unixnu.config import Context
    ctx = Context(cli.parser().parse_args(["build", "firmware", "-D", str(device),
                                           "--out", str(out), "--uefi", str(uefi),
                                           "--edk2", str(edk2), "-j", "10"]))
    ctx.work, ctx.logs = out / "work", out / "logs"
    ctx.tree = ctx.work / "tree"
    ctx.tree.mkdir(parents=True, exist_ok=True)
    ctx.logs.mkdir(parents=True, exist_ok=True)
    for repo in [base, device]:
        tree._copy_scripts(repo / "scripts", ctx.tree / "scripts")
    for name in ["package", "drivers"]:
        link = ctx.tree / name
        if link.is_symlink():
            link.unlink()
        if not link.exists():
            link.symlink_to(os.path.relpath(base / name, ctx.tree), target_is_directory=True)
    ctx.board["firmware"]["submodules"] = []
    ctx.board["firmware"]["packages"].append("{uefi}/Silicon/Samsung")
    ctx.board["firmware"]["defines"]["FUXI_USB_RAM_RECEIVER"] = "1"
    ctx.board["firmware"]["defines"]["FUXI_USB_TRY_SID_ROUTE"] = "1"
    ctx.board["firmware"]["defines"]["FUXI_USB_KEEP_PHY"] = "1"
    ctx.board["firmware"]["defines"]["FUXI_PAYLOAD_DIAGNOSTIC"] = "0"
    ctx.board["firmware"]["defines"]["FUXI_USB_RAM_SYSTEM_HANDOFF"] = "0"
    # M1 native UFS diagnostic; the M0 probe stays off (no BlockIo provider).
    # --without-ufs is the A/B baseline: USB init runs with no UFS takeover,
    # SMMU stream setup or DMA allocation ahead of it.
    ctx.board["firmware"]["defines"]["FUXI_DATA_PORT_UFS"] = "0" if args.without_ufs else "1"
    ctx.board["firmware"]["defines"]["FUXI_UFS_REPORT_HOLD_SECONDS"] = str(hold)
    ctx.board["firmware"]["defines"]["FUXI_DATA_PORT_PROBE"] = "0"
    ctx.board["firmware"]["defines"]["FUXI_DATA_SCM_QUERY"] = "0"
    # Accepted M1 candidates ship with the trace off so the UFS block stays
    # readable; the receiver's per-packet EP0 traces would scroll it away.
    ctx.board["firmware"]["defines"]["FUXI_USB_EP0_TRACE"] = args.usb_ep0_trace
    ctx.board["firmware"]["defines"]["FUXI_USB_EP0_FORCERM"] = args.usb_ep0_forcerm
    ctx.uefi = uefi
    fd = firmware.build(ctx, {}, uefi, edk2, "DEBUG")
    shutil.copyfile(fd, out / "SILICIUM_UEFI.fd")
    artifacts = uefi / "Build/fuxiPkg/DEBUG_CLANGPDB/AARCH64"
    for name in ["FuxiUsbRamDxe", "UsbfnDwc3Dxe"] + ([] if args.without_ufs else ["FuxiNativeUfsDxe"]):
        shutil.copyfile(artifacts / (name + ".efi"), out / (name + ".efi"))
    write_sources(uefi, out)
    dummy = out / "dummy-ramdisk.img"
    dummy.write_bytes(b"dummy")
    primary = "Mu-fuxi-usb-ram.img" if args.without_ufs else "Mu-fuxi-ufs-m1.img"
    alias = "Mu-fuxi-ufs-m1.img" if args.without_ufs else "Mu-fuxi-usb-ram.img"
    image = bootimg.build(ctx, uefi, fd, uefi / "Resources/DTBs/fuxi.dtb", dummy,
                          out / primary)
    # The delivery image checker reads Mu-fuxi-usb-ram.img, so both names are
    # the same bytes either way.
    shutil.copyfile(image, out / alias)
    report = dict(image=str(image), sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                  bytes=image.stat().st_size,
                  mode=("receiver-only image without the UFS diagnostic (A/B baseline)"
                        if args.without_ufs else
                        "receiver-only image with the M1 native UFS read-only diagnostic"),
                  dma_audit_only=False, dma_transfer_enabled=True,
                  usb_sid_route_enabled=True, usb_keep_phy=True,
                  ufs_report_cached=not args.without_ufs,
                  ufs_report_replay_at_receiver_park=not args.without_ufs,
                  ufs_report_hold_seconds=hold,
                  fuxi_data_port_ufs=not args.without_ufs, fuxi_data_port_probe=False,
                  usb_ep0_trace=args.usb_ep0_trace == "1",
                  usb_ep0_endtransfer_forcerm=args.usb_ep0_forcerm == "1",
                  native_ufs_takeover=("absent; --without-ufs" if args.without_ufs else
                                        "diagnostic only; read commands, no writes, no keys"),
                  controller="DWC3 USB2, SM8550 inherited ABL PHY/clocks",
                  hardware_result="pending", kernel_handoff=False, receiver_only=True,
                  partition_io=False, system_handoff=False)
    (out / "candidate.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def write_sources(uefi, out):
    paths = [
        *sorted((uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiUsbRamDxe").glob("*.[ch]")),
        *sorted((uefi / "Platforms/Xiaomi/fuxiPkg/Library/FuxiUsbfnLib").glob("*.[ch]")),
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiUsbRamDxe/FuxiUsbRamDxe.inf",
        *sorted((uefi / "Platforms/Xiaomi/fuxiPkg/Library/FuxiUsbfnLib").glob("*.inf")),
        uefi / "Silicon/Samsung/SamsungPkg/Drivers/UsbfnDwc3Dxe/UsbfnDwc3Dxe.inf",
        *sorted((uefi / "Silicon/Samsung/SamsungPkg/Drivers/UsbfnDwc3Dxe").glob("*.[ch]")),
        uefi / "Silicon/Samsung/SamsungPkg/Include/Device/Dwc3.h",
        *sorted((uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe").glob("*.[ch]")),
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/FuxiNativeUfsDxe.inf",
        uefi / "Platforms/Xiaomi/fuxiPkg/fuxi.dsc", uefi / "Platforms/Xiaomi/fuxiPkg/fuxi.fdf",
        uefi / "Platforms/Xiaomi/fuxiPkg/Include/DXE.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Library/MemoryMapLib/MemoryMapLib.c",
        uefi / "Platforms/Xiaomi/fuxiPkg/Library/MemoryMapLib/MemoryMapLib.inf",
        uefi / "Platforms/Xiaomi/fuxiPkg/Include/Protocol/FuxiUfsReport.h",
        Path(__file__),
    ]
    (out / "sources.json").write_text(json.dumps({str(x.relative_to(uefi)):
        hashlib.sha256(x.read_bytes()).hexdigest() for x in paths if x.is_file()}, indent=2) + "\n")


if __name__ == "__main__":
    main()
