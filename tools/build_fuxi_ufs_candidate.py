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
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True,
                        help="checkout providing the unixnu framework (scripts/unixnu)")
    parser.add_argument("--device", type=Path, required=True,
                        help="device repository holding board.toml")
    parser.add_argument("--device-config-ref", help="explicit immutable device board.toml revision; does not change the shared checkout")
    parser.add_argument("--edk2", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ufs-report-hold-seconds", type=int, default=20,
                        help="photo hold before USB (0..60 seconds, default 20)")
    parser.add_argument("--m3-scm-bridge", action="store_true", help="query bridge service availability only")
    parser.add_argument("--m3-smc-context", action="store_true", help="INFO-only context control, disables bridge and object execution")
    parser.add_argument("--m3-smci-mode", choices=["legacy", "object"], default="legacy",
                        help="explicit root invoke entry; no runtime fallback")
    parser.add_argument("--m3-smci-loader", action="store_true", help="gated root/open UID122/release batch; no TA or keys")
    parser.add_argument("--m3-smci-lookup", action="store_true", help="loader lookup of keymaster64/keymaster only; no load or keys")
    parser.add_argument("--m3-smci-lookup-arch", action="store_true", help="matched TZ 1011/BO4 lookup of keymaster64 only; no fallback, load or TA command")
    parser.add_argument("--m3-smci-load", action="store_true",
                        help="one loadFromBuffer of the keymaster_a extent, then release; no command or key")
    parser.add_argument("--m3-smci-version", action="store_true", help="one KeyMint getVersion after load; no key or decrypt")
    parser.add_argument("--m3-smci-resume", action="store_true", help="bounded SCM interrupted-call continuation")
    parser.add_argument("--m3-smci-date", action="store_true", help="read-only KeyMint date capability query")
    parser.add_argument("--m3-recover-key", action="store_true", help="recover one existing metadata key, wipe output, close session; no convert/ICE")
    parser.add_argument("--recovery-binding", type=Path, help="exact pinned real Android unbound-context evidence; required for recovery")
    parser.add_argument("--m3-recovery-public", action="store_true", help="observe same-boot allowlisted blob fields before begin; no new TA command")
    parser.add_argument("--m3-configure-recovery", action="store_true", help="one fixed public configure before first secret request; explicit audited recovery only")
    parser.add_argument("--configure-patch", type=int, choices=(20261005,20991231), default=20261005, help="fixed public OS/vendor patch profile; alternate requires A/B evidence")
    parser.add_argument("--configure-evidence", type=Path, help="exact pinned live -64 / TA gate / QTI date-support proof")
    parser.add_argument("--m3-characteristics-probe", action="store_true",
                        help="one read-only getKeyCharacteristics (0x2109) after configure; version integers only")
    parser.add_argument("--m3-smci-setver", action="store_true", help="one bounded KeyMint set-version 200 request")
    parser.add_argument("--m3-smci-root", action="store_true", help="C2 root register/release only; no TA or keys")
    parser.add_argument("--m3-bridge-large", action="store_true", help="0x82000 HLOS bridge after LUN4 hashes")
    parser.add_argument("--m3-bridge-hlos", action="store_true", help="one VMID3 RW bridge diagnostic; no blob/key/context")
    parser.add_argument("--m3-bridge-blob", action="store_true",
                        help="C1: read the pinned metadata blob into an 8 KiB bridge; no TA")
    parser.add_argument("--m3-bridge-call", action="store_true",
                        help="closed-loop enable/create/delete of one registered page")
    parser.add_argument("--m3-crypto-cap", action="store_true", help="read bounded standard UFS crypto capability registers")
    parser.add_argument("--m3-scm-invoke", action="store_true", help="query smcinvoke service availability")
    parser.add_argument("--m3-scm-subjects", action="store_true", help="query availability of ICE SCM services after INFO self-query")
    parser.add_argument("--m3-scm-info", action="store_true", help="one SMC64 INFO self-availability query")
    parser.add_argument("--m3-metadata-key", action="store_true",
                        help="read-only listing and hashing of the metadata key directory")
    parser.add_argument("--lun4-keymaster", action="store_true", help="read-only LUN4 keymaster hashes; no slot selection")
    parser.add_argument("--m2-metadata-files", action="store_true",
                        help="run bounded metadata file diagnostics and park before USB dispatch")
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
    if args.m3_scm_bridge and not args.m3_scm_info:
        parser.error("bridge availability requires --m3-scm-info")
    if args.m3_crypto_cap and not args.m2_metadata_files:
        parser.error("crypto capability probe requires parked diagnostic")
    if args.m3_scm_invoke and not args.m3_scm_info:
        parser.error("invoke availability requires --m3-scm-info")
    if args.m3_scm_subjects and not args.m3_scm_info:
        parser.error("ICE availability requires --m3-scm-info")
    if args.m3_scm_info and not args.m2_metadata_files:
        parser.error("M3 INFO requires the parked diagnostic")
    if args.lun4_keymaster and not args.m2_metadata_files:
        parser.error("LUN4 diagnostic requires parked M2")
    if args.m2_metadata_files and args.without_ufs:
        parser.error("M2 requires the native UFS diagnostic")
    if args.m3_metadata_key and not args.m2_metadata_files:
        parser.error("metadata key discovery requires --m2-metadata-files")
    if args.m3_bridge_call and not (args.m3_scm_info and args.m2_metadata_files):
        parser.error("bridge calls require --m3-scm-info and --m2-metadata-files")
    if args.m3_bridge_blob and not args.m3_bridge_call:
        parser.error("bridge blob requires --m3-bridge-call")
    if args.m3_smci_root and (not (args.m3_bridge_call and args.m3_scm_invoke) or args.m3_bridge_blob or args.m3_metadata_key):
        parser.error("SMCI root requires bridge call and invoke availability, with no key probes")
    if args.m3_smci_mode == "object" and not args.m3_smci_root:
        parser.error("object invoke mode requires --m3-smci-root")
    if args.m3_smc_context and not args.m3_smci_root:
        parser.error("context control requires parked root diagnostic configuration")
    if args.m3_bridge_hlos and (not args.m3_bridge_call or not args.m3_scm_bridge or args.m3_bridge_blob or args.m3_smc_context or args.m3_metadata_key):
        parser.error("HLOS requires bridge availability; no blob/context/key")
    if args.m3_bridge_hlos and args.m3_smci_root and args.m3_smci_mode != "object":
        parser.error("HLOS C2 candidate requires explicit object mode; no legacy fallback")
    if args.m3_smci_loader and (not args.m3_smci_root or not args.m3_bridge_hlos or args.m3_smci_mode != "object" or args.m3_smc_context):
        parser.error("loader batch requires HLOS object root; no context mode")
    if args.m3_bridge_large and not (args.lun4_keymaster and args.m3_bridge_hlos and args.m3_scm_bridge and args.m3_bridge_call and not args.m3_bridge_blob):
        parser.error("large bridge requires LUN4, HLOS bridge and INFO, no blob")
    if args.m3_smci_lookup and not args.m3_smci_loader:
        parser.error("lookup batch requires --m3-smci-loader")
    lookup_binding=None
    if args.m3_smci_lookup_arch:
        if not args.m3_smci_lookup or args.m3_smci_load or args.m3_recover_key:
            parser.error('deployed lookup requires lookup-only; no load or recovery')
        from m3_lookup_arch_binding import load_binding
        lookup_binding=load_binding()
    if args.m3_smci_load and (not args.m3_smci_loader or args.m3_smci_lookup or not args.m3_bridge_large or not args.lun4_keymaster):
        parser.error("load stage requires the large LUN4 loader batch and no lookup")
    if args.m3_smci_version and not args.m3_smci_load:
        parser.error("version stage requires --m3-smci-load")
    if args.m3_smci_resume and not args.m3_smci_version:
        parser.error("SCM resume requires --m3-smci-version")
    if args.m3_smci_setver and not (args.m3_smci_version and args.m3_smci_resume):
        parser.error("set-version requires version and resume")
    if args.m3_smci_date and (not (args.m3_smci_version and args.m3_smci_resume) or args.m3_smci_setver):
        parser.error("date query requires version and resume and excludes set-version")
    recovery_binding=None
    if args.m3_recover_key:
        if not (args.m3_smci_version and args.m3_smci_resume and args.m3_smci_mode=="object" and args.m2_metadata_files) or args.m3_metadata_key or args.m3_smci_setver or args.m3_smci_date:
            parser.error("recovery requires the version/resume object batch and excludes discovery/date/set-version")
        if not args.recovery_binding:parser.error("recovery requires --recovery-binding")
        from m3_recovery_binding import load_binding
        recovery_binding=load_binding(args.recovery_binding)
    elif args.recovery_binding:parser.error("binding evidence is only valid with --m3-recover-key")
    configure_binding=None
    if args.m3_configure_recovery:
        if not args.m3_recover_key or not args.configure_evidence:parser.error('configure requires recovery and explicit --configure-evidence')
        from m3_configure_binding import load_configure_evidence
        configure_binding=load_configure_evidence(args.configure_evidence,args.configure_patch)
    elif args.configure_evidence or args.configure_patch!=20261005:parser.error('configure evidence/profile requires --m3-configure-recovery')
    if args.m3_characteristics_probe and not (args.m3_configure_recovery and args.m3_recover_key):
        parser.error('characteristics probe requires the configured recovery candidate')
    if args.m3_recovery_public and (not args.m3_configure_recovery or args.m3_characteristics_probe):
        parser.error("public observation requires configured recovery without characteristics")
    hold = 0 if args.without_ufs or args.m2_metadata_files else args.ufs_report_hold_seconds
    uefi = Path(__file__).resolve().parents[1]
    if args.sources_only:
        write_sources(uefi, args.output.resolve())
        return
    base, device, edk2, out = [x.resolve() for x in [args.base, args.device, args.edk2, args.output]]
    sys.path.insert(0, str(base / "scripts"))
    from unixnu import cli, firmware, bootimg, tree
    from unixnu.config import Context
    # Firmware-only candidates may pin the last qualified format-1 board
    # while another workflow migrates the shared device to layered profiles.
    config_device = device
    binding = {"device": str(device), "config_ref": None}
    if args.device_config_ref:
        revision = subprocess.check_output(["git", "-C", str(device), "rev-parse",
                                             args.device_config_ref + "^{commit}"], text=True).strip()
        board = subprocess.check_output(["git", "-C", str(device), "show", revision + ":board.toml"])
        config_device = out / "config-input"
        config_device.mkdir(parents=True, exist_ok=True)
        existing = config_device / "board.toml"
        if existing.exists() and existing.read_bytes() != board:
            raise SystemExit("refusing to replace a candidate's pinned board input")
        existing.write_bytes(board)
        binding.update(config_ref=revision, board_sha256=hashlib.sha256(board).hexdigest())
    ctx = Context(cli.parser().parse_args(["build", "firmware", "-D", str(config_device),
                                           "--out", str(out), "--uefi", str(uefi),
                                           "--edk2", str(edk2), "-j", "10"]))
    ctx.device = device
    binding["framework_ref"] = subprocess.check_output(["git", "-C", str(base), "rev-parse", "HEAD"], text=True).strip()
    binding["framework_dirty"] = bool(subprocess.check_output(["git", "-C", str(base), "status", "--porcelain"], text=True))
    (out / "build-inputs.json").write_text(json.dumps(binding, indent=2) + "\n")
    if recovery_binding:
        shutil.copyfile(args.recovery_binding,out/"recovery-binding.json")
    if configure_binding:
        shutil.copyfile(args.configure_evidence,out/"configure-evidence.json")
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
    ctx.board["firmware"]["defines"]["FUXI_UFS_M2_FILES"] = str(int(args.m2_metadata_files))
    ctx.board["firmware"]["defines"]["FUXI_UFS_LUN4_KEYS"] = str(int(args.lun4_keymaster))
    ctx.board["firmware"]["defines"]["FUXI_M3_BRIDGE_LARGE"] = str(int(args.m3_bridge_large))
    ctx.board["firmware"]["defines"]["FUXI_M3_METADATA_KEY"] = str(int(args.m3_metadata_key))
    ctx.board["firmware"]["defines"]["FUXI_M3_SCM_INFO"] = str(int(args.m3_scm_info))
    ctx.board["firmware"]["defines"]["FUXI_M3_SCM_SUBJECTS"] = str(int(args.m3_scm_subjects))
    ctx.board["firmware"]["defines"]["FUXI_M3_SCM_INVOKE"] = str(int(args.m3_scm_invoke))
    ctx.board["firmware"]["defines"]["FUXI_M3_CRYPTO_CAP"] = str(int(args.m3_crypto_cap))
    ctx.board["firmware"]["defines"]["FUXI_M3_SCM_BRIDGE"] = str(int(args.m3_scm_bridge))
    ctx.board["firmware"]["defines"]["FUXI_M3_SMC_CONTEXT"] = str(int(args.m3_smc_context))
    ctx.board["firmware"]["defines"]["FUXI_M3_SMCI_OBJECT"] = str(int(args.m3_smci_mode == "object"))
    ctx.board["firmware"]["defines"]["FUXI_M3_SMCI_LOADER"] = str(int(args.m3_smci_loader))
    ctx.board["firmware"]["defines"]["FUXI_M3_SMCI_LOOKUP"] = str(int(args.m3_smci_lookup))
    ctx.board["firmware"]["defines"]["FUXI_M3_SMCI_LOOKUP_ARCH"] = str(int(args.m3_smci_lookup_arch))
    ctx.board["firmware"]["defines"]["FUXI_M3_SMCI_LOAD"] = str(int(args.m3_smci_load))
    ctx.board["firmware"]["defines"]["FUXI_M3_SMCI_VERSION"] = str(int(args.m3_smci_version))
    ctx.board["firmware"]["defines"]["FUXI_M3_SMCI_RESUME"] = str(int(args.m3_smci_resume))
    ctx.board["firmware"]["defines"]["FUXI_M3_SMCI_DATE"] = str(int(args.m3_smci_date))
    ctx.board["firmware"]["defines"]["FUXI_M3_SMCI_SETVER"] = str(int(args.m3_smci_setver))
    ctx.board["firmware"]["defines"]["FUXI_M3_KEY_RECOVERY"] = str(int(args.m3_recover_key))
    ctx.board["firmware"]["defines"]["FUXI_M3_RECOVERY_PUBLIC"] = str(int(args.m3_recovery_public))
    ctx.board["firmware"]["defines"]["FUXI_M3_CONFIGURE_RECOVERY"] = str(int(args.m3_configure_recovery))
    ctx.board["firmware"]["defines"]["FUXI_M3_CONFIGURE_PATCH"] = str(args.configure_patch)
    ctx.board["firmware"]["defines"]["FUXI_M3_CONFIGURE_TAG"] = configure_binding['tag'] if configure_binding else '0'
    ctx.board["firmware"]["defines"]["FUXI_M3_CHARACTERISTICS_PROBE"] = str(int(args.m3_characteristics_probe))
    ctx.board["firmware"]["defines"]["FUXI_M3_SECRET_EXCHANGE"] = str(int(args.m3_recover_key))
    ctx.board["firmware"]["defines"]["FUXI_M3_BINDING_NONE"] = str(int(args.m3_recover_key))
    ctx.board["firmware"]["defines"]["FUXI_M3_BINDING_TAG"] = recovery_binding['tag'] if recovery_binding else '0'
    ctx.board["firmware"]["defines"]["FUXI_M3_SMCI_ROOT"] = str(int(args.m3_smci_root))
    ctx.board["firmware"]["defines"]["FUXI_M3_BRIDGE_HLOS"] = str(int(args.m3_bridge_hlos))
    ctx.board["firmware"]["defines"]["FUXI_M3_BRIDGE_BLOB"] = str(int(args.m3_bridge_blob))
    ctx.board["firmware"]["defines"]["FUXI_M3_SCM_BRIDGE_CALL"] = str(int(args.m3_bridge_call))
    ctx.board["firmware"]["defines"]["FUXI_UFS_DIAGNOSTIC_PARK"] = str(int(args.m2_metadata_files))
    ctx.board["firmware"]["defines"]["FUXI_DATA_PORT_PROBE"] = "0"
    ctx.board["firmware"]["defines"]["FUXI_DATA_SCM_QUERY"] = "0"
    # Accepted M1 candidates ship with the trace off so the UFS block stays
    # readable; the receiver's per-packet EP0 traces would scroll it away.
    ctx.board["firmware"]["defines"]["FUXI_USB_EP0_TRACE"] = args.usb_ep0_trace
    ctx.board["firmware"]["defines"]["FUXI_USB_EP0_FORCERM"] = args.usb_ep0_forcerm
    (out / "board-effective.json").write_text(json.dumps(ctx.board, indent=2) + "\n")
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
    if args.m2_metadata_files:
        shutil.copyfile(image, out / "Mu-fuxi-m2-metadata.img")
    report = dict(lun4_keymaster=args.lun4_keymaster, m3_bridge_large=args.m3_bridge_large, image=str(image), sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                  bytes=image.stat().st_size,
                  mode=("M2 metadata read-only diagnostic; parks before USB" if args.m2_metadata_files else
                        "receiver-only image without the UFS diagnostic (A/B baseline)"
                        if args.without_ufs else
                        "receiver-only image with the M1 native UFS read-only diagnostic"),
                  dma_audit_only=False, dma_transfer_enabled=True,
                  usb_sid_route_enabled=True, usb_keep_phy=True,
                  ufs_report_cached=not args.without_ufs,
                  ufs_report_replay_at_receiver_park=not args.without_ufs and not args.m2_metadata_files,
                  m2_metadata_files=args.m2_metadata_files, m3_metadata_key=args.m3_metadata_key,
                  m3_key_paths=(["/vold", "/vold/metadata_encryption", "/vold/metadata_encryption/key"]
                                if args.m3_metadata_key else None),
                  m3_key_file_limit=8192 if args.m3_metadata_key else None,
                  m3_crypto_cap=args.m3_crypto_cap, m3_scm_bridge=args.m3_scm_bridge,
                  m3_smc_context=args.m3_smc_context,
                  m3_smci_root=args.m3_smci_root, m3_smci_loader=args.m3_smci_loader,
                  m3_smci_lookup=args.m3_smci_lookup, m3_smci_load=args.m3_smci_load,
                  m3_smci_lookup_arch=args.m3_smci_lookup_arch,m3_lookup_arch_binding=lookup_binding,
                  m3_smci_version=args.m3_smci_version, m3_smci_resume=args.m3_smci_resume, m3_smci_setver=args.m3_smci_setver, m3_smci_date=args.m3_smci_date,
                  m3_recover_key=args.m3_recover_key, m3_recovery_binding=recovery_binding,
                  m3_configure_recovery=args.m3_configure_recovery,m3_configure_binding=configure_binding,
                  m3_characteristics_probe=args.m3_characteristics_probe, m3_recovery_public=args.m3_recovery_public,
                  m3_recovery_output_discarded=bool(args.m3_recover_key),
                  m3_smci_mode=("context" if args.m3_smc_context else args.m3_smci_mode) if args.m3_smci_root else None,
                  m3_smci_fnid=("42000601" if args.m3_smc_context else "72000602" if args.m3_smci_mode == "object" else "72000600") if args.m3_smci_root else None,
                  m3_smci_arginfo=("1" if args.m3_smc_context else "224") if args.m3_smci_root else None,
                  m3_smci_ops=(["standard-info-control"] if args.m3_smc_context else ["root-register-null", "open-loader-uid122", "lookup-keymaster64", "lookup-keymaster", "ta-release", "loader-release", "environment-release"] if args.m3_smci_lookup else ["root-register-null", "open-loader-uid122", "loadfrombuffer-keymaster64", "get-version", "set-version-200", "ta-release", "loader-release", "environment-release"] if args.m3_smci_setver else ["root-register-null", "open-loader-uid122", "loadfrombuffer-keymaster64", "get-version", "date-support", "ta-release", "loader-release", "environment-release"] if args.m3_smci_date else ["root-register-null", "open-loader-uid122", "loadfrombuffer-keymaster64", "get-version", "ta-release", "loader-release", "environment-release"] if args.m3_smci_version else ["root-register-null", "open-loader-uid122", "loadfrombuffer-keymaster64", "ta-release", "loader-release", "environment-release"] if args.m3_smci_load else ["root-register-null", "open-loader-uid122", "loader-release", "environment-release"] if args.m3_smci_loader else ["root-register-null", "remote-release"]) if args.m3_smci_root else None,
                  m3_smci_ta_bytes=0x63058 if args.m3_smci_load else None,
                  m3_smci_no_keys=(not args.m3_recover_key) if args.m3_smci_root else None,
                  m3_bridge_abi="standard64-a0-status-a1-service-a2-handle64" if args.m3_bridge_call else None,
                  m3_bridge_fnids=["42000c1c","42000c1e","42000c1d"] if args.m3_bridge_call and not args.m3_smc_context else [],
                  m3_bridge_hlos=args.m3_bridge_hlos,
                  m3_bridge_profile=("hlos" if args.m3_bridge_hlos else "zero-vm-control") if args.m3_bridge_call and not args.m3_smc_context else None,
                  m3_bridge_vm_count=1 if args.m3_bridge_hlos else 0,
                  m3_bridge_vmid=3 if args.m3_bridge_hlos else 0,
                  m3_bridge_ns_perm=6 if args.m3_bridge_hlos else 0,
                  m3_bridge_tz_perm=6, m3_bridge_hyp_flags=0,
                  m3_bridge_blob=args.m3_bridge_blob,
                  m3_bridge_bytes=0x82000 if args.m3_bridge_large else 0 if args.m3_smc_context else 8192 if (args.m3_bridge_blob or args.m3_smci_root) else (8192 if args.m3_bridge_call else None),
                  m3_blob_bytes=208 if args.m3_bridge_blob else None,
                  m3_blob_sha256="9a57f01af0b8c9836cdf04f9abc2f83ad21baf94527b2c80b18b06f04ab2321e" if args.m3_bridge_blob else None,
                  m3_blob_prefix_bytes=32 if args.m3_bridge_blob else None,
                  m3_bridge_call=args.m3_bridge_call,
                  m3_bridge_ops=([] if args.m3_smc_context else ["enable", "create", "delete"] if args.m3_bridge_call else None), m3_scm_info=args.m3_scm_info, m3_scm_subjects=args.m3_scm_subjects, m3_scm_invoke=args.m3_scm_invoke, diagnostic_park_before_usb=args.m2_metadata_files,
                  m2_target_path="/aconfig/maps/system.package.map" if args.m2_metadata_files else None,
                  m2_reference_bytes=10527 if args.m2_metadata_files else None,
                  m2_reference_sha256="14f3d8675423917e383a71c936f4d9a81a29480f34ae3c550e0f4c34e53a0991" if args.m2_metadata_files else None,
                  receiver_runtime_enabled=not args.m2_metadata_files,
                  ufs_report_hold_seconds=hold,
                  fuxi_data_port_ufs=not args.without_ufs, fuxi_data_port_probe=False,
                  usb_ep0_trace=args.usb_ep0_trace == "1",
                  usb_ep0_endtransfer_forcerm=args.usb_ep0_forcerm == "1",
                  native_ufs_takeover=("absent; --without-ufs" if args.without_ufs else
                                        "diagnostic only; read commands, no writes, no keys"),
                  controller="DWC3 USB2, SM8550 inherited ABL PHY/clocks",
                  hardware_result="pending", kernel_handoff=False, receiver_only=not args.m2_metadata_files, diagnostic_only=args.m2_metadata_files,
                  partition_io=False, raw_partition_reads=not args.without_ufs,
                  partition_writes=False, system_handoff=False)
    if args.m3_smci_lookup_arch:
        report['m3_smci_ops']=['root-register-null','open-loader-uid122','lookup-keymaster64-arch','ta-release','loader-release','environment-release']
    if args.m3_recover_key:
        report['m3_smci_ops']=['root-register-null','open-loader-uid122','loadfrombuffer-keymaster64','get-version','recover-existing-key','wipe-recovered-key','ta-release','loader-release','environment-release']
        if args.m3_configure_recovery:report['m3_smci_ops'].insert(4,'configure-public-once')
        if args.m3_characteristics_probe:report['m3_smci_ops'].insert(5,'characteristics-probe')
        report['native_ufs_takeover']='read-only diagnostic; existing key recovery, no convert/ICE or userdata decryption'
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
        *sorted((uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe").glob("*.[ch]")),
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/FuxiNativeUfsDxe.inf",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M2Diagnostic.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3KeyDiagnostic.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3BridgeBlob.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3BridgeDiagnostic.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3SmciDiagnostic.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3RecoveryDiagnostic.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3ConfigureDiagnostic.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3CharacteristicsDiagnostic.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/M3KeyMintBackend.c",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/M3KeyMintBackend.h",
        uefi / "tools/test_fuxi_m3_characteristics.py",
        uefi / "tools/tests/m3_characteristics_host.c",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3SmcContext.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Include/APRIORI.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/fuxi.dsc", uefi / "Platforms/Xiaomi/fuxiPkg/fuxi.fdf",
        uefi / "Platforms/Xiaomi/fuxiPkg/Include/DXE.inc",
        uefi / "Platforms/Xiaomi/fuxiPkg/Library/MemoryMapLib/MemoryMapLib.c",
        uefi / "Platforms/Xiaomi/fuxiPkg/Library/MemoryMapLib/MemoryMapLib.inf",
        uefi / "Platforms/Xiaomi/fuxiPkg/Include/Protocol/FuxiUfsReport.h",
        *sorted((uefi / "tools/tests").glob("dwc3_*_host.c")),
        uefi / "tools/test_fuxi_usb_state.py",
        *sorted((uefi / "tools/tests").glob("fuxi_f2fs*_host.c")),
        *sorted((uefi / "tools").glob("test_fuxi_f2fs*.py")),
        Path(__file__),
        uefi / "tools/m3_recovery_binding.py",
        uefi / "tools/m3_lookup_arch_binding.py",
        uefi / "tools/test_fuxi_m3_lookup_arch.py",
        uefi / "tools/tests/m3_lookup_arch_host.c",
        uefi / "tools/audit_fuxi_m3_lookup_arch_contract.py",
        uefi / "docs/evidence/fuxi-m3-deployed-loader-20261030.json",
        uefi / "tools/m3_configure_binding.py",
        uefi / "tools/test_m3_configure_binding.py",
        uefi / "tools/check_fuxi_m3_configure_pair.py",
        uefi / "tools/audit_fuxi_m3_configure_profiles.py",
        uefi / "tools/qualify_fuxi_ufs_candidate.py",
        uefi / "tools/check_fuxi_ufs_report_image.py",
        uefi / "tools/check_fuxi_m3_live_objects.py",
        uefi / "tools/test_m3_recovery_binding.py",
        uefi / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/M3BlobPublic.h",
        uefi / "tools/test_fuxi_m3_native_public.py",
        uefi / "tools/collect_fuxi_m3_blob_public.py",
        uefi / "tools/test_fuxi_m3_blob_public.py",
        uefi / "tools/tests/m3_blob_public_host.c",
        uefi / "tools/tests/m3_public_blob_fixture.inc",
        uefi / "tools/test_fuxi_m3_recovery_entry.py",
        uefi / "tools/tests/m3_smci_resume_host.c",
        uefi / "tools/tests/m3_recovery_entry_fixture.inc",
        uefi / "tools/tests/m3_recovery_entry_cases.inc",
        uefi / "tools/tests/m3_configure_monitor.inc",
        uefi / "tools/tests/m3_configured_recovery_cases.inc",
        uefi / "tools/tests/m3_characteristics_monitor.inc",
        uefi / "tools/tests/m3_characteristics_entry_cases.inc",
        uefi / "docs/evidence/fuxi-m3-android-binding-20261030.json",
        uefi / "docs/evidence/fuxi-m3-configure-gate-20261030.json",
        uefi / "docs/evidence/fuxi-m3-configure-profiles-20261030.json",
        uefi / "docs/evidence/fuxi-m3-twrp-keystore-context-20261030.json",
    ]
    (out / "sources.json").write_text(json.dumps({str(x.relative_to(uefi)):
        hashlib.sha256(x.read_bytes()).hexdigest() for x in paths if x.is_file()}, indent=2) + "\n")


if __name__ == "__main__":
    main()
