#!/usr/bin/env python3
"""Record the exact source, dependencies and verified DEBUG artifacts."""
import argparse
import hashlib
import json
import os
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def command(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    config_path = root / "Resources/Configs/fuxi.toml"
    import tomllib
    with config_path.open("rb") as stream:
        config = tomllib.load(stream)
    image = root / "Mu-fuxi.img"
    fd = root / "Build/fuxiPkg/DEBUG_CLANGPDB/FV/SILICIUM_UEFI.fd"
    with image.open("rb") as stream:
        header = stream.read(4096)
    if header[:8] != b"ANDROID!" or len(header) != 4096:
        raise ValueError("missing Android boot image header")
    kernel_size, ramdisk_size = struct.unpack_from("<II", header, 8)
    header_size, version = struct.unpack_from("<I", header, 20)[0], struct.unpack_from("<I", header, 40)[0]
    if version != 3 or header_size != 1580:
        raise ValueError(f"expected Android header v3/1580, got {version}/{header_size}")
    expected_size = 4096 + ((kernel_size + 4095) // 4096) * 4096 + ((ramdisk_size + 4095) // 4096) * 4096
    if image.stat().st_size != expected_size:
        raise ValueError("boot image payload size/padding disagrees with header")
    if fd.stat().st_size != config["uefi_fd"]["size"]:
        raise ValueError("firmware volume size disagrees with fuxi.toml")
    unixnu = Path(os.environ.get("UNIXNU_ROOT", str(root / "UniXNU"))).resolve()
    shim = root / "BootShim/BootShim.bin"
    symbols = command("llvm-nm", "-n", "BootShim/BootShim.elf", cwd=root)
    stage_labels = [any(line.split()[-1:] == [name] for line in symbols.splitlines())
                    for name in ("_Stage1Marker", "_Stage2Marker")]
    if stage_labels[0] != stage_labels[1]:
        raise ValueError("incomplete BootShim stage-marker symbols")
    markers = all(stage_labels)
    manifest = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": command("git", "rev-parse", "HEAD", cwd=root),
        "source_branch": command("git", "branch", "--show-current", cwd=root),
        "working_tree_status": command("git", "status", "--porcelain", "--untracked-files=no", cwd=root),
        "submodules": command("git", "submodule", "status", "--recursive", cwd=root).splitlines(),
        "unixnu_commit": command("git", "rev-parse", "HEAD", cwd=unixnu),
        "darwinboot_commit": command("git", "rev-parse", "HEAD", cwd=unixnu / "drivers/DarwinBoot"),
        "clang_version": command("clang", "--version"),
        "python_version": command("python3", "--version"),
        "pip_freeze": command("python3", "-m", "pip", "freeze").splitlines(),
        "build_command": 'UNIXNU_ROOT="$PWD/UniXNU" ./build_uefi.py -d fuxi -r DEBUG -c' + (' --boot-stage-markers' if markers else ''),
        "boot_shim": {"size": shim.stat().st_size, "sha256": hashlib.sha256(shim.read_bytes()).hexdigest(),
                      "stage_markers": markers,
                      "marker_config": config["boot_shim"]["stage_markers"] if markers else None},
        "fd_base": config["uefi_fd"]["base"],
        "fd_size": config["uefi_fd"]["size"],
        "android_header": {"version": version, "header_size": header_size, "kernel_size": kernel_size, "ramdisk_size": ramdisk_size},
        "artifacts": [{"path": str(p.relative_to(root)), "size": p.stat().st_size,
                       "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in (image, fd)],
        "hardware_boot_verified": False,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (args.output / "source.diff").write_text(command("git", "diff", "HEAD", cwd=root) + "\n")
    (args.output / "image-header.txt").write_text(command("python3", "tools/mkbootimg_v3.py", "info", "--image", "Mu-fuxi.img", cwd=root) + "\n")
    print(json.dumps({"manifest": str(args.output / "manifest.json"), "artifacts": manifest["artifacts"]}, indent=2))


if __name__ == "__main__":
    main()
