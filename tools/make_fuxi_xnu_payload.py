#!/usr/bin/env python3
"""Create the stage-2a FAT16 payload that drives the DarwinBoot loader path.

Same identified 4 MiB geometry as make_fuxi_payload.py, so FuxiPayloadDxe
accepts it unchanged. Adds an `xnu` entry plus a synthetic Mach-O kernel and
its Apple device-tree sidecar. The synthetic pair exists only to walk
DarwinBoot's validation path: it is generated here, contains no Apple code,
and is never executed, because the ADT asks for a window far larger than any
run this firmware can offer.

Run on the build host with dosfstools/mtools; never accesses a phone.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

SIZE = 4 * 1024 * 1024

# Default window request is deliberately unsatisfiable: DarwinBoot then refuses
# the allocation and returns, instead of exiting boot services into the
# fixture. Pass --window 0x10000000 to ask for a window this firmware can
# actually supply, which makes the loader hand off and jump into the fixture.
DEFAULT_WINDOW = 0x200000000
MIN_WINDOW = 0x10000000
MAX_WINDOW = 0x200000000

KERNEL_BASE = 0xFFFFFFF007004000
KERNEL_ENTRY = KERNEL_BASE + 0x1000

CONFIG = '''# Stage 2a: exercise the DarwinBoot loader path from UniXNU.
# No initrd and no dtb, so the loader request carries neither; DarwinBoot's
# own checks reject a non-NULL device tree, and this entry must not set one.
version = 1
[boot]
timeout = 5
default = "xnu"
[ui]
title = "%(title)s"
[[entry]]
id = "xnu"
title = "XNU loader path test"
type = "xnu"
path = "Payloads/kernel.macho"
[[entry]]
id = "exit"
title = "Return to firmware"
type = "action"
action = "exit"
[[entry]]
id = "reset"
title = "Restart"
type = "action"
action = "reset"
[[entry]]
id = "shutdown"
title = "Power off"
type = "action"
action = "shutdown"
'''


def macho():
    """Minimal 64-bit Mach-O that satisfies DarwinBoot's ParseKernel()."""
    def segment(name, address, size, offset, length, protection):
        return struct.pack('<II16sQQQQiiII', 0x19, 72, name, address, size, offset,
                           length, protection, protection, 0, 0)

    state = bytearray(272)
    struct.pack_into('<Q', state, 256, KERNEL_ENTRY)
    commands = (segment(b'__TEXT', KERNEL_BASE, 0x2000, 0, 0x2000, 5)
                + segment(b'__DATA', KERNEL_BASE + 0x4000, 0x1000, 0, 0, 3)
                + struct.pack('<IIII', 5, 288, 6, 68) + state)
    image = bytearray(0x2000)
    image[:32] = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 3, len(commands), 0, 0)
    image[32:32 + len(commands)] = commands
    # If the loader ever does reach the entry, spin instead of running data.
    image[0x1000:0x1004] = struct.pack('<I', 0x14000000)  # b .
    return bytes(image)


def node(name, properties=(), children=()):
    props = [('name', name.encode() + b'\0'), *properties]
    data = struct.pack('<II', len(props), len(children))
    for key, value in props:
        data += struct.pack('<32sI', key.encode(), len(value)) + value + bytes(-len(value) % 4)
    return data + b''.join(children)


def adt(window):
    return node('device-tree', children=[node(
        'chosen', [('darwinboot-memory-size', struct.pack('<Q', window))])])


def make(output, window, title):
    for tool in ("mkfs.fat", "mmd", "mcopy", "mtype", "fsck.fat"):
        if not shutil.which(tool):
            raise RuntimeError(f"missing {tool}; install dosfstools and mtools")
    if not (MIN_WINDOW <= window <= MAX_WINDOW) or (window & 0x1FFFFF):
        raise SystemExit(f"window {window:#x} outside DarwinWindowSizeValid")
    config_text = CONFIG % {"title": title}
    tree_bytes = adt(window)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(output)
    with tempfile.TemporaryDirectory(prefix="fuxi-fat-", dir=output.parent) as tmp:
        temp = Path(tmp)
        image = temp / "payload.img"
        config = temp / "unixnu.toml"
        tree = temp / "kernel.macho.adt"
        config.write_text(config_text)
        tree.write_bytes(tree_bytes)
        env = dict(os.environ, MTOOLS_SKIP_CHECK="0", TZ="UTC", SOURCE_DATE_EPOCH="1792627200")

        def run(*args):
            return subprocess.run(list(map(str, args)), check=True, capture_output=True, env=env).stdout

        run("mkfs.fat", "--invariant", "-a", "-F", "16", "-S", "512", "-s", "1",
            "-R", "1", "-r", "256", "-f", "2", "-n", "FUXIPAYLOAD", "-i", "46555832",
            "-C", image, "4096")
        data = bytearray(image.read_bytes())
        data[3:11] = b"FUXIPAYL"
        assert len(data) == SIZE
        assert struct.unpack_from("<H", data, 11)[0] == 512 and data[13] == 1
        assert struct.unpack_from("<H", data, 14)[0] == 1 and data[16] == 2
        assert struct.unpack_from("<HH", data, 17) == (256, 8192)
        assert struct.unpack_from("<H", data, 22)[0] == 32
        assert struct.unpack_from("<I", data, 39)[0] == 0x46555832
        assert data[43:54] == b"FUXIPAYLOAD "[:11]
        assert data[510:512] == b"\x55\xaa"
        image.write_bytes(data)
        run("mmd", "-i", image, "::/EFI")
        run("mmd", "-i", image, "::/EFI/UniXNU")
        run("mmd", "-i", image, "::/EFI/UniXNU/Payloads")
        run("mcopy", "-i", image, config, "::/EFI/UniXNU/unixnu.toml")
        for name, blob in (("kernel.macho", macho()), ("kernel.macho.adt", tree_bytes)):
            path = temp / name
            path.write_bytes(blob)
            run("mcopy", "-i", image, path, f"::/EFI/UniXNU/Payloads/{name}")
        readback = run("mtype", "-i", image, "::/EFI/UniXNU/unixnu.toml")
        assert readback == config_text.encode(), "FAT/LFN readback mismatch"
        assert run("mtype", "-i", image, "::/EFI/UniXNU/Payloads/kernel.macho") == macho()
        assert run("mtype", "-i", image, "::/EFI/UniXNU/Payloads/kernel.macho.adt") == tree_bytes
        fsck = run("fsck.fat", "-n", image).decode()
        assert "differ" not in fsck.lower(), fsck
        shutil.copyfile(image, output)
    manifest = {
        "bytes": output.stat().st_size,
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "volume_label": "FUXIPAYLOAD", "volume_id": "0x46555832",
        "config": "EFI/UniXNU/unixnu.toml",
        "config_sha256": hashlib.sha256(config_text.encode()).hexdigest(),
        "kernel": "EFI/UniXNU/Payloads/kernel.macho",
        "kernel_sha256": hashlib.sha256(macho()).hexdigest(),
        "adt": "EFI/UniXNU/Payloads/kernel.macho.adt",
        "adt_sha256": hashlib.sha256(tree_bytes).hexdigest(),
        "requested_window": hex(window),
        # Largest 2 MiB-aligned window the 5 GiB bank at 0x8C0000000 can hold,
        # after DarwinBoot adds the 0x4000 low bits of the kernel link address.
        "window_satisfiable": window <= 0x13FE00000,
        "expected_menu_title": title,
        "expected_default_entry": "xnu",
        "fsck": fsck,
        "scope": "synthetic Mach-O/ADT only; no XNU kernel, no initrd, no kexts",
    }
    output.with_suffix(".json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--window", type=lambda v: int(v, 0), default=DEFAULT_WINDOW,
                        help="darwinboot-memory-size in the synthetic ADT, 2 MiB aligned")
    parser.add_argument("--title", default="fuxi xnu loader stage",
                        help="[ui] title, so candidates are distinguishable on screen")
    args = parser.parse_args()
    make(args.output, args.window, args.title)