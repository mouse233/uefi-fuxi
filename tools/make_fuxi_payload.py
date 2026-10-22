#!/usr/bin/env python3
"""Create the small, identified FAT16 volume used by FuxiPayloadDxe.

Run on the build host with dosfstools/mtools; never accesses a phone or mounts
a host disk. Every tool receives a regular image file via -i/-C.
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
CONFIG = '''# Diagnostic configuration: no kernel, drivers, kits or disk writes.
version = 1
[boot]
timeout = -1
default = "exit"
[ui]
title = "fuxi payload OK"
[[entry]]
id = "exit"
title = "Return to firmware (payload read OK)"
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


def make(output):
    for tool in ("mkfs.fat", "mmd", "mcopy", "mtype", "fsck.fat"):
        if not shutil.which(tool):
            raise RuntimeError(f"missing {tool}; install dosfstools and mtools")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(output)
    with tempfile.TemporaryDirectory(prefix="fuxi-fat-", dir=output.parent) as tmp:
        temp = Path(tmp)
        image = temp / "payload.img"
        config = temp / "unixnu.toml"
        config.write_text(CONFIG)
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
        assert data[43:54] == b"FUXIPAYLOAD "[:11]  # eleven-character volume label
        assert data[510:512] == b"\x55\xaa"
        image.write_bytes(data)
        run("mmd", "-i", image, "::/EFI")
        run("mmd", "-i", image, "::/EFI/UniXNU")
        run("mcopy", "-i", image, config, "::/EFI/UniXNU/unixnu.toml")
        readback = run("mtype", "-i", image, "::/EFI/UniXNU/unixnu.toml")
        assert readback == CONFIG.encode(), "FAT/LFN readback mismatch"
        fsck = run("fsck.fat", "-n", image).decode()
        shutil.copyfile(image, output)
    manifest = {"bytes": output.stat().st_size, "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "volume_label": "FUXIPAYLOAD", "volume_id": "0x46555832",
                "config": "EFI/UniXNU/unixnu.toml", "config_sha256": hashlib.sha256(CONFIG.encode()).hexdigest(),
                "expected_menu_title": "fuxi payload OK", "fsck": fsck,
                "scope": "read-only configuration diagnostic; no XNU"}
    output.with_suffix(".json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    make(parser.parse_args().output)
