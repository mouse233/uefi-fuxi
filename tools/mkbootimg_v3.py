#!/usr/bin/env python3
"""Android boot image v3 packer (Mu-Silicium / UniXNU layout on SM8550).

Layout, verified byte-for-byte against Mu-Silicium v4.0 `Mu-qrd8550.img`
(2026-10-21):

    0x0000  header, 1580 bytes, zero-padded to PAGE (4096)
    0x1000  kernel field:
              gzip stream  = BootShim + UEFI firmware volume
              device tree  = raw FDT, appended right after the gzip stream
            kernel_size covers BOTH parts
            ramdisk
            zero padding to PAGE

Measured on the reference image:
    gzip consumed      1,074,187 bytes
    decompressed       3,145,840 bytes   (~3 MiB firmware volume)
    appended FDT         776,668 bytes   (starts with 0xd00dfeed)

The Android bootloader decompresses the kernel field and hands control to
BootShim. BootShim copies the FD and preserves x0; it does not parse gzip or
locate the DTB. The DTB handoff is a separate platform/bootloader contract.

This tool handles the current fuxi v3 container profile. A syntactically valid
container, a reference qrd8550 image, or a fastboot acknowledgement does not
establish that this device's ABL accepts or successfully executes the payload.
The generic UniXNU overview/verifier currently describes a v0 pipeline.

Usage:
    python mkbootimg_v3.py pack   --kernel K [--dtb D] [--ramdisk R] --out boot.img
    python mkbootimg_v3.py unpack --image boot.img --outdir DIR
    python mkbootimg_v3.py info   --image boot.img
"""
import argparse
import os
import struct
import zlib
from pathlib import Path

MAGIC = b"ANDROID!"
FDT_MAGIC = b"\xd0\x0d\xfe\xed"
PAGE = 4096
HEADER_SIZE = 1580
VERSION = 3


def _header(kernel_size, ramdisk_size, os_version, cmdline):
    cmd = cmdline.encode("utf-8")[:1535]
    cmd += b"\x00" * (1536 - len(cmd))
    h = bytearray()
    h += MAGIC
    h += struct.pack("<I", kernel_size)
    h += struct.pack("<I", ramdisk_size)
    h += struct.pack("<I", os_version)
    h += struct.pack("<I", HEADER_SIZE)
    h += struct.pack("<IIII", 0, 0, 0, 0)
    h += struct.pack("<I", VERSION)
    h += cmd
    assert len(h) == HEADER_SIZE, len(h)
    return bytes(h)


def pack(kernel, dtb, ramdisk, out, cmdline="", os_version=0):
    k = Path(kernel).read_bytes()
    t = Path(dtb).read_bytes() if dtb else b""
    r = Path(ramdisk).read_bytes() if ramdisk else b""

    if k[:2] != b"\x1f\x8b":
        print("warning: kernel is not gzip; this profile expects a gzip kernel field", flush=True)
    if t and t[:4] != FDT_MAGIC:
        print("warning: dtb does not start with the FDT magic", flush=True)
    if not t:
        print("warning: no dtb given; the image has no appended device tree", flush=True)

    field = k + t
    hdr = _header(len(field), len(r), os_version, cmdline)
    kernel_pad = (-len(field)) % PAGE
    ramdisk_pad = (-len(r)) % PAGE

    with open(out, "wb") as f:
        f.write(hdr)
        f.write(b"\x00" * ((-len(hdr)) % PAGE))
        f.write(field)
        f.write(b"\x00" * kernel_pad)
        f.write(r)
        f.write(b"\x00" * ramdisk_pad)

    print(f"packed {out}")
    print(f"  header        {len(hdr)} (kernel at {(len(hdr) + PAGE - 1) // PAGE * PAGE:#x})")
    print(f"  gzip          {len(k)}")
    print(f"  dtb           {len(t)}")
    print(f"  kernel_size   {len(field)}")
    print(f"  ramdisk       {len(r)}")
    print(f"  padding       kernel={kernel_pad} ramdisk={ramdisk_pad}")
    print(f"  total         {len(hdr) + ((-len(hdr)) % PAGE) + len(field) + kernel_pad + len(r) + ramdisk_pad}")


def parse(path):
    d = Path(path).read_bytes()
    if len(d) < HEADER_SIZE or d[:8] != MAGIC:
        raise ValueError("missing or truncated Android v3 header")
    ks, = struct.unpack_from("<I", d, 8)
    rs, = struct.unpack_from("<I", d, 12)
    osv, = struct.unpack_from("<I", d, 16)
    hs, = struct.unpack_from("<I", d, 20)
    hv, = struct.unpack_from("<I", d, 40)
    if hv != VERSION or hs != HEADER_SIZE:
        raise ValueError(f"expected v3 header size {HEADER_SIZE}, got version={hv} size={hs}")
    ramdisk_at = PAGE + ((ks + PAGE - 1) // PAGE) * PAGE
    required_size = ramdisk_at + ((rs + PAGE - 1) // PAGE) * PAGE
    if len(d) < required_size:
        raise ValueError(f"truncated boot image: need {required_size} bytes, got {len(d)}")
    cmdline = d[44:44 + 1536].split(b"\x00")[0].decode("utf-8", "replace")
    return dict(file_size=len(d), kernel_size=ks, ramdisk_size=rs, os_version=osv,
                header_size=hs, header_version=hv, cmdline=cmdline,
                kernel_at=PAGE, ramdisk_at=ramdisk_at, data=d)


def split_field(buf):
    """Split a kernel field into (gzip_bytes, dtb_bytes)."""
    if buf[:2] != b"\x1f\x8b":
        return buf, b""
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    dec.decompress(buf)
    used = len(buf) - len(dec.unused_data)
    return buf[:used], dec.unused_data


def unpack(image, outdir):
    i = parse(image)
    os.makedirs(outdir, exist_ok=True)
    d, off = i["data"], i["kernel_at"]
    field = d[off:off + i["kernel_size"]]
    off = i["ramdisk_at"]
    gz, dtb = split_field(field)
    (Path(outdir) / "kernel").write_bytes(gz)
    (Path(outdir) / "dtb").write_bytes(dtb)
    (Path(outdir) / "ramdisk").write_bytes(d[off:off + i["ramdisk_size"]])
    print(f"unpacked to {outdir}: gzip={len(gz)} dtb={len(dtb)} ramdisk={i['ramdisk_size']}")


def info(image):
    i = parse(image)
    d, off = i["data"], i["kernel_at"]
    field = d[off:off + i["kernel_size"]]
    gz, dtb = split_field(field)
    print(f"  {'header_version':16}: {i['header_version']}")
    print(f"  {'header_size':16}: {i['header_size']}  (kernel at {i['kernel_at']:#x})")
    print(f"  {'kernel_size':16}: {i['kernel_size']}  = gzip {len(gz)} + dtb {len(dtb)}")
    print(f"  {'ramdisk_size':16}: {i['ramdisk_size']}")
    print(f"  {'ramdisk_at':16}: {i['ramdisk_at']:#x}")
    print(f"  {'file_size':16}: {i['file_size']}")
    if gz:
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = dec.decompress(gz) + dec.flush()
        print(f"  {'gzip decompresses':16}: {len(out)} bytes")
    if dtb:
        m, tot = struct.unpack_from(">II", dtb, 0)[0], struct.unpack_from(">I", dtb, 4)[0]
        print(f"  {'dtb':16}: magic {m:#x} totalsize {tot} "
              f"({'header matches' if m == 0xd00dfeed and tot == len(dtb) else 'MISMATCH'})")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pack")
    p.add_argument("--kernel", required=True)
    p.add_argument("--dtb", default="")
    p.add_argument("--ramdisk", default="")
    p.add_argument("--out", required=True)
    p.add_argument("--cmdline", default="")
    p.add_argument("--os-version", type=int, default=0)

    u = sub.add_parser("unpack")
    u.add_argument("--image", required=True)
    u.add_argument("--outdir", required=True)

    n = sub.add_parser("info")
    n.add_argument("--image", required=True)

    a = ap.parse_args()
    if a.cmd == "pack":
        pack(a.kernel, a.dtb, a.ramdisk, a.out, a.cmdline, a.os_version)
    elif a.cmd == "unpack":
        unpack(a.image, a.outdir)
    else:
        info(a.image)


if __name__ == "__main__":
    main()
