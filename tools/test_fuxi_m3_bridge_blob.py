#!/usr/bin/env python3
"""Exercise C1 production F2FS/SHA and lifecycle, with simulated SMC only."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile


def fixture(path, original, kind):
    original(path)
    data = bytes((i * 7 + 0xa5) & 255 for i in range(208))
    directory = bytearray(4096)
    slot = 0
    for name, nid, mode in [('.',6,2),('..',5,2),('keymaster_key_blob',8,1),('version',7,1)]:
        raw = name.encode()
        used = (len(raw)+7)//8
        for i in range(used):
            directory[(slot+i)//8] |= 1 << ((slot+i)%8)
        struct.pack_into('<IHB',directory,30+slot*11+4,nid,len(raw),mode)
        directory[30+214*11+slot*8:30+214*11+slot*8+len(raw)] = raw
        slot += used
    with path.open('r+b') as f:
        f.seek(4503*4096); f.write(directory)
        f.seek(4105*4096); inode = bytearray(f.read(4096))
        struct.pack_into('<Q',inode,16,208 if kind != 'size' else 209)
        if kind == 'inline':
            inode[3] = 10
            inode[364:364+208] = data
        f.seek(4105*4096); f.write(inode)
        f.seek(4505*4096); f.write(data)
        if kind == 'version':
            f.seek(4504*4096); f.write(b'2')
        if kind == 'missing':
            f.seek(4503*4096+30+214*11+2*8); f.write(b'X')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--edk2',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    src = root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
    native = root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe'
    spec = importlib.util.spec_from_file_location('key_fixture',root/'tools/test_fuxi_m3_key_paths.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    arch = 'AArch64' if platform.machine() in ('aarch64','arm64') else 'X64'
    sources = [src/n for n in ('DataReadOnly.c','F2fsReadOnly.c','F2fsFiles.c')]
    paths = [*sources,src/'DataReadOnly.h',src/'F2fsReadOnly.h',native/'UfsSha256.c',
             native/'UfsSha256.h',native/'M3BridgeBlob.inc',native/'M3BridgeDiagnostic.inc',
             root/'tools/tests/m3_bridge_blob_host.c',root/'tools/test_fuxi_m3_key_paths.py',Path(__file__)]
    digests = {}
    with tempfile.TemporaryDirectory(prefix='fuxi-c1-') as directory:
        tmp = Path(directory); binary = tmp/'c1-host'
        command = [shutil.which('clang') or 'clang','-std=c11','-Wall','-Wextra','-Werror',
                   '-fshort-wchar','-fsanitize=address,undefined','-fno-omit-frame-pointer',
                   '-I',str(args.edk2/'MdePkg/Include'),'-I',str(args.edk2/'MdePkg/Include'/arch),
                   '-I',str(src),'-I',str(native),str(root/'tools/tests/m3_bridge_blob_host.c'),
                   *map(str,sources),str(native/'UfsSha256.c'),'-o',str(binary)]
        subprocess.run(command,check=True)
        for kind in ('block','inline','version','size','missing'):
            image = tmp/(kind+'.img')
            digests[kind] = fixture(image,mod.build_image,kind)
            subprocess.run([str(binary),str(image),'valid' if kind in ('block','inline') else 'invalid'],check=True)
    report = dict(result='passed',sanitizers=['address','undefined'],fixtures=digests,
                  scope='Production C1 F2FS/SHA/bridge lifecycle; inline and block files; length/version/hash/cache corruption; allocation/read/enable/create/delete failures; simulated SMC only',
                  sources={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
