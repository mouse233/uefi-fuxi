#!/usr/bin/env python3
"""Read-only TWRP metadata-block reference; no key material or block contents saved."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

SERIAL = 'fcde91e'
DM_PATH = re.compile(r'^/dev/block/(dm-[0-9]+)$')
RAW_PATH = re.compile(r'^/dev/block/([A-Za-z0-9._-]+)$')


def collect(run):
    def text(*args):
        return run(*args).decode('utf-8', 'strict').strip()
    if text('get-state') != 'recovery':
        raise RuntimeError('device is not in recovery')
    product = text('shell', 'getprop', 'ro.product.device')
    serial = text('shell', 'getprop', 'ro.boot.serialno')
    twrp = text('shell', 'getprop', 'ro.twrp.version')
    release = text('shell', 'getprop', 'ro.build.version.release')
    if product != 'fuxi' or serial != SERIAL or not twrp or release != '17':
        raise RuntimeError('unexpected recovery identity or version')
    mounts = text('shell', 'cat', '/proc/mounts').splitlines()
    data = [line.split() for line in mounts if len(line.split()) >= 4 and line.split()[1] == '/data']
    metadata = [line.split() for line in mounts if len(line.split()) >= 4 and line.split()[1] == '/metadata']
    if len(data) != 1 or len(metadata) != 1 or data[0][2] != 'f2fs':
        raise RuntimeError('expected mounted /data and /metadata were not found uniquely')
    match = DM_PATH.fullmatch(data[0][0])
    if not match:
        raise RuntimeError('/data is not backed by the expected dm block path')
    dm_name = match.group(1)
    raw_path = text('shell', 'readlink', '-f', '/dev/block/by-name/userdata')
    raw_match = RAW_PATH.fullmatch(raw_path)
    if not raw_match:
        raise RuntimeError('unexpected userdata device path')
    mapped_name = text('shell', 'cat', f'/sys/class/block/{dm_name}/dm/name')
    slaves = text('shell', 'ls', '-1', f'/sys/class/block/{dm_name}/slaves').splitlines()
    if not mapped_name or not slaves or any(not re.fullmatch(r'[A-Za-z0-9._-]+', x) for x in slaves):
        raise RuntimeError('unable to establish safe block device metadata')

    def block(path):
        data = run('exec-out', 'dd', f'if={path}', 'bs=4096', 'count=1', 'status=none')
        if len(data) != 4096:
            raise RuntimeError('block read did not return exactly 4096 bytes')
        return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'f2fs_superblock_magic_at_1024': int.from_bytes(data[1024:1028], 'little') == 0xf2f52010}

    # Neither block bytes nor any device-mapper table/key material are retained.
    mapped = block(data[0][0])
    raw = block('/dev/block/by-name/userdata')
    return {
        'schema': 1, 'collected_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'read-only first-block SHA and F2FS magic; no block contents or key material saved',
        'device': {'serial': serial, 'product': product, 'recovery': twrp, 'release_property': release},
        'data_mount': {'device': data[0][0], 'filesystem': data[0][2], 'options': data[0][3]},
        'metadata_mount': {'device': metadata[0][0], 'filesystem': metadata[0][2], 'options': metadata[0][3]},
        'mapping': {'dm_name': mapped_name, 'direct_slaves': slaves,
                    'userdata_resolved_path': raw_path,
                    'direct_userdata_backing_match': raw_match.group(1) in slaves,
                    'table_geometry_verified': False},
        'mapped_data_first_block': mapped, 'raw_userdata_first_block': raw,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', type=Path, required=True)
    parser.add_argument('--serial', default=SERIAL)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.serial != SERIAL or not args.adb.is_file():
        raise SystemExit('expected fcde91e and an existing adb executable')

    def run(*arguments):
        result = subprocess.run([str(args.adb), '-s', args.serial, *arguments],
                                capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(f'adb command failed: {arguments[0]} (exit {result.returncode})')
        return result.stdout

    report = collect(run)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
