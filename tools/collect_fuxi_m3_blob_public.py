#!/usr/bin/env python3
"""Read only the public CBOR envelope prefix from fixed fuxi TWRP metadata.

Reads end at the fourth outer-array item (authorization bytes). The encrypted
key/nonce/MAC tail is never requested. Only allowlisted integers/presence flags
are saved, never raw bytes or any input-material prefix/digest. These fields
are UNAUTHENTICATED and cannot alone prove the live TA's execution branch.
"""
import argparse
import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path

BLOB = '/metadata/vold/metadata_encryption/key/keymaster_key_blob'
LIB = '/vendor/lib64/libqtikeymint.so'
LIB_SHA = '657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb'
MAGIC = 0x4b4d4b44
REQUIRED_VERSION = 0x400000005
VERSION_TAGS = {0x300002c1: 'os_version', 0x300002c2: 'os_patch',
                0x300002cf: 'boot_patch', 0x300002ce: 'vendor_patch'}


class Reader:
    def __init__(self, read_at, limit):
        if not 1 <= limit <= 4096:
            raise ValueError('public input length bound')
        self.read_at, self.limit = read_at, limit
        self.buffer = bytearray()
        self.at = 0

    def take(self, n):
        end = self.at+n
        if n < 0 or end > self.limit:
            raise ValueError('truncated or oversized public structure')
        if end > len(self.buffer):
            chunk = self.read_at(len(self.buffer), end-len(self.buffer))
            if len(chunk) != end-len(self.buffer):
                raise ValueError('short public-prefix read')
            self.buffer.extend(chunk)
        start = self.at
        self.at = end
        return memoryview(self.buffer)[start:end]

    def head(self):
        first = self.take(1)[0]
        major, ai = first >> 5, first & 31
        if ai < 24:
            return major, ai
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        if ai not in widths:
            raise ValueError('indefinite/reserved CBOR not supported')
        n = int.from_bytes(self.take(widths[ai]), 'big')
        if n < {24: 24, 25: 256, 26: 65536, 27: 1 << 32}[ai]:
            raise ValueError('noncanonical public integer/length')
        return major, n

    def uint(self):
        major, n = self.head()
        if major != 0:
            raise ValueError('expected public unsigned integer')
        return n

    def skip(self, depth=0):
        if depth > 8:
            raise ValueError('public nesting bound')
        major, n = self.head()
        if major in (0, 1) or major == 7 and n in (20, 21, 22):
            return
        if major in (2, 3):
            self.take(n)
            return
        if major in (4, 5) and n <= 128:
            for _ in range(n*(2 if major == 5 else 1)):
                self.skip(depth+1)
            return
        raise ValueError('unsupported public CBOR item')


def authorization(raw):
    # This byte array is only the public authorization item, never the opaque
    # encrypted tail. Drop it after parsing; no byte dumps/hashes in errors.
    r = Reader(lambda offset, count: raw[offset:offset+count], len(raw))
    major, count = r.head()
    if major != 5 or count != 2:
        raise ValueError('expected two authorization domains')
    domains = {}
    for _ in range(count):
        domain = r.uint()
        if domain not in (0, 1) or domain in domains:
            raise ValueError('duplicate/unknown authorization domain')
        major, n = r.head()
        if major != 5 or n > 128:
            raise ValueError('authorization map bound')
        row, seen = {}, set()
        for _ in range(n):
            tag = r.uint()
            if tag > 0xffffffff or tag in seen:
                raise ValueError('duplicate/oversized authorization tag')
            seen.add(tag)
            if tag in VERSION_TAGS or tag == 0x10000002:
                value = r.uint()
                if value > 0xffffffff:
                    raise ValueError('public version/algorithm width')
                row[VERSION_TAGS.get(tag, 'algorithm')] = value
            elif tag == 0x700002d2:
                if r.head() != (7, 21):
                    raise ValueError('unexpected FBE boolean encoding')
                row['fbe_tag_present'] = True
            else:
                r.skip()
        domains[domain] = row
    if r.at != len(raw):
        raise ValueError('trailing authorization bytes')
    return domains


def inspect_public(read_at, blob_bytes):
    r = Reader(read_at, blob_bytes)
    try:
        major, count = r.head()
        if major != 4 or not 4 <= count <= 16:
            raise ValueError('public envelope array shape')
        magic, version = r.uint(), r.uint()
        r.uint()  # Opaque outer identifier: consume, never retain or report.
        if magic != MAGIC:
            raise ValueError('public envelope magic mismatch')
        major, n = r.head()
        if major != 2 or not 1 <= n <= 2048:
            raise ValueError('public authorization byte-string bound')
        # Stop exactly here: later encrypted items are not read or decoded.
        auth = bytes(r.take(n))
        domains = authorization(auth)
        return dict(authenticated=False, format_version=hex(version),
                    required_format_version=hex(REQUIRED_VERSION),
                    format_below_required=version < REQUIRED_VERSION,
                    public_prefix_bytes=r.at, unread_tail_bytes=blob_bytes-r.at,
                    hardware=domains[1], software=domains[0],
                    scope='Unauthenticated public outer fields only; not a live version-gate trace.')
    finally:
        # Do not retain the raw prefix in the collector/report or exception.
        r.buffer[:] = bytes(len(r.buffer))


def collect(run):
    def text(*args):
        return run(*args).decode('utf-8', errors='strict').strip()
    def identity():
        state = text('get-state')
        props = {key: text('shell', 'getprop', key) for key in
                 ('ro.product.device', 'ro.boot.serialno', 'ro.boot.slot_suffix',
                  'ro.twrp.version', 'ro.build.version.release')}
        if state != 'recovery' or props['ro.product.device'] != 'fuxi' or props['ro.boot.serialno'] != 'fcde91e':
            raise ValueError('expected fixed fuxi recovery identity')
        if props['ro.boot.slot_suffix'] != '_a' or not props['ro.twrp.version'] or props['ro.build.version.release'] != '17':
            raise ValueError('unexpected TWRP/slot/release')
        if text('shell', 'id', '-u') != '0':
            raise ValueError('TWRP root required')
        return props
    before = identity()
    library = text('shell', 'sha256sum', LIB).split()
    if len(library) != 2 or library[0] != LIB_SHA or library[1] != LIB:
        raise ValueError('fixed reference KeyMint library mismatch')
    # Reject symlinks. Existing recovery mounts are used; never mount/remount.
    if text('shell', 'test -f '+BLOB+' && test ! -L '+BLOB+' && echo regular') != 'regular':
        raise ValueError('expected regular metadata blob file')
    stat_before = text('shell', 'stat', '-c', '%s:%i:%Y', BLOB)
    if not re.fullmatch(r'208:[0-9]+:[0-9]+', stat_before):
        raise ValueError('expected pinned 208-byte metadata blob shape')
    ranges, snapshots = [], [bytearray(), bytearray()]
    snapshot_index = 0
    def read_at(offset, count):
        if offset < 0 or count < 1 or offset+count > 208:
            raise ValueError('fixed public read bound')
        data = run('exec-out', 'dd if='+BLOB+' bs=1 skip='+str(offset)+' count='+str(count)+' 2>/dev/null')
        if len(data) != count:
            raise ValueError('short metadata prefix read')
        ranges.append((offset, count))
        snapshots[snapshot_index].extend(data)
        return data
    try:
        first = inspect_public(read_at, 208)
        snapshot_index = 1
        second = inspect_public(read_at, 208)
        if first != second or snapshots[0] != snapshots[1] or stat_before != text('shell', 'stat', '-c', '%s:%i:%Y', BLOB) or before != identity():
            raise ValueError('metadata or recovery context changed during capture')
        if text('shell', 'sha256sum', LIB).split() != library:
            raise ValueError('reference library changed during capture')
    finally:
        for data in snapshots:
            data[:] = bytes(len(data))
    if first['unread_tail_bytes'] < 1:
        raise ValueError('no opaque tail remains; unexpected blob layout')
    return dict(result='captured', serial='fcde91e', properties=before,
                reference_library_sha256=LIB_SHA, stable_snapshots=2,
                blob_bytes=208, public=first, total_bytes_read=sum(n for _, n in ranges),
                commands='Fixed identity/stat/library hash and exact public-prefix dd reads only.',
                limits=['No encrypted tail requested, raw prefix/digest saved, KeyMint API, process-memory read or device write.',
                        'Public fields are unauthenticated and do not prove the live TA returned from a particular PC.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', default='/opt/homebrew/bin/adb')
    p.add_argument('--serial', choices=['fcde91e'], required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise SystemExit('refusing to replace a previous capture')
    processes = subprocess.check_output(['ps', '-eo', 'pid=,args='], text=True)
    if re.search(r'test-usb-ram-full|usb-ram-send|boot-ram-window', processes):
        raise SystemExit('another device task is active')
    def run(*args):
        result = subprocess.run([a.adb, '-s', a.serial, *args], capture_output=True, timeout=15)
        if result.returncode:
            raise ValueError('fixed read-only ADB command failed; payload suppressed')
        return result.stdout
    report = collect(run)
    report['collected_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['collector_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS stable public envelope fields captured; no raw prefix, input digest or encrypted tail saved')


if __name__ == '__main__':
    main()
