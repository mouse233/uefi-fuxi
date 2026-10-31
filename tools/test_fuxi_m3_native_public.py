#!/usr/bin/env python3
"""Differential production C public-prefix parser, protected tail, synthetic only."""
import argparse
import hashlib
import json
import platform
import random
import shutil
import subprocess
import tempfile
from pathlib import Path
import collect_fuxi_m3_blob_public as reference
from test_fuxi_m3_blob_public import fixture, uint, bstr


def envelope(auth, version=0x400000005, opaque=0, shape=0x86):
    return bytes([shape])+uint(reference.MAGIC)+uint(version)+uint(opaque)+bstr(auth)


def corpus():
    prefix, _ = fixture()
    yield prefix, 208
    yield prefix, len(prefix)
    for version in (0, 0x400000004, 0x400000005, 0xffffffffffffffff):
        for opaque in (0, 24, 1 << 32, 0xffffffffffffffff):
            yield envelope(b'\xa2\x00\xa0\x01\xa0', version, opaque), 208
    for shape in (0x83, 0x84, 0x90, 0x91, 0x9f, 0xa4):
        yield envelope(b'\xa2\x00\xa0\x01\xa0', shape=shape), 208
    tags = [0x300002c1, 0x300002c2, 0x300002cf, 0x300002ce, 0x10000002]
    for tag in tags:
        for value in (0, 170000, 202610, 20260801, 0xffffffff, 1 << 32):
            yield envelope(b'\xa2\x00\xa0\x01\xa1'+uint(tag)+uint(value)), 208
    for auth in (b'\xa1\x00\xa0', b'\xa2\x00\xa0\x00\xa0',
                 b'\xa2\x00\xa0\x02\xa0', b'\xa2\x00\xa0\x01\xa0\x00',
                 b'\xa2\x00\xa2'+uint(tags[0])+b'\x01'+uint(tags[0])+b'\x02\x01\xa0',
                 b'\xa2\x00\xb8\x81', b'\xa2\x00\xa1'+uint(1 << 32)+b'\x00\x01\xa0'):
        yield envelope(auth), 208
    for value in (b'\xf5', b'\xf4', b'\x01', b'\xf8\x15'):
        yield envelope(b'\xa2\x00\xa0\x01\xa1'+uint(0x700002d2)+value), 208
    for value in (b'\xf6', b'\x21', bstr(b'public skip'), b'\x18\x00', b'\x1f', b'\xc0\x00',
                  b'\x81'*9+b'\x00', b'\x81'*8+b'\x00', b'\x98\x81', b'\x59\xff\xff'):
        yield envelope(b'\xa2\x00\xa1\x01'+value+b'\x01\xa0'), 208
    for n in range(1, len(prefix)):
        yield prefix[:n], n
    # Boundaries, empty/oversized authorization, canonical length checks.
    for n in (0, 2048, 2049):
        p = envelope(b'\x00'*n)
        yield p, len(p)
    yield prefix, 4097
    # Deterministic mutations; Bytes equals mapped size for malformed prefixes.
    rng = random.Random(62)
    for _ in range(800):
        p = bytearray(prefix)
        for _ in range(rng.randint(1, 4)):
            p[rng.randrange(len(p))] = rng.randrange(256)
        yield bytes(p), len(p)


def expected(prefix, total):
    def read(at, n):
        # Accepted cases may advertise an unread tail behind a guard page.
        return prefix[at:at+n]
    try:
        p = reference.inspect_public(read, total)
    except ValueError:
        return 'rejected'
    row = [int(p['format_version'], 16), p['public_prefix_bytes']]
    names = ['os_version', 'os_patch', 'boot_patch', 'vendor_patch', 'algorithm']
    for domain in ('software', 'hardware'):
        fields = p[domain]
        row += [sum(1 << i for i, name in enumerate(names) if name in fields)]
        row += [fields.get(name, 0) for name in names]+[int(fields.get('fbe_tag_present', False))]
    return ' '.join(map(str, row))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--edk2', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    if platform.system() != 'Linux':
        p.error('run in unixnu-fuxi-build-arm64')
    root = Path(__file__).resolve().parents[1]
    native = root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe'
    test = root/'tools/tests/m3_blob_public_host.c'
    cases = list(corpus())
    want = [expected(*case) for case in cases]
    with tempfile.TemporaryDirectory(prefix='native-public-') as tmp:
        exe = str(Path(tmp)/'test')
        subprocess.run([shutil.which('clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-macro-redefined', '-fshort-wchar', '-g', '-O1', '-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer', '-I'+str(a.edk2/'MdePkg/Include'),
                        '-I'+str(a.edk2/'MdePkg/Include/AArch64'), '-I'+str(native),
                        str(test), '-o', exe], check=True)
        wire = b''.join(f'{len(data)} {total}\n'.encode()+data for data, total in cases)
        got = subprocess.check_output([exe], input=wire).decode().splitlines()
    assert len(got) == len(want)
    for i, (actual, predicted) in enumerate(zip(got, want)):
        assert actual == predicted, f'case {i}: public field/parser disagreement'
    files = [Path(__file__), test, native/'M3BlobPublic.h',
             root/'tools/collect_fuxi_m3_blob_public.py', root/'tools/test_fuxi_m3_blob_public.py']
    report = dict(result='passed', cases=len(cases), accepted=sum(x != 'rejected' for x in want),
                  sanitizers=['address', 'undefined'], tail_guard='PROT_NONE immediately after supplied prefix',
                  scope='Synthetic parser/allowlist equivalence only; not TA authentication or live branch evidence.',
                  sources={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2)+'\n')
    print(f'PASS {len(cases)} native public-prefix cases; protected unread tail')


if __name__ == '__main__':
    main()
