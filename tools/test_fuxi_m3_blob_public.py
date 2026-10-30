#!/usr/bin/env python3
"""Public-prefix streaming/identity/race/output controls; synthetic data only."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import collect_fuxi_m3_blob_public as collect


def uint(n):
    for limit, ai, width in ((24, 0, 0), (256, 24, 1), (65536, 25, 2), (1 << 32, 26, 4), (1 << 64, 27, 8)):
        if n < limit:
            return bytes([n if not width else ai])+(n.to_bytes(width, 'big') if width else b'')
    raise ValueError('test integer bound')


def bstr(data):
    head = bytearray(uint(len(data))); head[0] |= 0x40
    return bytes(head)+data


def fixture(extra=b'', *, magic=collect.MAGIC, version=collect.REQUIRED_VERSION):
    hw = [(0x10000002, 32), (0x300002c1, 170000), (0x300002c2, 202610),
          (0x300002cf, 0), (0x300002ce, 20261005)]
    auth = b'\xa2\x01'+bytes([0xa0+len(hw)+bool(extra)])+b''.join(uint(k)+uint(v) for k, v in hw)
    if extra:
        auth += uint(0x900003e9)+bstr(extra)
    auth += b'\x00\xa0'
    prefix = b'\x86'+uint(magic)+uint(version)+b'\x00'+bstr(auth)
    return prefix, prefix+b'OPAQUE_TAIL_MUST_NOT_BE_READ'.ljust(208-len(prefix), b'X')


class Mock:
    def __init__(self, mode='ok'):
        self.mode = mode
        self.prefix, self.data = fixture(b'PUBLIC_OPAQUE_DO_NOT_SAVE')
        self.snapshot = 0
        self.library_queries = 0
        self.identity_queries = 0
        self.reads = []

    def __call__(self, *args):
        if args == ('get-state',):
            self.identity_queries += 1
            return b'fastboot' if self.mode == 'state' else b'recovery'
        if args[:2] == ('shell', 'getprop'):
            props = {'ro.product.device': 'fuxi', 'ro.boot.serialno': 'fcde91e',
                     'ro.boot.slot_suffix': '_a', 'ro.twrp.version': '3.7.1_12-Xiaomi13_v9.0_A15',
                     'ro.build.version.release': '17'}
            if self.mode in ('serial', 'product', 'slot', 'twrp', 'release'):
                key, val = {'serial': ('ro.boot.serialno', 'wrong'), 'product': ('ro.product.device', 'other'),
                            'slot': ('ro.boot.slot_suffix', '_b'), 'twrp': ('ro.twrp.version', ''),
                            'release': ('ro.build.version.release', '16')}[self.mode]
                props[key] = val
            if self.mode == 'property-race' and self.identity_queries > 1:
                props['ro.boot.slot_suffix'] = '_b'
            return props[args[2]].encode()
        if args == ('shell', 'id', '-u'):
            return b'2000' if self.mode == 'root' else b'0'
        if args == ('shell', 'sha256sum', collect.LIB):
            self.library_queries += 1
            sha = '0'*64 if self.mode == 'library' or self.mode == 'library-race' and self.library_queries > 1 else collect.LIB_SHA
            return (sha+'  '+collect.LIB).encode()
        if args[0] == 'shell' and len(args) == 2 and args[1].startswith('test -f '):
            assert args[1] == 'test -f '+collect.BLOB+' && test ! -L '+collect.BLOB+' && echo regular'
            return b'' if self.mode == 'symlink' else b'regular'
        if args == ('shell', 'stat', '-c', '%s:%i:%Y', collect.BLOB):
            if self.mode == 'size':
                return b'209:71:1'
            return b'208:71:2' if self.mode == 'stat-race' and self.snapshot > 1 else b'208:71:1'
        if args[0] == 'exec-out':
            m = re.fullmatch(r'dd if='+re.escape(collect.BLOB)+r' bs=1 skip=([0-9]+) count=([0-9]+) 2>/dev/null', args[1])
            assert m, 'non-allowlisted command'
            offset, count = map(int, m.groups())
            assert offset+count <= len(self.prefix), 'opaque tail was requested'
            if offset == 0:
                self.snapshot += 1
            self.reads.append((offset, count))
            data = self.data
            if self.mode == 'prefix-race' and self.snapshot > 1:
                changed = bytearray(data)
                changed[len(self.prefix)-4] ^= 1  # skipped opaque public attribute
                data = bytes(changed)
            return data[offset:offset+count-(self.mode == 'short')]
        raise AssertionError('unexpected command')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path, required=True)
    args = p.parse_args()
    cases = []
    mock = Mock()
    report = collect.collect(mock)
    assert report['stable_snapshots'] == 2 and report['public']['unread_tail_bytes'] > 0
    assert report['public']['hardware']['os_patch'] == 202610
    assert report['total_bytes_read'] == 2*len(mock.prefix)
    assert set(report['public']) == {'authenticated','format_version','required_format_version','format_below_required','public_prefix_bytes','unread_tail_bytes','hardware','software','scope'}
    text = json.dumps(report)
    assert 'PUBLIC_OPAQUE_DO_NOT_SAVE' not in text and 'OPAQUE_TAIL' not in text
    assert mock.library_queries == 2
    cases.append('two-stable-snapshots-exact-public-prefix-no-tail-or-material-output')
    for mode in ('state', 'serial', 'product', 'slot', 'twrp', 'release', 'root', 'library',
                 'symlink', 'size', 'short', 'property-race', 'stat-race', 'prefix-race', 'library-race'):
        mock = Mock(mode)
        try:
            collect.collect(mock)
        except ValueError:
            cases.append(mode+'-rejected')
        else:
            raise AssertionError('unsafe capture accepted: '+mode)
    good, _ = fixture()
    malformed = [('bad-magic', fixture(magic=0)[0]), ('truncation', good[:-1]),
                 ('indefinite', b'\x9f'+good[1:]), ('wrong-root', b'\xa6'+good[1:]),
                 ('noncanonical', good[:15]+b'\x18\x00'+good[16:])]
    for name, payload in malformed:
        try:
            collect.inspect_public(lambda offset, count: payload[offset:offset+count], len(payload))
        except ValueError:
            cases.append(name+'-rejected')
        else:
            raise AssertionError('malformed public envelope accepted: '+name)
    duplicate = b'\xa2\x01\xa2'+uint(0x300002c1)+uint(1)+uint(0x300002c1)+uint(2)+b'\x00\xa0'
    try:
        collect.authorization(duplicate)
    except ValueError:
        cases.append('duplicate-tag-rejected')
    else:
        raise AssertionError('ambiguous authorization accepted')
    for n in (0, 4097):
        try:
            collect.Reader(lambda *_: b'', n)
        except ValueError:
            cases.append('input-bound-'+str(n))
        else:
            raise AssertionError('input bound accepted')
    root = Path(__file__).resolve().parents[1]
    sources = [Path(__file__), Path(collect.__file__)]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(dict(result='passed', cases=len(cases), tests=cases,
        scope='Synthetic read-only command mocks/public CBOR only; no phone, actual blob, authentication or decryption.',
        sources={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in sources}), indent=2)+'\n')
    print('PASS', len(cases), 'public-prefix streaming, identity, races, malformed input and output controls; no device')


if __name__ == '__main__':
    main()
