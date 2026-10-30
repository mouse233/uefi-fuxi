#!/usr/bin/env python3
"""Offline public configure A/B serializer/parser proof; no phone or real key."""
import argparse
import hashlib
import itertools
import json
import struct
from pathlib import Path
from audit_fuxi_m3_configure_gate import Codec, configure, encode, ta

OLD_PIN = '817bc13d0783d79380a054cfa0b6e5fa27d86a44b245a649016f1fbe1f6c2c32'
CONTEXT_PIN = 'e6d10b4457c6e2a681c363d2bf1e574c141381073156698ee9d812db6cf4a42a'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--partition', type=Path, required=True)
    p.add_argument('--libraries', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    old = root/'docs/evidence/fuxi-m3-configure-gate-20261030.json'
    context = root/'docs/evidence/fuxi-m3-twrp-keystore-context-20261030.json'
    digest = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
    assert digest(old) == OLD_PIN and digest(context) == CONTEXT_PIN
    live = json.loads(old.read_text())['live_gate_evidence']['recovery']
    assert live['status_signed'] == -64 and live['commands'] == 1 and live['retained']
    ctx = json.loads(context.read_text())['twrp_context']
    assert ctx['stable_snapshots'] == 2 and ctx['reference_hashes_match']
    assert ctx['props']['ro.build.version.release'] == '17'
    for key in ('ro.build.version.security_patch', 'ro.vendor.build.security_patch'):
        assert ctx['props'][key] == '2099-12-31'
    for name in ('libqtikeymint.so', 'libqcbor.so', 'libkeymasterdeviceutils.so'):
        assert digest(a.libraries/name) == ctx['library_sha256']['/vendor/lib64/'+name]
    raw = a.partition.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ta.TA_SHA
    codec = Codec(a.libraries)
    profiles = []
    for patch in (20261005, 20991231):
        params = [(0x300002c1, 170000), (0x300002c2, patch), (0x300002ce, patch)]
        vectors, cases = [], []
        for order in itertools.permutations(params):
            u = codec.u
            u.mem_write(codec.this, struct.pack('<Q', codec.qt+0x3e870))
            u.mem_write(codec.params+0x100, b''.join(struct.pack('<IIQQ', tag, 0, v, 0) for tag, v in order))
            u.mem_write(codec.params, struct.pack('<QQ', codec.params+0x100, 3))
            u.mem_write(codec.output, struct.pack('<QQ', codec.buffer, 0x8000))
            codec.call(0x35178, [codec.this, codec.params, codec.output])
            n = struct.unpack('<Q', u.mem_read(codec.output+8, 8))[0]
            assert n <= 64
            payload = bytes(u.mem_read(codec.buffer, n))
            assert payload == encode(order)
            vectors.append(payload.hex())
            _, result = configure(raw, payload)
            assert result['status'] == 0 and result['configured'] == 1
            assert result['values'] == [170000, 0, patch, patch]
            cases.append(result)
        invalid = [encode([v for i, v in enumerate(params) if i != index]) for index in range(3)]
        invalid += [encode(params+[(0x300002cf, 1)]), encode(params, count=4),
                    encode([params[0], params[0], params[1]]), encode(params)[:-1]]
        for payload in invalid:
            _, result = configure(raw, payload)
            assert result['status'] < 0 and not result['configured']
            cases.append(result)
        profiles.append(dict(os_version=170000, os_patch=patch, vendor_patch=patch,
                             configure_cbor_hex=encode(params).hex(),
                             vendor_request_matches=len(vectors), vendor_vectors=vectors,
                             cases=len(cases), tests=cases))
    files = [Path(__file__), root/'tools/audit_fuxi_m3_configure_gate.py',
             root/'tools/audit_fuxi_m3_recovery_wire.py', root/'tools/audit_fuxi_m3_metadata_read.py']
    report = dict(result='passed', command='0x2116', date_support=1,
                  original_gate_sha256=OLD_PIN, twrp_context_sha256=CONTEXT_PIN,
                  partition_sha256=ta.TA_SHA, profiles=profiles,
                  sources={str(f.relative_to(root)): digest(f) for f in files},
                  scope='Fixed vendor serializer and TA public parser in private emulator RAM. '
                        'No phone, real blob, secret, SMC, upgrade or persistent write. '
                        'Current TWRP properties do not prove constructor-sampled values or explain live -62.')
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS two profiles: 12 vendor serializer matches, 26 TA parser cases; no phone')


if __name__ == '__main__':
    main()
