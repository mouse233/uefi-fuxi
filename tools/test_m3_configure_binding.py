#!/usr/bin/env python3
"""Require exact A/B evidence and reject unsupported dates or modified proof."""
import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from m3_configure_binding import load_configure_evidence, PIN, PROFILES_PIN


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    old = root/'docs/evidence/fuxi-m3-configure-gate-20261030.json'
    proof = root/'docs/evidence/fuxi-m3-configure-profiles-20261030.json'
    context = root/'docs/evidence/fuxi-m3-twrp-keystore-context-20261030.json'
    digest = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
    cases = 0
    evidence = json.loads(proof.read_text())
    assert digest(old) == PIN and digest(proof) == PROFILES_PIN
    assert digest(context) == evidence['twrp_context_sha256']
    for name, value in evidence['sources'].items():
        assert digest(root/name) == value, name
    for patch, tail in ((20261005, '0135288d'), (20991231, '01404cff')):
        binding = load_configure_evidence(proof, patch)
        assert binding['os_patch'] == binding['vendor_patch'] == patch
        assert binding['configure_cbor_hex'] == 'a416031a300002c11a000298101a300002c21a'+tail+'1a300002ce1a'+tail
        assert binding['sha256'] == PROFILES_PIN
        cases += 1
    assert load_configure_evidence(old)['os_patch'] == 20261005
    cases += 1
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp)/'bad.json'
        raw = proof.read_bytes()
        for payload in (raw+b'\n', b'{}', raw.replace(b'20991231', b'20991230'), raw[:-1]):
            assert payload != raw
            bad.write_bytes(payload)
            try:
                load_configure_evidence(bad, 20991231)
            except ValueError:
                cases += 1
            else:
                raise AssertionError('modified configure evidence accepted')
    for path, patch in ((old, 20991231), (proof, 0), (proof, 20261006), (proof, 20991230)):
        try:
            load_configure_evidence(path, patch)
        except ValueError:
            cases += 1
        else:
            raise AssertionError('unbound configure profile accepted')
    files = [Path(__file__), root/'tools/m3_configure_binding.py', old, proof, context]
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(dict(result='passed', cases=cases,
        profiles=[20261005, 20991231], evidence_sha256=PROFILES_PIN,
        sources={str(f.relative_to(root)): digest(f) for f in files}), indent=2)+'\n')
    print('PASS', cases, 'configure profile pin/rejection cases')


if __name__ == '__main__':
    main()
