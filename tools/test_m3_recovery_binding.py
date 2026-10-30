#!/usr/bin/env python3
"""Reject mutated or synthetic evidence before enabling real key recovery."""
import argparse, hashlib, json, tempfile
from pathlib import Path
from m3_recovery_binding import load_binding, PIN

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    root=Path(__file__).resolve().parents[1];evidence=root/'docs/evidence/fuxi-m3-android-binding-20261030.json'
    assert load_binding(evidence)['seed_bytes']==0
    raw=evidence.read_bytes()
    with tempfile.TemporaryDirectory() as tmp:
        bad=Path(tmp)/'binding.json'
        for data in (raw+b'\n',b'{}',raw.replace(b'"state": 2',b'"state": 1'),raw[:-1]):
            assert data!=raw
            bad.write_bytes(data)
            try:load_binding(bad)
            except ValueError:pass
            else:raise AssertionError('untrusted binding accepted')
    files=[Path(__file__),root/'tools/m3_recovery_binding.py',evidence]
    a.report.parent.mkdir(parents=True,exist_ok=True)
    a.report.write_text(json.dumps(dict(result='passed',cases=5,evidence_sha256=PIN,sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}),indent=2)+'\n')
    print('PASS 5 real binding pin/rejection cases')
if __name__=='__main__':main()
