"""Pin the matched deployment evidence used by the opt-in lookup candidate."""
import hashlib
import json
from pathlib import Path

EVIDENCE='docs/evidence/fuxi-m3-deployed-loader-20261030.json'
SHA='8c50771e55596540eeb60e3b1589656aa1a5af570f4bfbf7d55f49696e7a5018'


def load_binding(path=None):
    path=Path(path) if path else Path(__file__).resolve().parents[1]/EVIDENCE
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('deployed lookup evidence mismatch')
    evidence=json.loads(raw)
    if evidence['result']!='passed' or evidence['deployed_lookup']!=dict(op=2,counts='0x1011',arch_output_bytes=4):
        raise ValueError('unexpected deployed lookup contract')
    return dict(evidence_sha256=SHA,tz_sha256=evidence['tz_sha256'],identity_sha256=evidence['identity_sha256'],
                operation=2,counts='1011',payload_offset=40,arch_offset=56,arch_bytes=4,oo_offset=28,
                name='keymaster64',fallback=False,load=False,ta_command=False)
