"""Only the fixed live -64 plus TA/QTI public-input proof enables configure."""
import hashlib,json
from pathlib import Path
PIN='817bc13d0783d79380a054cfa0b6e5fa27d86a44b245a649016f1fbe1f6c2c32'

def load_configure_evidence(path):
    raw=Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:raise ValueError('expected pinned real -64 / fixed TA configure evidence')
    e=json.loads(raw)
    if e['result']!='passed' or e['cases']!=13 or e['vendor_request_matches']!=6:raise ValueError('incomplete configure proof')
    if e['constructor_date_support']!=1 or e['public_parameter_values']!=[[0x300002c1,170000],[0x300002c2,20261005],[0x300002ce,20261005]]:raise ValueError('public parameter binding changed')
    live=e['live_gate_evidence']
    if live['recovery']['status_signed']!=-64 or live['recovery']['commands']!=1 or not live['recovery']['retained']:raise ValueError('live prerequisite not established')
    return dict(sha256=PIN,tag='0x'+PIN[:8],os_version=170000,os_patch=20261005,vendor_patch=20261005,command='0x2116',date_support=1,configure_cbor_hex=e['configure_cbor_hex'])
