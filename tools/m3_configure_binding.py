"""Only the fixed live -64 plus TA/QTI public-input proof enables configure."""
import hashlib,json
from pathlib import Path
PIN='817bc13d0783d79380a054cfa0b6e5fa27d86a44b245a649016f1fbe1f6c2c32'

PROFILES_PIN='3cc89865a2f0de0298ef9fa5c2c593be7f8770594afb2f990cf0e1bff53f1320'

def load_configure_evidence(path, patch=20261005):
    raw=Path(path).read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    if digest==PROFILES_PIN:
        e=json.loads(raw)
        if e['result']!='passed' or e['command']!='0x2116' or e['date_support']!=1 or e['original_gate_sha256']!=PIN:
            raise ValueError('incomplete A/B configure proof')
        if patch not in (20261005,20991231):raise ValueError('unsupported configure profile')
        profile=next(x for x in e['profiles'] if x['os_patch']==patch)
        if profile['cases']!=13 or profile['vendor_request_matches']!=6 or profile['os_version']!=170000 or profile['vendor_patch']!=patch:
            raise ValueError('profile proof mismatch')
        return dict(sha256=digest,tag='0x'+digest[:8],os_version=170000,os_patch=patch,vendor_patch=patch,
                    command='0x2116',date_support=1,configure_cbor_hex=profile['configure_cbor_hex'])
    if patch!=20261005:raise ValueError('alternate profile requires pinned A/B evidence')
    if digest!=PIN:raise ValueError('expected pinned real -64 / fixed TA configure evidence')
    e=json.loads(raw)
    if e['result']!='passed' or e['cases']!=13 or e['vendor_request_matches']!=6:raise ValueError('incomplete configure proof')
    if e['constructor_date_support']!=1 or e['public_parameter_values']!=[[0x300002c1,170000],[0x300002c2,20261005],[0x300002ce,20261005]]:raise ValueError('public parameter binding changed')
    live=e['live_gate_evidence']
    if live['recovery']['status_signed']!=-64 or live['recovery']['commands']!=1 or not live['recovery']['retained']:raise ValueError('live prerequisite not established')
    return dict(sha256=PIN,tag='0x'+PIN[:8],os_version=170000,os_patch=20261005,vendor_patch=20261005,command='0x2116',date_support=1,configure_cbor_hex=e['configure_cbor_hex'])
