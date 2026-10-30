"""Only the already captured real fuxi state2 evidence may enable this candidate."""
import hashlib
import json
from pathlib import Path

PIN='f2e5a8b406a8040e6834afcec72c31613adf1a840eec759ad7b10bacf74dedfc'


def load_binding(path):
    raw=Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:raise ValueError('expected pinned real Android binding evidence')
    evidence=json.loads(raw);runtime=evidence['runtime_binding'];binding=runtime['binding']
    if runtime['serial']!='fcde91e' or runtime['process']!='vold' or runtime['executable_sha256']!='9c20de9cb015e066474ad9cc23e1364d5ddf4fa55fca5f2c9a57e3ad0caed418':
        raise ValueError('unexpected runtime binding identity')
    if binding!=dict(state=2,meaning='used without seed',vector_empty=True,stable_snapshots=2):raise ValueError('unbound context required')
    if evidence['metadata_file_sizes']!=dict(version=1,secdiscardable=16384,keymaster_key_blob=208,encrypted_key=276):raise ValueError('fixed metadata subset changed')
    return dict(sha256=PIN,tag='0x'+PIN[:8],serial='fcde91e',seed_bytes=0,mode='pinned Android state2, empty vector',captured_utc=runtime['collected_utc'])
