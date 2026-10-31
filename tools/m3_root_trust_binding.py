"""Only the fixed offline ROT contract enables the observation candidate."""
import hashlib,json
from pathlib import Path
PIN='b225a546e7dfb434a62d75a8cdc5fe5e27e6c4bc653c69b72631a97b265f9610'
VECTORS_PIN='3b1ccaa2ab2a82dcca96d5ad962e3c2fd71978c6e2be14852b2e480c746fa660'
def load_binding(path):
 raw=Path(path).read_bytes()
 if hashlib.sha256(raw).hexdigest()!=PIN:raise ValueError('expected fixed ROT contract evidence')
 e=json.loads(raw)
 if e['result']!='passed' or len(e['codec_controls'])!=11 or len(e['failure_controls'])!=6 or len(e['capacity_controls'])!=5:raise ValueError('incomplete ROT contract')
 if e['service_imports']!={'0x5a048':'qsee_prng_getdata','0x5a0e8':'qsee_SW_Hmac'}:raise ValueError('ROT service contract changed')
 return dict(sha256=PIN,command='0x311f',challenge_bytes=16,boot_only=True,mac_verified=False,ta_private_mac_cache_may_initialize=True,vectors_sha256=VECTORS_PIN)
