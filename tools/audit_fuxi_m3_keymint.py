#!/usr/bin/env python3
"""Pin and inspect the local A17 KeyMint protocol; never execute vendor code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

EXPECTED = {
 'libqtikeymint.so':'657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb',
 'libkeymasterdeviceutils.so':'1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2',
}
RANGES = {
 'convert':('libqtikeymint.so',0x32540,0x326e0,
    [r'mov\s+w1, #0x311d\b',r'KeymasterUtils4init',r'serializeConvertStorageKey',r'KeymasterUtils7sendCmd',r'deserializeClientExpKey']),
 'serialize-convert':('libqtikeymint.so',0x39d44,0x39e3c,
    [r'QCBOREncode_OpenMap_3',r'mov\s+w2, #0x17\b',r'QCBOREncode_AddBytes_3',r'QCBOREncode_Finish']),
 'api-version':('libqtikeymint.so',0x2e26c,0x2e380,
    [r'mov\s+w1, #0x3121\b',r'mov\s+w1, #0xc8\b',r'serializeInteger',r'KeymasterUtils7sendCmd']),
 'configure':('libqtikeymint.so',0x2e3c0,0x2e588,
    [r'keymint_set_version',r'mov\s+w1, #0x2116\b',r'serializeClientParams']),
 'init':('libkeymasterdeviceutils.so',0x6760,0x67b8,
    [r'mov\s+w2, #0xa000\b',r'str\s+w20, \[x8\], #0x4',r'mov\s+w9, #0x9ffc\b']),
 'send':('libkeymasterdeviceutils.so',0x67b8,0x6860,
    [r'and\s+w8, w8, #0xfffffffc',r'QSEECom_send_cmd',r'ldr\s+w3, \[x20\]',r'ldr\s+w8, \[x20, #0x4\]',r'add\s+x9, x20, #0x8']),
 'load':('libkeymasterdeviceutils.so',0x62b0,0x6358,
    [r'add\s+x2, x2, #0xd95',r'add\s+x2, x2, #0xe8b',r'mov\s+w3, #0xa000',r'QSEECom_start_app',r'mov\s+w8, #0x200']),
}


def audit(ramdisk, output, objdump='llvm-objdump'):
    libs = ramdisk/'vendor/lib64'
    for name, expected in EXPECTED.items():
        if hashlib.sha256((libs/name).read_bytes()).hexdigest() != expected:
            raise ValueError('input SHA256 mismatch: '+name)
    raw = (libs/'libkeymasterdeviceutils.so').read_bytes()
    for offset, string in [(0x2a15,b'/vendor/firmware_mnt/image\0'),
                           (0x2d95,b'keymaster64\0'),(0x2e8b,b'keymaster\0')]:
        if raw[offset:offset+len(string)] != string:
            raise ValueError('TA name/path binding mismatch')
    output.mkdir(parents=True,exist_ok=True)
    evidence = {}
    for name,(library,start,end,patterns) in RANGES.items():
        text = subprocess.check_output([objdump,'-d','--start-address='+hex(start),
                 '--stop-address='+hex(end),str(libs/library)],text=True)
        normalized = re.sub(r'[\t ]+',' ',text)
        for pattern in patterns:
            if not re.search(pattern,normalized):
                raise ValueError('instruction binding mismatch: '+name+' '+pattern)
        path = output/(name+'.asm')
        path.write_text(text)
        evidence[name] = dict(library=library,start=hex(start),stop=hex(end),
            sha256=hashlib.sha256(text.encode()).hexdigest(),file=path.name)
    report = dict(result='passed',files_sha256=EXPECTED,evidence=evidence,
        ta_name='keymaster64',fallback_ta_name='keymaster',ta_directory='/vendor/firmware_mnt/image',
        userspace_shared_bytes=40960,convert_command=0x311d,convert_cbor_bytes_label=23,
        api_version_command=0x3121,api_version_value=200,configure_command=0x2116,
        scope='Fixed local binary instruction facts only; no TA execution, request equivalence, object lifetime, OS version configuration or decryption verified',
        limitations=['CBOR map {23: bstr} is inferred from calls, not byte-for-byte execution',
                     'set_version sends integer 200; it must not be treated as the Android release',
                     '8 KiB C1 registration is not the 40 KiB userspace QSEECom buffer',
                     'root register, callbacks, interrupted SMC, object release and loader remain hardware-unverified'])
    (output/'audit.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ramdisk',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(audit(a.ramdisk,a.output),indent=2))


if __name__=='__main__':
    main()
