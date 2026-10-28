#!/usr/bin/env python3
"""Test the fixed-binary audit and reject a modified vendor input."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
from audit_fuxi_m3_keymint import EXPECTED, audit


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ramdisk',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    report=audit(a.ramdisk,a.output)
    rejected=[]
    with tempfile.TemporaryDirectory(prefix='fuxi-keymint-audit-') as temp:
        root=Path(temp); libs=root/'vendor/lib64';libs.mkdir(parents=True)
        for name in EXPECTED:
            shutil.copyfile(a.ramdisk/'vendor/lib64'/name,libs/name)
        for name in EXPECTED:
            path=libs/name;raw=path.read_bytes();changed=bytearray(raw);changed[-1]^=1;path.write_bytes(changed)
            try:
                audit(root,root/'output')
            except ValueError as e:
                assert 'SHA256 mismatch' in str(e); rejected.append(name)
            else:
                raise RuntimeError('modified input accepted')
            path.write_bytes(raw)
    report={'result':'passed','audit_result':report['result'],'modified_inputs_rejected':rejected}
    (a.output/'tests.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()
