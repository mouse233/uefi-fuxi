#!/usr/bin/env python3
"""Verify the delivered M3 DXE discovery markers and protocol GUIDs."""
import argparse
import hashlib
import json
from pathlib import Path
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    out = parser.parse_args().output.resolve()
    candidate = json.loads((out / 'candidate.json').read_text())
    prior = json.loads((out / 'report-image-tests.json').read_text())
    image = out / 'Mu-fuxi-ufs-m1.img'
    module = (out / 'FuxiNativeUfsDxe.efi').read_bytes()
    digest = lambda value: hashlib.sha256(value).hexdigest()
    assert prior['result'] == 'passed' and prior['ufs_efi_in_delivered_fd']
    assert digest(image.read_bytes()) == candidate['sha256'] == prior['boot_sha256']
    assert digest(module) == prior['ufs_efi_sha256']
    assert all(value == 0 for value in prior['smc_instructions'].values())
    for marker in ('FUXIM3 DXE protocols SCM=%r nonnull=%u QSEE=%r nonnull=%u',
                   'FUXIM3 discovery only: no protocol methods or SMC; no decrypt'):
        assert marker.encode('utf-16-le') in module, marker
    for guid in ('77ed108d-8524-4b8b-9d2e-34987aecb9c1',
                 'a74862ce-680f-4fe1-a311-df41f4030391'):
        assert uuid.UUID(guid).bytes_le in module, guid
    result = {'result': 'passed', 'boot_sha256': candidate['sha256'],
              'ufs_efi_sha256': digest(module), 'protocol_guids': 2,
              'discovery_markers': 2, 'direct_smc_instructions': 0,
              'hardware_result': 'pending',
              'scope': 'delivery binding only; no protocol provider or decryption proved'}
    (out / 'm3-discovery-image-tests.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
