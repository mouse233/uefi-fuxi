#!/usr/bin/env python3
"""Bind an independently qualified pair whose only board change is patch date."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--a', type=Path, required=True)
    p.add_argument('--b', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    read = lambda path: json.loads(path.read_text())
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    sources = [read(out/'sources.json') for out in (args.a, args.b)]
    assert sources[0] == sources[1]
    for name, value in sources[0].items():
        assert digest(root/name) == value, name
    boards, candidates, inputs, rows = [], [], [], []
    packets = [bytes.fromhex('16210000a416031a300002c11a000298101a300002c21a'+v+'1a300002ce1a'+v)
               for v in ('0135288d', '01404cff')]
    for index, (out, patch) in enumerate(((args.a, 20261005), (args.b, 20991231))):
        q = read(out/'qualification.json')
        codes = read(out/'check-exit-codes.json')
        assert q['result'] == 'passed' and q['hardware_result'] == 'pending'
        assert q['checks'] == len(codes) == 29 and all(x['exit_code'] == 0 for x in codes)
        build = read(out/'build-check-exit-codes.json')
        assert len(build) == 4 and all(x['exit_code'] == 0 for x in build)
        c = read(out/'candidate.json')
        image = out/'Mu-fuxi-ufs-m1.img'
        assert digest(image) == c['sha256'] == read(out/'verification.json')['boot_sha256']
        assert c['m3_configure_recovery'] and c['m3_recover_key']
        assert not c['m3_characteristics_probe'] and not c['m3_smci_date'] and not c['m3_smci_setver']
        assert not c['kernel_handoff'] and not c['receiver_runtime_enabled']
        binding = c['m3_configure_binding']
        assert binding['os_version'] == 170000 and binding['os_patch'] == binding['vendor_patch'] == patch
        entry = read(out/'configured-recovery-tests.json')
        assert entry['cases'] == 27 and entry['configured'] and entry['configure_patch'] == patch
        efi = (out/'FuxiNativeUfsDxe.efi').read_bytes()
        assert packets[index] in efi and packets[1-index] not in efi
        assert read(out/'live-object-checks.json')['configure_binding'] == binding
        assert read(out/'report-image-tests.json')['result'] == 'passed'
        board = read(out/'board-effective.json')
        assert board['firmware']['defines'].pop('FUXI_M3_CONFIGURE_PATCH') == str(patch)
        boards.append(board)
        rows.append(dict(profile='AB'[index], patch=patch, image_sha256=c['sha256'],
                         bytes=image.stat().st_size, checks=len(codes), efi_sha256=digest(out/'FuxiNativeUfsDxe.efi')))
        for key in ('image', 'sha256', 'bytes'):
            c.pop(key)
        for key in ('os_patch', 'vendor_patch', 'configure_cbor_hex'):
            binding.pop(key)
        candidates.append(c)
        inputs.append(read(out/'build-inputs.json'))
    assert boards[0] == boards[1] and candidates[0] == candidates[1] and inputs[0] == inputs[1]
    # All copied framework scripts must be the same bytes for both builds,
    # including any pre-existing dirty files in the framework checkout.
    scripts = []
    for out in (args.a, args.b):
        tree = out/'work/tree/scripts'
        scripts.append({str(f.relative_to(tree)): digest(f) for f in tree.rglob('*')
                        if f.is_file() and '__pycache__' not in f.parts and f.suffix != '.pyc'})
    assert scripts[0] == scripts[1] and scripts[0]
    report = dict(result='passed', profiles=rows, source_files=len(sources[0]),
                  same_sources=True, same_framework_scripts=True, same_build_inputs=True,
                  board_difference=['FUXI_M3_CONFIGURE_PATCH'], inputs=inputs[0],
                  sources={str(Path(__file__).relative_to(root)): digest(Path(__file__))},
                  scope='Host qualification only. No device boot or M3/M4/M5 result.')
    args.report.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS A/B: identical sources/inputs, only public patch define changes; 29 checks each')


if __name__ == '__main__':
    main()
