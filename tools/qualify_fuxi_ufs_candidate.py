#!/usr/bin/env python3
"""Run M1 delivery qualification with the tracked TWRP branch fixtures."""
import argparse
import datetime
import hashlib
import json
import pathlib
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', type=pathlib.Path, required=True)
    parser.add_argument('--edk2', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--f2fs-tools', type=pathlib.Path, help='optional independent mkfs/sload validation; required for M2')
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    out, device, edk2 = args.output.resolve(), args.device.resolve(), args.edk2.resolve()
    logs = out / 'checks' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    logs.mkdir(parents=True)
    commands = []
    for name, script, report in [
        ('smmu', 'check-usb-smmu-audit.py', 'smmu-tests.json'),
        ('route', 'check-usb-smmu-route.py', 'route-tests.json'),
        ('receiver', 'check-usb-ram.py', 'host-tests.json'),
    ]:
        commands.append((name, ['python3', str(device / 'scripts' / script),
                                '--uefi', str(root), '--report', str(out / report)]))
    commands.append(('usb-state', ['python3', str(root / 'tools/test_fuxi_usb_state.py'),
                                  '--edk2', str(edk2), '--report-dir', str(out)]))
    for name, script, report in [
        ('m0', 'test_fuxi_data_port.py', 'data-port-tests.json'),
        ('m1-core', 'test_fuxi_ufs_port.py', 'ufs-core-tests.json'),
        ('report-cache', 'test_fuxi_ufs_report.py', 'report-cache-tests.json'),
        ('m2-draft', 'test_fuxi_f2fs.py', 'm2-draft-tests.json'),
        ('m2-files', 'test_fuxi_f2fs_files.py', 'm2-file-tests.json'),
    ]:
        commands.append((name, ['python3', str(root / 'tools' / script),
                                '--edk2', str(edk2), '--report', str(out / report)]))
    candidate=json.loads((out/'candidate.json').read_text())
    if candidate.get('m2_metadata_files') and not args.f2fs_tools:
        parser.error('M2 requires --f2fs-tools independent image validation')
    if args.f2fs_tools:
        commands.append(('m2-tools', ['python3', str(root/'tools/test_fuxi_f2fs_tools.py'),
            '--edk2',str(edk2),'--tools',str(args.f2fs_tools),'--report',str(out/'m2-tools-tests.json')]))
    if candidate.get('m3_bridge_call'):
        commands.append(('m3-transport', ['python3', str(root / 'tools/test_fuxi_m3_bridge_call.py'),
                                          '--edk2', str(edk2), '--report', str(out / 'm3-transport-tests.json')]))
        if not candidate.get('m3_smci_root'):
            commands.append(('m3-bridge-lifetime', ['python3',str(root/'tools/test_fuxi_m3_bridge_lifetime.py'),'--edk2',str(edk2),'--report',str(out/'m3-bridge-lifetime-tests.json')]))
            commands.append(('m3-bridge-abi', ['python3',str(root/'tools/audit_fuxi_m3_bridge_abi.py'),'--module',str(root/'out/twrp-a17-analysis/ramdisk/vendor/lib/modules/1.1/qcom-scm.ko'),'--output',str(out/'static-bridge-abi')]))
    elif candidate.get('m3_metadata_key'):
        commands.append(('m3-transport', ['python3', str(root / 'tools/test_fuxi_m3_key_paths.py'),
                                          '--edk2', str(edk2), '--report', str(out / 'm3-transport-tests.json')]))
    if candidate.get('m3_bridge_blob'):
        commands.append(('m3-blob', ['python3', str(root / 'tools/test_fuxi_m3_bridge_blob.py'),
                                   '--edk2', str(edk2), '--report', str(out / 'm3-blob-tests.json')]))
    if candidate.get('m3_smci_root'):
        commands.append(('m3-smci', ['python3', str(root / 'tools/test_fuxi_m3_smci_root.py'),
                                   '--edk2', str(edk2), '--report', str(out / 'm3-smci-tests.json')]))
    if candidate.get('m3_smc_context'):
        commands.append(('m3-context', ['python3', str(root / 'tools/test_fuxi_m3_smc_context.py'),
                                      '--edk2', str(edk2), '--report', str(out / 'm3-context-tests.json')]))
    commands += [
        ('image', ['python3', str(device / 'scripts/check-fuxi-usb-ram-image.py'),
                   '--uefi', str(root), '--output', str(out)]),
        ('ufs-delivery', ['python3', str(root / 'tools/check_fuxi_ufs_report_image.py'),
                          '--output', str(out)]),
    ]
    results = []
    for name, command in commands:
        path = logs / (name + '.log')
        with path.open('w') as stream:
            result = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT)
        results.append(dict(name=name, command=command, exit_code=result.returncode, log=str(path)))
        (out / 'check-exit-codes.json').write_text(json.dumps(results, indent=2) + '\n')
        print(name, result.returncode, flush=True)
        if result.returncode:
            print(path.read_text()[-6000:])
            raise SystemExit(result.returncode)
    binding = json.loads((out / 'build-inputs.json').read_text())
    if binding.get('config_ref'):
        board = out / 'config-input/board.toml'
        assert hashlib.sha256(board.read_bytes()).hexdigest() == binding['board_sha256']
    (out / 'qualification.json').write_text(json.dumps(dict(
        result='passed', checks=len(results), hardware_result='pending',
        m2_runtime_enabled=bool(candidate.get("m2_metadata_files")),
        diagnostic_park_before_usb=bool(candidate.get("diagnostic_park_before_usb")), inputs=binding,
        runner_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    ), indent=2) + '\n')


if __name__ == '__main__':
    main()
