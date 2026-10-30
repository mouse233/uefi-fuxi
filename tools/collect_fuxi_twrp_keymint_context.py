#!/usr/bin/env python3
"""Read only TWRP properties, process identity and library hashes; no key APIs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

from collect_fuxi_recovery_binding import parse_maps

SERIAL = 'fcde91e'
PROPS = ('ro.product.device', 'ro.boot.serialno', 'ro.twrp.version',
         'ro.build.version.release', 'ro.system.build.version.release',
         'ro.build.version.security_patch', 'ro.vendor.build.security_patch',
         'ro.bootimage.build.version.security_patch', 'ro.boot.slot_suffix',
         'init.svc.vendor.keymint-qti', 'init.svc.keystore2',
         'init.svc.vendor.qseecomd', 'vendor.sys.listeners.registered')
PROCESSES = ('recovery', 'keystore2', 'android.hardware.security.keymint-service-qti')
PINS = {
    'recovery': '9aa603b1b2851df9c773c153f7df4520b7c634be0c15bc55f43c2fb83b82e4b0',
    'keystore2': 'c969b1d32054d05943a7a101eb0ea92c2063aec5d0cb2a555226197c5f4f5f4a',
    'android.hardware.security.keymint-service-qti': '104325882c4b03dde44daaf645b05272757fc3df0c69fb6e56fa0c2c27617dba',
    '/vendor/lib64/libqtikeymint.so': '657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb',
    '/vendor/lib64/libkeymasterdeviceutils.so': '1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2',
    '/vendor/lib64/libqcbor.so': 'bda86553e45dce1da186830619909b3bae95ff9a91ce3a5df94fa0801c8b2500',
    '/vendor/lib64/libQSEEComAPI.so': '5c996c509fdab3e5925af52f59d554bf54a7c54743c668017a83ef0d1b4e65ed',
}
LIBS = tuple(name for name in PINS if name.startswith('/'))


def collect(run):
    def text(*args):
        raw = run(*args)
        if len(raw) > 1024*1024:
            raise ValueError('read exceeds context bound')
        return raw.decode('utf-8', 'strict').strip()

    if text('get-state') != 'recovery' or text('shell', 'id', '-u') != '0':
        raise ValueError('existing root TWRP ADB required')
    props = {name: text('shell', 'getprop', name) for name in PROPS}
    if (props['ro.product.device'] != 'fuxi' or props['ro.boot.serialno'] != SERIAL or
            not props['ro.twrp.version'] or props['ro.boot.slot_suffix'] != '_a'):
        raise ValueError('unexpected recovery identity/slot')
    if any(props[name] != 'running' for name in PROPS if name.startswith('init.svc.')):
        raise ValueError('reference services are not all running')
    if props['vendor.sys.listeners.registered'] != 'true':
        raise ValueError('listener readiness not established')

    def digest(path):
        answer = text('shell', 'sha256sum', path).split()
        if len(answer) != 2 or answer[1] != path or not re.fullmatch('[0-9a-f]{64}', answer[0]):
            raise ValueError('invalid digest response')
        return answer[0]

    def pid_of(name):
        value = text('shell', 'pidof', name)
        if not re.fullmatch('[1-9][0-9]{0,6}', value):
            raise ValueError('unique reference process required')
        return value

    def started(pid):
        stat = text('shell', 'cat', '/proc/' + pid + '/stat')
        parts = stat.rsplit(')', 1)
        if not stat.startswith(pid + ' (') or len(parts) != 2:
            raise ValueError('invalid process stat identity')
        fields = parts[1].split()
        if len(fields) < 20 or not fields[19].isdigit():
            raise ValueError('invalid process start time')
        return fields[19]

    def mapped(pid):
        # Keep only allowlisted image paths; never publish addresses/full maps.
        return sorted({row[4] for row in parse_maps(text('shell', 'cat', '/proc/' + pid + '/maps'))
                       if row[4] in LIBS})

    processes = {}
    for name in PROCESSES:
        pid = pid_of(name)
        start = started(pid)
        processes[name] = dict(pid=int(pid), start_ticks=start,
                               executable_sha256=digest('/proc/' + pid + '/exe'),
                               mapped_libraries=mapped(pid))
    if any(path not in processes[PROCESSES[2]]['mapped_libraries'] for path in LIBS):
        raise ValueError('KeyMint process did not map all reference libraries')
    libraries = {path: digest(path) for path in LIBS}
    for name, record in processes.items():
        pid = str(record['pid'])
        if (pid_of(name) != pid or started(pid) != record['start_ticks'] or
                mapped(pid) != record['mapped_libraries'] or
                digest('/proc/' + pid + '/exe') != record['executable_sha256']):
            raise ValueError('process identity/mappings changed during capture')
    if props != {name: text('shell', 'getprop', name) for name in PROPS}:
        raise ValueError('properties changed during capture')
    mismatches = [name for name in PROCESSES if processes[name]['executable_sha256'] != PINS[name]]
    mismatches += [name for name in LIBS if libraries[name] != PINS[name]]
    root = Path(__file__).resolve().parent
    return dict(schema=1, result='captured', collected_utc=datetime.now(timezone.utc).isoformat(),
                serial=SERIAL, adb_state='recovery', props=props, processes=processes,
                library_sha256=libraries, reference_hashes_match=not mismatches,
                reference_mismatches=mismatches, stable_snapshots=2,
                constructor_values_proven=False,
                sources={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                         (Path(__file__), root/'collect_fuxi_recovery_binding.py')},
                scope='Read-only current properties, /proc stat/maps/exe hashes and library hashes. '
                      'No process memory, key file, secret, logcat, Binder/KeyMint call, service start or device write. '
                      'Stable current properties do not prove constructor-sampled values or which recovery branch ran.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', type=Path, default=Path('/opt/homebrew/bin/adb'))
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise SystemExit('refusing to overwrite capture')
    ps = subprocess.check_output(['ps', '-eo', 'pid=,args='], text=True)
    if any(name in ps for name in ('test-usb-ram-full', 'usb-ram-send', 'boot-ram-window')):
        raise SystemExit('another device task is active')
    def run(*args):
        result = subprocess.run([str(a.adb), '-s', SERIAL, *args], capture_output=True, timeout=20)
        if result.returncode:
            raise ValueError('ADB metadata read failed')
        return result.stdout
    result = collect(run)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print('Captured TWRP context; reference hashes match:', result['reference_hashes_match'])


if __name__ == '__main__':
    main()
