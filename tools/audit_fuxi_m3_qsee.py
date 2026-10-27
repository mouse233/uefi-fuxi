#!/usr/bin/env python3
"""Audit fixed A17 TWRP QSEE transport files without running device code."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

EXPECTED = {
    'vendor/lib/modules/1.1/smcinvoke_dlkm.ko': '831a6db7570e66729db84cd0a7ddc63f8cdbc4b03fd250dee15b80b561969348',
    'vendor/lib/modules/1.1/qseecom_proxy.ko': '5dc0d5df0cbb704d9657faefcfc3d182d0dd9e17d09831fe7f96f7fc82355565',
    'vendor/lib/modules/1.1/qcom-scm.ko': '8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5',
    'vendor/lib/modules/1.1/modules.dep': '5b0a211ac99af18d84104469620ffd20233ec218f04c9227b37c1f2dabc7c31e',
    'vendor/lib64/libqtikeymint.so': '657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb',
    'vendor/lib64/libkeymasterutils.so': '3462e243d9de84e797ac9387e43796f6f4f1dd3682eeabe74541c9a6a881f30b',
    'vendor/lib64/libkeymasterdeviceutils.so': '1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2',
    'vendor/lib64/libQSEEComAPI.so': '5c996c509fdab3e5925af52f59d554bf54a7c54743c668017a83ef0d1b4e65ed',
}


def output(*cmd):
    return subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)


def require(condition, description):
    if not condition:
        raise SystemExit('audit failed: ' + description)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ramdisk', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--llvm-nm', default='llvm-nm')
    p.add_argument('--llvm-objdump', default='llvm-objdump')
    a = p.parse_args()
    root = a.ramdisk.resolve()
    for name, expected in EXPECTED.items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name)
    mod = root / 'vendor/lib/modules/1.1/smcinvoke_dlkm.ko'
    proxy = root / 'vendor/lib/modules/1.1/qseecom_proxy.ko'
    mint = root / 'vendor/lib64/libqtikeymint.so'
    mod_syms = output(a.llvm_nm, str(mod))
    proxy_syms = output(a.llvm_nm, str(proxy))
    mint_syms = output(a.llvm_nm, '-D', '-C', str(mint))
    device_syms = output(a.llvm_nm, '-D', '-C', str(root / 'vendor/lib64/libkeymasterdeviceutils.so'))
    def has_symbol(text, kind, name):
        return re.search(r'^\s*(?:[0-9a-fA-F]+\s+)?' + kind + r'\s+' + re.escape(name) + r'$', text, re.M) is not None
    for sym in ('provide_qseecom_kernel_fun_ops', 'qcom_scm_invoke_smc', 'qtee_shmbridge_allocate_shm'):
        require(has_symbol(mod_syms, 'U', sym), sym)
    for sym in ('__qseecom_send_command', '__qseecom_start_app'):
        require(has_symbol(mod_syms, '[tT]', sym), sym)
    for sym in ('provide_qseecom_kernel_fun_ops', 'qseecom_send_command', 'qseecom_start_app'):
        require(has_symbol(proxy_syms, 'T', sym), sym)
    for sym in ('keymasterutils::KeymasterUtils::qseecom_dev_init()',
                'keymasterutils::KeymasterUtils::sendCmd(keymaster_blob_t const&, keymaster_blob_t*)'):
        require(has_symbol(mint_syms, 'U', sym), sym)
        require(has_symbol(device_syms, 'T', sym), sym)
    for sym in ('QSEECom_start_app', 'QSEECom_send_cmd', 'QSEECom_shutdown_app'):
        require(has_symbol(device_syms, 'U', sym), sym)
    dis = output(a.llvm_objdump, '-dr', '--disassemble-symbols=get_qseecom_kernel_fun_ops', str(mod))
    require('qseecom_driver_ops' in dis and 'R_AARCH64_CALL26' in dis and 'provide_qseecom_kernel_fun_ops' in dis, 'QSEE registration')
    deps = (root / 'vendor/lib/modules/1.1/modules.dep').read_text().splitlines()
    matches = [x for x in deps if x.startswith('smcinvoke_dlkm.ko:')]
    require(len(matches) == 1 and 'qseecom_proxy.ko' in matches[0] and 'qcom-scm.ko' in matches[0], 'module dependencies')
    report = {'result': 'passed', 'files_sha256': EXPECTED,
              'smcinvoke_depends_on_proxy_and_scm': True,
              'smcinvoke_registers_qseecom_driver_ops': True,
              'smcinvoke_has_qseecom_send_and_start_symbols': True,
              'smcinvoke_imports_scm_invoke_and_shmbridge': True,
              'qtikeymint_imports_keymasterutils_transport': True,
              'deviceutils_provides_transport_and_imports_qseecom': True,
              'scope': 'static ELF and metadata only; no execution, firmware ABI or keys verified'}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
