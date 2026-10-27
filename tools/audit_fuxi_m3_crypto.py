#!/usr/bin/env python3
"""Check fixed TWRP modules; static evidence only, never execute vendor code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

EXPECTED = {
    'qcom-scm.ko': '8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5',
    'ufshcd-crypto-qti.ko': '02ed3dd34b22ecde458bef3644906ae42b4192be039dbc1dc12e7f0abdbca538',
    'crypto-qti-hwkm.ko': 'be67c86de45b02bfc9e00089c6b49899c1d2579e7db2860e684b186cf22e866d',
}


def require(ok, message):
    if not ok:
        raise SystemExit('audit failed: ' + message)


def disasm(module, symbol):
    return subprocess.check_output(['llvm-objdump', '-dr', '--disassemble-symbols='+symbol, str(module)], text=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--modules', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    for name, sha in EXPECTED.items():
        require(hashlib.sha256((a.modules/name).read_bytes()).hexdigest() == sha, name)
    scm, ufs, hw = (a.modules/n for n in EXPECTED)
    register=disasm(scm,'qtee_shmbridge_register')
    for pattern in (r'cmp\s+w4,\s*#0x4', r'lsl\s+w10,\s*w23,\s*#9',
                    r'mov\s+w11,\s*#0x1a', r'R_AARCH64_CALL26\s+qcom_scm_create_shm_bridge'):
        require(re.search(pattern,register) is not None, 'bridge register '+pattern)
    program=disasm(ufs,'ufshcd_crypto_qti_keyslot_program')
    for pattern in (r'lsr\s+w23,\s*w11,\s*#9', r'cmp\s+w10,\s*w13', r'cmp\s+w14,\s*w13', r'tst\s+w23,\s*w13',
                    r'R_AARCH64_CALL26\s+crypto_qti_keyslot_program'):
        require(re.search(pattern,program) is not None, 'UFS selection '+pattern)
    hwprog=disasm(hw,'crypto_qti_program_key')
    for pattern in (r'lsl\s+w24,\s*w22,\s*#1',r'R_AARCH64_CALL26\s+qti_hwkm_init',
                    r'R_AARCH64_CALL26\s+qtee_shmbridge_allocate_shm',
                    r'R_AARCH64_CALL26\s+qtee_shmbridge_flush_shm_buf',
                    r'R_AARCH64_CALL26\s+qcom_scm_config_set_ice_key'):
        require(re.search(pattern,hwprog) is not None, 'HWKM '+pattern)
    ordered = [hwprog.index(x) for x in ('R_AARCH64_CALL26\tqti_hwkm_init',
               'R_AARCH64_CALL26\tqtee_shmbridge_allocate_shm',
               'R_AARCH64_CALL26\tqtee_shmbridge_flush_shm_buf',
               'R_AARCH64_CALL26\tqcom_scm_config_set_ice_key')]
    require(ordered == sorted(ordered), 'HWKM linear call-site order')
    with tempfile.TemporaryDirectory(prefix='fuxi-crypto-audit-') as d:
        path=Path(d)/'rodata'
        subprocess.run(['llvm-objcopy', '--dump-section', '.rodata='+str(path), str(ufs)], check=True)
        data=path.read_bytes()
        require(data[0x160:0x168] == bytes.fromhex('0000000003000000'), 'crypto selection table entry')
    result=dict(result='passed',file_hashes=EXPECTED,scm_register_vm_count_limit=4,
                scm_register_has_conditional_extra_flags_0x1a=True,
                ufs_selects_algorithm_keysize_dusize=True,
                crypto_table_at_0x160='0000000003000000',
                hwkm_initialization_and_bridge_before_scm=True,physical_slot_shift_one=True,
                scope='fixed ELF static patterns only; no device, key or runtime ABI verification')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__ == '__main__': main()
