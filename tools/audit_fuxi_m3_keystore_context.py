#!/usr/bin/env python3
"""Fixed TWRP/keystore context audit; optional public-input branch emulation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from audit_fuxi_m3_key_recovery import PINS as BASE_PINS, elf_bytes
from collect_fuxi_twrp_keymint_context import PINS, PROCESSES

SOURCE = ('https://android.googlesource.com/platform/system/security.git/+/'
          'd43c1b9db3510dd5c25d35a34b926389bfeb2d33/keystore2/src/security_level.rs')


def verify(name, data):
    expected = PINS['keystore2'] if name == 'keystore2' else BASE_PINS[name]
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('fixed input mismatch: ' + name)


def branch_controls(raw):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_PC
    cases=[]
    for outer,domain,status in ((1,1,-62),(0,1,-62),(1,2,-62),(1,1,-33),(1,1,-64),(1,1,0)):
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        base,stack=0x1000000,0x3000000
        u.mem_map(base,0x200000);u.mem_map(stack,0x10000)
        # Only the nine real test/branch instructions. No callback, allocator,
        # Binder transaction, crypto, upgrade or error handler is mapped.
        start,upgrade,other=0x1115a4,0x1115c8,0x111648
        u.mem_write(base+start,elf_bytes(raw,start,upgrade-start))
        u.reg_write(UC_ARM64_REG_SP,stack)
        u.mem_write(stack+0x630,struct.pack('<IIi',outer,domain,status))
        reached=[]
        def stop(emu,pc,_size,_ctx):
            if pc in (base+upgrade,base+other):
                reached.append(pc-base);emu.emu_stop();return
            if not base+start<=pc<base+upgrade:
                raise ValueError('execution outside public branch fragment')
        u.hook_add(UC_HOOK_CODE,stop)
        u.emu_start(base+start,base+0x180000,count=16)
        expected=upgrade if (outer,domain,status)==(1,1,-62) else other
        if reached!=[expected]:raise ValueError('fixed status branch did not match')
        cases.append(dict(outer=outer,error_domain=domain,status=status,stop_va=hex(expected),
                          upgrade_branch_selected=expected==upgrade))
    return cases


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference',type=Path,required=True,help='fixed expanded TWRP ramdisk root')
    p.add_argument('--partition',type=Path,required=True)
    p.add_argument('--twrp-context',type=Path,required=True)
    p.add_argument('--twrp-binding',type=Path,required=True)
    p.add_argument('--android-context',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--objdump',default='llvm-objdump')
    p.add_argument('--controls',action='store_true')
    a=p.parse_args()
    paths={'recovery':a.reference/'system/bin/recovery',
           'keystore2':a.reference/'system/bin/keystore2',
           'keymint':a.reference/'vendor/lib64/libqtikeymint.so','partition':a.partition}
    pins={**BASE_PINS,'keystore2':PINS['keystore2']}
    raw={name:path.read_bytes() for name,path in paths.items()}
    for name,data in raw.items():
        verify(name,data)
        changed=bytearray(data);changed[-1]^=1
        try:verify(name,changed)
        except ValueError:pass
        else:raise AssertionError('mutated input accepted: '+name)
    twrp=json.loads(a.twrp_context.read_text());android=json.loads(a.android_context.read_text())
    binding=json.loads(a.twrp_binding.read_text())
    if (twrp.get('result')!='captured' or twrp.get('serial')!='fcde91e' or
            twrp.get('stable_snapshots')!=2 or not twrp.get('reference_hashes_match')):
        raise ValueError('stable matching real TWRP capture required')
    if android.get('serial')!='fcde91e':raise ValueError('wrong Android context serial')
    if (binding.get('serial')!='fcde91e' or binding.get('process')!='recovery' or
            binding.get('executable_sha256')!=BASE_PINS['recovery'] or
            binding.get('binding')!=dict(state=2,meaning='used without seed',vector_empty=True,stable_snapshots=2)):
        raise ValueError('stable real TWRP empty-seed metadata required')
    for name in PROCESSES:
        if twrp['processes'][name]['executable_sha256']!=PINS[name]:raise ValueError('runtime binary mismatch')
    for name in ('ro.build.version.release','ro.build.version.security_patch','ro.vendor.build.security_patch'):
        if name not in twrp['props'] or name not in android['props']:raise ValueError('context field absent')
    if (twrp['props']['ro.build.version.release']!='17' or android['props']['ro.build.version.release']!='17' or
            any(twrp['props'][k]!='2099-12-31' or android['props'][k]!='2026-10-05' for k in
                ('ro.build.version.security_patch','ro.vendor.build.security_patch'))):
        raise ValueError('this differential is pinned to the two observed contexts')
    a.output.mkdir(parents=True,exist_ok=True)
    ranges={
        'recovery-blob-domain':('recovery',0x250F28,0x250F50,['mov w8, #0x3','mov w8, #0x64']),
        'recovery-create-operation':('recovery',0x251110,0x251134,['ldr x9, [x8, #0x30]','blr x9']),
        'keystore-status-branch':('keystore2',0x1115A4,0x1115C8,['cmn w8, #0x3e','b.ne 0x111648']),
        'keystore-upgrade-label':('keystore2',0x1115FC,0x111630,['#0x55a','bl 0x7d810']),
        'keystore-upgrade-call':('keystore2',0x112228,0x112244,['ldr x9, [x26, #0x48]','blr x9']),
        'keystore-retry-closure':('keystore2',0x113ABC,0x113AE0,['bl 0x1249b0']),
        'keystore-begin-call':('keystore2',0x124AE4,0x124B18,['ldr x10, [x8, #0x68]','blr x10']),
        'hal-upgrade-command':('keymint',0x2F50C,0x2F574,['mov w8, #0x2114','serializeClientParamsKeyblob']),
    }
    evidence={}
    for name,(kind,lo,hi,needles) in ranges.items():
        text=subprocess.check_output([a.objdump,'-d','--start-address='+hex(lo),'--stop-address='+hex(hi),str(paths[kind])],text=True)
        normal=re.sub(r'[\t ]+',' ',text)
        if any(needle not in normal for needle in needles):raise ValueError('fixed code changed: '+name)
        (a.output/(name+'.asm')).write_text(text)
        evidence[name]=dict(input=kind,start=hex(lo),end=hex(hi),code_sha256=hashlib.sha256(elf_bytes(raw[kind],lo,hi-lo)).hexdigest())
    # Bind the branch label itself, not only its nearby address computation.
    label=b'In KeystoreSecurityLevel::upgrade_keyblob_if_required_with: calling upgradeKey.'
    if elf_bytes(raw['keystore2'],0x2A55A,len(label))!=label:raise ValueError('branch label changed')
    controls=branch_controls(raw['keystore2']) if a.controls else []
    configure_controls=[]
    if a.controls:
        from audit_fuxi_m3_configure_gate import configure,encode
        for patch in (20261005,20991231):
            payload=encode([(0x300002c1,170000),(0x300002c2,patch),(0x300002ce,patch)])
            _u,result=configure(raw['partition'],payload)
            if result['status']!=0 or result['values']!=[170000,0,patch,patch]:raise ValueError('public configure control failed')
            configure_controls.append(dict(patch=patch,request_hex='16210000'+payload.hex(),**result))
    root=Path(__file__).resolve().parents[1]
    files=[Path(__file__),root/'tools/collect_fuxi_twrp_keymint_context.py',root/'tools/audit_fuxi_m3_key_recovery.py']
    if a.controls:files += [root/'tools/audit_fuxi_m3_configure_gate.py',root/'tools/audit_fuxi_m3_metadata_read.py']
    report=dict(result='passed',input_sha256=pins,mutated_inputs_rejected=len(raw),evidence=evidence,branch_controls=controls,public_configure_controls=configure_controls,
        twrp_context_sha256=hashlib.sha256(a.twrp_context.read_bytes()).hexdigest(),
        twrp_binding_sha256=hashlib.sha256(a.twrp_binding.read_bytes()).hexdigest(),
        android_context_sha256=hashlib.sha256(a.android_context.read_bytes()).hexdigest(),
        context_difference={k:dict(twrp=twrp['props'][k],android=android['props'][k]) for k in
            ('ro.build.version.release','ro.build.version.security_patch','ro.vendor.build.security_patch')},
        upstream_reference=SOURCE,upstream_binary_source_identity_proven=False,
        limits=['Current stable properties do not prove values sampled during KeyMint construction.',
                'The fixed keystore2 contains -62 -> upgrade -> retry; this does not prove that the phone used it for the metadata key.',
                'Upstream source explains the static pattern, not an exact source/build identity.',
                'No real key/blob, secure service or generate/upgrade/configure command was sent. UEFI remains no-upgrade.',
                'The public 2099 configure packet is only an offline differential input, not a qualified boot candidate or proved fix.'],
        sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    (a.output/'audit.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(evidence),'fixed ranges,',len(controls),'status branch controls,',len(configure_controls),'public configure controls')


if __name__=='__main__':main()
