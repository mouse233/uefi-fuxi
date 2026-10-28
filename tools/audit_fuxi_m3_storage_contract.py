#!/usr/bin/env python3
"""Fixed-binary storage contract audit and secret-free synthetic response model.

Never loads vendor code, reads a storage blob, executes SMC or accepts a device.
The model below returns only a bounded opaque length; it is not a TA decoder.
"""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path

EXPECTED={
 'vendor/lib64/libqtikeymint.so':'657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb',
 'vendor/lib/modules/1.1/qcom-scm.ko':'8932f0206f8a0083af352684cd64de8c9406346dd639606d045136cf27b079a5',
 'vendor/lib/modules/1.1/crypto-qti-hwkm.ko':'be67c86de45b02bfc9e00089c6b49899c1d2579e7db2860e684b186cf22e866d',
 'vendor/lib/modules/1.1/ufshcd-crypto-qti.ko':'02ed3dd34b22ecde458bef3644906ae42b4192be039dbc1dc12e7f0abdbca538',
 'vendor/lib/modules/1.1/crypto-qti-common.ko':'3ee5088ac15e581aff71ddb0f50c8987a21d10b2ffec7f7468e8108ebe4f5242',
}
RANGES={
 'export-decode':('vendor/lib64/libqtikeymint.so',0x35dac,0x3601c,[
   r'QCBORDecode_Init',r'cmp w8, #0x5',r'and w8, w8, #0xfe',r'cmp w8, #0x2',
   r'cmp x8, #0x24',r'cmp w8, #0x6',r'QCBORDecode_Finish',r'_Znam@plt',
   r'km_memscpy',r'stp x24, x22, \[x19\]']),
 'program':('vendor/lib/modules/1.1/crypto-qti-hwkm.ko',0x23c,0x45c,[
   r'ldr w2, \[x1, #0x14\]',r'cmp w2, #0x20',r'b.ls',r'qti_hwkm_init',
   r'mov w9, #0x4040',r'add w25, w9, w22, lsl #7',r'lsl w24, w22, #1',
   r'qtee_shmbridge_flush_shm_buf',r'mov w3, wzr',r'mov w4, wzr',r'mov w5, wzr',
   r'qcom_scm_config_set_ice_key',r'orr w0, w9, #0x80000000',
   r'ldrb w2, \[x23, x20\]',r'_printk']),
 'invalidate':('vendor/lib/modules/1.1/crypto-qti-hwkm.ko',0x4d8,0x56c,[
   r'cmp w8, #0x1',r'b.ne',r'lsl w0, w1, #1',r'mov w1, wzr',
   r'qcom_scm_clear_ice_key',r'mov w0, wzr']),
 'common-evict':('vendor/lib/modules/1.1/crypto-qti-common.ko',0x9fc,0xa50,[
   r'crypto_qti_invalidate_key',r'mov w19, w0',r'mov w0, w19']),
 'ufs-selection':('vendor/lib/modules/1.1/ufshcd-crypto-qti.ko',0x29c,0x48c,[
   r'lsr w23, w11, #9',r'cmp w10, w13',r'cmp w14, w13',r'tst w23, w13',
   r'mov w2, w20',r'mov w3, w23',r'mov w4, w22',r'crypto_qti_keyslot_program']),
 'scm-set':('vendor/lib/modules/1.1/qcom-scm.ko',0x5518,0x5610,[
   r'movk x9, #0x5, lsl #32',r'mov w8, #0x86',r'stp x9, x1, \[sp, #0x10\]',
   r'stp x2, x8, \[sp, #0x20\]',r'stp x9, x10, \[sp, #0x30\]',r'mov x3, xzr',r'mov w4, #0x2']),
 'scm-clear':('vendor/lib/modules/1.1/qcom-scm.ko',0x5610,0x56fc,[
   r'movk x9, #0x6, lsl #32',r'mov w8, #0x2',r'mov x3, xzr',r'mov w4, #0x2']),
 'scm-extended':('vendor/lib/modules/1.1/qcom-scm.ko',0x89e8,0x8af0,[
   r'qtee_shmbridge_allocate_shm',r'mov w0, #0x38',r'ldr x9, \[x23, #0x28\]',
   r'ldr x9, \[x23, #0x30\]',r'ldr x9, \[x23, #0x38\]',r'str x9, \[x8, #0x10\]']),
}

def check_inputs(ramdisk):
 for name,digest in EXPECTED.items():
  if hashlib.sha256((ramdisk/name).read_bytes()).hexdigest()!=digest:raise ValueError('fixed input SHA256 mismatch: '+name)

def _uint(data,pos,major):
 if pos>=len(data):raise ValueError('truncated CBOR')
 head=data[pos];pos+=1
 if head>>5!=major:raise ValueError('unexpected CBOR type')
 ai=head&31
 if ai<24:return ai,pos
 if ai not in (24,25,26,27):raise ValueError('indefinite/reserved CBOR not accepted')
 count=1<<(ai-24)
 if pos+count>len(data):raise ValueError('truncated CBOR length')
 value=int.from_bytes(data[pos:pos+count],'big')
 return value,pos+count

def validate_synthetic_export_envelope(response,payload_limit=40960):
 """Conservative *host-only* subset: LE status/len + {36: bstr}, length only.

 It must never be wired to a phone or key path as a complete vendor decoder.
 Does not return payload, hex, hashes, raw bytes or a printable key value.
 """
 if type(response) is not bytes or type(payload_limit) is not int or not 1<=payload_limit<=40960:
  raise ValueError('invalid synthetic model input')
 if len(response)<8 or len(response)>40960:raise ValueError('envelope bounds')
 status,size=struct.unpack_from('<II',response)
 if status or size!=len(response)-8 or size>payload_limit:raise ValueError('status/length')
 data=memoryview(response)[8:];count,pos=_uint(data,0,5)
 if count!=1:raise ValueError('one known map entry required')
 label,pos=_uint(data,pos,0)
 if label!=36:raise ValueError('export label36 required')
 length,pos=_uint(data,pos,2)
 if not 0<length<=payload_limit or pos+length!=len(data):raise ValueError('opaque payload bounds/trailing data')
 return {'opaque_bytes':length,'representation':'opaque-storage-export','hardware_verified':False}

def audit(ramdisk,output):
 check_inputs(ramdisk);output.mkdir(parents=True,exist_ok=True);evidence={}
 for label,(name,start,end,patterns) in RANGES.items():
  asm=subprocess.check_output(['llvm-objdump','-dr',f'--start-address={start}',f'--stop-address={end}',str(ramdisk/name)],text=True)
  normalized=re.sub(r'[\t ]+',' ',asm)
  for pattern in patterns:
   if not re.search(pattern,normalized):raise ValueError(label+' missing instruction '+pattern)
  (output/(label+'.asm')).write_text(asm)
  evidence[label]={'file':label+'.asm','input':name,'start':hex(start),'stop':hex(end),'sha256':hashlib.sha256(asm.encode()).hexdigest()}
 root=Path(__file__).resolve().parents[1]
 paths=[Path(__file__),root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/M3DefaultKeyPlan.c',root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe/M3DefaultKeyPlan.h',
  root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe/UfsCore.c',root/'tools/m3_ufs_crypto_layout.py']
 report=dict(result='passed',inputs=EXPECTED,evidence=evidence,
  client_export=dict(cbor_map_enum=5,label=36,label_enums=[2,3],value_enum=6,bounded_length_not_fixed_keysize=True,raw_key_semantics_not_proven=True),
  hwkm=dict(program_size_necessary_gt32=True,scm_slot='logical_slot*2',config_offset='0x4040+logical_slot*0x80',scm_tail_args=[0,0,0],program_failure_payload_logging_must_not_be_ported=True,evict_zero_can_skip_clear_if_not_initialized=True),
  scm=dict(set_arginfo='86',set_arg_count=6,extended_buffer_required=True,clear_arg_count=2,derive_is_distinct_operation=True),
  qcbor_public_types=dict(url='https://github.com/laurencelundblade/QCBOR/blob/master/inc/qcbor/qcbor_decode.h',git_blob='f873eedc761f1ace17b7d82c9c0cd7cd9159533e',types={'INT64':2,'UINT64':3,'MAP':5,'BYTE_STRING':6},exact_device_library_version_proven=False),
  sources={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
  scope='Fixed local binary instruction facts plus public enum corroboration; synthetic parser length-only. No vendor execution, actual key/blob reads, device, SCM, TA, slot ownership or decryption.',
  hardware_gates=['TA convert success and bounded opaque representation','owned ICE logical slot and capability selection','SCM extended-argument lifetime/return and HWKM readiness','confirmed hardware clear after queue quiesce','crypto UTRD/DUN and one-block mapped plaintext digest comparison'])
 (output/'audit.json').write_text(json.dumps(report,indent=2)+'\n');return report

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--ramdisk',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 print(json.dumps(audit(a.ramdisk,a.output),indent=2))
if __name__=='__main__':main()
