#!/usr/bin/env python3
"""Offline semantic-model and tamper tests; no vendor, firmware or device execution."""
import argparse,hashlib,json,shutil,struct,tempfile
from pathlib import Path
import audit_fuxi_m3_ta_contract as m
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--ramdisk',type=Path,required=True);p.add_argument('--reference',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 vectors=0
 def reject(fn,*args,**kwargs):
  nonlocal vectors
  try:fn(*args,**kwargs)
  except ValueError:vectors+=1
  else:raise AssertionError('invalid input accepted')
 x=m.build_lookup(0x44,'keymaster64');assert x['counts']==0x1001 and x['descriptors']==[dict(kind='BI',offset=32,size=11)] and struct.unpack_from('<I',x['buffer'],20)[0]==0;vectors+=1
 for handle in [0,1,0x80000004,-1,True]:reject(m.build_lookup,handle,'keymaster64')
 for name in ['', 'x'*64,'bad/name','a\0b','密钥']:reject(m.build_lookup,0x44,name)
 # Synthetic ELF64: program table in b00, two payload splits at validated offsets.
 b00=bytearray(232);b00[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<Q',b00,32,64);struct.pack_into('<HHH',b00,52,64,56,3)
 for i,off,size in [(1,4096,16),(2,8192,32)]:struct.pack_into('<Q',b00,64+i*56+8,off);struct.pack_into('<QQ',b00,64+i*56+32,size,size)
 parts={1:b'A'*16,2:b'B'*32}
 fw=m.plan_elf64_fragments(bytes(b00),parts);assert fw['image_bytes']==8224 and not fw['authenticated'];vectors+=1
 for change in ['magic','class','phoff','entsize','phnum','overlap','extent','memsz']:
  b=bytearray(b00)
  if change=='magic':b[0]=0
  elif change=='class':b[4]=1
  elif change=='phoff':struct.pack_into('<Q',b,32,233)
  elif change=='entsize':struct.pack_into('<H',b,54,55)
  elif change=='phnum':struct.pack_into('<H',b,56,101)
  elif change=='overlap':struct.pack_into('<Q',b,64+2*56+8,4100)
  elif change=='extent':struct.pack_into('<Q',b,64+2*56+8,m.MAX_MODEL)
  elif change=='memsz':struct.pack_into('<Q',b,64+56+40,15)
  reject(m.plan_elf64_fragments,bytes(b),parts)
 reject(m.plan_elf64_fragments,bytes(b00),{1:parts[1]})
 reject(m.plan_elf64_fragments,bytes(b00),{1:parts[1],2:parts[2],3:b''})
 reject(m.plan_elf64_fragments,bytes(b00),{1:b'A'*15,2:parts[2]})
 y=m.build_load_from_buffer(0x44,bytes(b00),'keymaster64')
 assert y['counts']==0x1012 and y['output_objects']==1 and y['null_input_objects']==0 and y['descriptors'][-1]['size']==64;vectors+=1
 reject(m.build_load_from_buffer,0x44,bytes(b00)+bytes(8192),'keymaster64',capacity=4096)
 z=m.build_send_request(0x44,b'\x00\x02\0\0'+bytes(4),40952,True)
 assert z['counts']==0x424 and z['raw_bytes']==82024 and z['page_bytes']==86016 and z['null_input_objects']==4
 assert [(d['offset'],d['size']) for d in z['descriptors']]==[(96,8),(104,40952),(41056,0),(41056,4),(41064,8),(41072,40952)]
 assert z['buffer'][60:92]==bytes(32);vectors+=1
 reject(m.build_send_request,0x44,b'abcdefgh',40952,True,capacity=8192)
 reject(m.build_send_request,0x44,b'abcdefgh',40960,True)
 reject(m.build_send_request,0x44,b'',8,True)
 reject(m.build_send_request,0x44,b'abcdefgh',0,True)
 reject(m.build_send_request,0x44,b'abcdefgh',8,2)
 assert m.parse_response(struct.pack('<II',0,3)+b'abc',32)==b'abc';vectors+=1
 for raw,cap in [(b'',8),(struct.pack('<II',1,0),8),(struct.pack('<II',0,9),16),(struct.pack('<II',0,4)+b'ab',16),(struct.pack('<II',0,0),7)]:
  reject(m.parse_response,raw,cap)
 m.verify_inputs(a.ramdisk,a.reference);vectors+=1
 # SHA refusal is independent of the disassembler and never executes inputs.
 rejected=[]
 with tempfile.TemporaryDirectory(prefix='ta-contract-tamper-') as tmp:
  dst=Path(tmp);ram=dst/'ramdisk';ref=dst/'ref';ref.mkdir()
  for name in m.EXPECTED:
   target=ram/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(a.ramdisk/name,target)
  for name in m.REF_EXPECTED:shutil.copyfile(a.reference/name,ref/name)
  for prefix,names in [(ram,m.EXPECTED),(ref,m.REF_EXPECTED)]:
   for name in names:
    path=prefix/name;raw=path.read_bytes();mutated=bytearray(raw);mutated[-1]^=1;path.write_bytes(mutated)
    reject(m.verify_inputs,ram,ref);rejected.append(str(path.relative_to(dst)));path.write_bytes(raw)
 root=Path(__file__).resolve().parents[1];paths=[Path(__file__),Path(m.__file__)]
 report=dict(result='passed',vectors=vectors,mutated_inputs_rejected=rejected,
  scope='Independent offline semantic/layout/capacity/ELF plan and fixed SHA refusal; not production UEFI or vendor execution equivalence, not TA authentication',
  sample=dict(wire_bytes=82024,input_page_bytes=86016,callback_output_additional=True),
  sources={str(x.relative_to(root)):hashlib.sha256(x.read_bytes()).hexdigest() for x in paths},
  binary_inputs=m.EXPECTED,reference_inputs=m.REF_EXPECTED)
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
