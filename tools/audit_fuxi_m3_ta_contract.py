#!/usr/bin/env python3
"""Fixed-input TA audit and offline message models; no device or vendor execution."""
import argparse,hashlib,json,re,struct,subprocess,tempfile
from pathlib import Path
from audit_fuxi_m3_keymint import audit as audit_keymint

EXPECTED={
 'vendor/lib/modules/1.1/smcinvoke_dlkm.ko':'831a6db7570e66729db84cd0a7ddc63f8cdbc4b03fd250dee15b80b561969348',
 'vendor/lib64/libqtikeymint.so':'657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb',
 'vendor/lib64/libkeymasterdeviceutils.so':'1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2'}
REF_EXPECTED={
 'smcinvoke.c':'9907468f34d72323e4f9919f9a3019a8fef0e0e70cb629a83f8951c2288a6b7f',
 'smcinvoke_kernel.c':'26b3716f8ec796cea6dace1b7adb9d8603ab1ac9eb51ecacac32c3ce8624272d',
 'IClientEnv.h':'e4efdfa386aef8105af11eb133e7eeeccb219014db06f5b43f11fac2e2528d2a',
 'IQSEEComCompat.h':'055f1af7680e0ccc8ca5e0fc70bcef46ae27dad06e22edba347ef429244f8fad',
 'IQSEEComCompatAppLoader.h':'597124e1769ab805fef0e947a4636dc043250ba368cc218557a339fd55122a06'}
U32=(1<<32)-1
PAGE=4096
MAX_MODEL=16*1024*1024
def _uint(n,label):
 if isinstance(n,bool) or not isinstance(n,int) or not 0<=n<=U32:raise ValueError(label)
 return n
def _handle(h):
 _uint(h,'handle')
 if h<=1 or h&0x80000000:raise ValueError('non-root remote handle required')
 return h
def _name(name):
 if not isinstance(name,str) or not name or '\0' in name:raise ValueError('app name')
 try:b=name.encode('ascii')
 except UnicodeEncodeError:raise ValueError('ASCII app name required')
 if len(b)>=64 or '/' in name or '\\' in name:raise ValueError('bounded basename required')
 return b
def align(n,a):return (n+a-1)//a*a
def build_call(handle,operation,bi,bo,oi=0,oo=0,capacity=MAX_MODEL):
 """Independent model of fixed-reference inline marshal; not a firmware encoder."""
 _handle(handle);_uint(operation,'operation');_uint(capacity,'capacity')
 if not 4096<=capacity<=MAX_MODEL:raise ValueError('model capacity')
 counts=(len(bi),len(bo),oi,oo)
 if any(type(n) is not int or not 0<=n<=15 for n in counts):raise ValueError('counts')
 if any(not isinstance(b,bytes) for b in bi):raise ValueError('BI bytes required')
 for n in bo:_uint(n,'BO size')
 desc=[];cursor=align(12+8*sum(counts),8)
 for kind,items in [('BI',bi),('BO',bo)]:
  for item in items:
   cursor=align(cursor,8);size=len(item) if kind=='BI' else item
   if size>MAX_MODEL or cursor>capacity-size:raise ValueError('message exceeds capacity')
   desc.append(dict(kind=kind,offset=cursor,size=size));cursor+=size
 size=align(cursor,PAGE)
 if size>capacity:raise ValueError('page aligned message exceeds capacity')
 buf=bytearray(size);packed=sum(n<<(4*i) for i,n in enumerate(counts))
 struct.pack_into('<III',buf,0,handle,operation,packed)
 for i,d in enumerate(desc):struct.pack_into('<II',buf,12+8*i,d['offset'],d['size'])
 for d,b in zip(desc,bi):buf[d['offset']:d['offset']+len(b)]=b
 return dict(operation=operation,counts=packed,descriptors=desc,raw_bytes=cursor,page_bytes=size,
             null_input_objects=oi,output_objects=oo,buffer=bytes(buf))
def build_lookup(handle,name,capacity=PAGE):
 return build_call(handle,2,[_name(name)],[],oo=1,capacity=capacity)
def build_load_from_buffer(handle,elf,name,capacity=MAX_MODEL):
 if not isinstance(elf,bytes) or len(elf)<64 or elf[:4]!=b'\x7fELF':raise ValueError('ELF input')
 return build_call(handle,1,[elf,_name(name)],[64],oo=1,capacity=capacity)
def build_send_request(handle,request,response_capacity,is64,capacity=MAX_MODEL):
 if not isinstance(request,bytes) or not request:raise ValueError('request bytes')
 _uint(response_capacity,'response capacity')
 if not 0<response_capacity<=0xa000 or len(request)+response_capacity>0xa000:raise ValueError('40KiB userspace partition')
 if type(is64) is not bool:raise ValueError('is64 boolean')
 return build_call(handle,0,[request,bytes(response_capacity),b'',struct.pack('<I',int(is64))],
                   [len(request),response_capacity],oi=4,capacity=capacity)
def parse_response(raw,capacity):
 """Conservative host-only command response bounds; no status interpretation."""
 _uint(capacity,'response capacity')
 if not isinstance(raw,bytes) or capacity<8 or len(raw)>capacity or len(raw)<8:raise ValueError('response envelope')
 status,length=struct.unpack_from('<II',raw)
 if status or length>capacity-8 or length>len(raw)-8:raise ValueError('TA error or response length')
 return raw[8:8+length]
def plan_elf64_fragments(b00,parts,limit=MAX_MODEL):
 """Stricter bounded plan for synthetic split ELF64; does not authenticate a TA."""
 if not isinstance(b00,bytes) or len(b00)<64 or b00[:7]!=b'\x7fELF\x02\x01\x01':raise ValueError('ELF64 little-endian header')
 if not isinstance(parts,dict) or type(limit) is not int or not 64<=limit<=MAX_MODEL:raise ValueError('fragment inputs')
 off=struct.unpack_from('<Q',b00,32)[0];eh,ents,num=struct.unpack_from('<HHH',b00,52)
 if eh!=64 or ents!=56 or not 2<=num<=100 or off<64 or off>len(b00)-num*56:raise ValueError('program table bounds')
 if set(parts)!=set(range(1,num)):raise ValueError('missing/extra split fragments')
 ranges=[(0,len(b00))];entries=[];total=len(b00)
 for i in range(1,num):
  at=off+i*56;offset=struct.unpack_from('<Q',b00,at+8)[0]
  filesz,memsz=struct.unpack_from('<QQ',b00,at+32);part=parts[i]
  if not isinstance(part,bytes) or filesz!=len(part) or memsz<filesz or offset>limit-filesz:raise ValueError('fragment extent')
  end=offset+filesz
  if filesz and any(offset<hi and lo<end for lo,hi in ranges):raise ValueError('overlapping fragments')
  ranges.append((offset,end));total=max(total,end);entries.append(dict(index=i,offset=offset,bytes=filesz))
 return dict(elf_class=64,fragments=num,image_bytes=total,entries=entries,authenticated=False)
def verify_inputs(ramdisk,reference):
 for name,digest in EXPECTED.items():
  if hashlib.sha256((ramdisk/name).read_bytes()).hexdigest()!=digest:raise ValueError('fixed binary mismatch: '+name)
 for name,digest in REF_EXPECTED.items():
  if hashlib.sha256((reference/name).read_bytes()).hexdigest()!=digest:raise ValueError('fixed reference mismatch: '+name)
def audit(ramdisk,reference,output):
 verify_inputs(ramdisk,reference);output.mkdir(parents=True,exist_ok=True)
 keymint=audit_keymint(ramdisk,output/'keymint')
 module=ramdisk/'vendor/lib/modules/1.1/smcinvoke_dlkm.ko'
 probes={
 'open-loader':(0x1e38,0x1e98,[r'mov w8, #0x7a',r'mov w1, wzr',r'mov w3, #0x1001',r'get_client_env_object']),
 'lookup':(0x1f18,0x1f84,[r'mov w1, #0x2',r'mov w3, #0x1001',r'firmware_request_from_smcinvoke',r'b 0x2028']),
 'load-buffer':(0x1f9c,0x2038,[r'mov w10, #0x40',r'mov w1, #0x1',r'mov w3, #0x1012',r'ldrb w8, \[x25, #0x4\]',r'qtee_shmbridge_allocate_shm']),
 'send-request':(0x1c3c,0x1d1c,[r'cmp w9, #0x2',r'cset w9, eq',r'mov w1, wzr',r'mov w3, #0x424',r'stp xzr, xzr, \[sp, #0x78\]',r'stp xzr, xzr, \[x10, #0x90\]']),
 'split-firmware':(0x74c8,0x77fc,[r'ldrb w3, \[x23, #0x4\]',r'ldrh w24, \[x23, #0x38\]',r'ldr x11, \[x23, #0x20\]',r'firmware_request_nowarn',r'qtee_shmbridge_allocate_shm',r'memcpy']),
 }
 evidence={}
 for name,(start,end,patterns) in probes.items():
  text=subprocess.check_output(['llvm-objdump','-dr',f'--start-address={start}',f'--stop-address={end}',str(module)],text=True)
  norm=re.sub(r'[\t ]+',' ',text)
  for pattern in patterns:
   if not re.search(pattern,norm):raise ValueError('instruction mismatch: '+name+' '+pattern)
  (output/(name+'.asm')).write_text(text);evidence[name]=dict(start=hex(start),stop=hex(end),sha256=hashlib.sha256(text.encode()).hexdigest())
 # Assert reference semantics separately; its SHA is pinned but exact device equivalence is false.
 source=(reference/'smcinvoke_kernel.c').read_text()
 for token in ['IQSEEComCompatAppLoader_lookupTA','IQSEEComCompatAppLoader_loadFromBuffer','Object_NULL, Object_NULL','Object_NULL, Object_NULL);','%s.b00','%s.b%02d']:
  if token not in source:raise ValueError('reference contract token absent')
 sample=build_send_request(0x44,b'\x00\x02\x00\x00'+bytes(4),0x9ff8,True)
 inventory={name:sorted(str(p.relative_to(ramdisk)) for p in ramdisk.rglob(name+'.b[0-9][0-9]')) for name in ['keymaster64','keymaster']}
 report=dict(result='passed',fixed_binaries=EXPECTED,reference_sources=REF_EXPECTED,reference_exact_device_match=False,
  evidence=evidence,keymint_init=dict(ta=keymint['ta_name'],fallback=keymint['fallback_ta_name'],userspace_shared_bytes=keymint['userspace_shared_bytes'],get_version_command='0200',api_version_command=keymint['api_version_command'],api_version_value=keymint['api_version_value'],configure_command=keymint['configure_command'],os_parameters_verified=False),loader=dict(uid=122,open_op=0,open_counts='1001',lookup_op=2,lookup_counts='1001',load_buffer_op=1,load_buffer_counts='1012',dist_name_capacity=64,input_objects=0),
  send=dict(op=0,counts='0424',bi=4,bo=2,oi=4,oo=0,null_input_objects=4,embedded_offsets_count=0,is64_from_context_arch=True,lookup_initializes_arch_proven=False),
  sample_send_layout={k:v for k,v in sample.items() if k!='buffer'},firmware_input_inventory=inventory,
  sources={str(p.relative_to(Path(__file__).resolve().parents[1])):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),Path(__file__).with_name('audit_fuxi_m3_keymint.py')]},
  scope='Fixed binary local facts plus independent fixed-reference semantic model; no SMC, device, vendor execution, TA authenticity, runtime authorization or response equivalence',
  must_validate_on_hardware=['C2 root/client environment','UID122 loader object authorization','terminal/callback/piggyback handling','TA lookup/load acceptance','protocol/OS configuration and response semantics'])
 (output/'audit.json').write_text(json.dumps(report,indent=2)+'\n');return report
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--ramdisk',type=Path,required=True);p.add_argument('--reference',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 print(json.dumps(audit(a.ramdisk,a.reference,a.output),indent=2))
if __name__=='__main__':main()
