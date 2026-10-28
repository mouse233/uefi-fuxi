#!/usr/bin/env python3
"""Offline analysis of pinned fuxi keymaster_a image; does not assert device trust."""
import argparse, hashlib, json, struct
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

PIN='2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6'
def inspect(data):
 if len(data)!=0x80000 or data[:7]!=b'\x7fELF\x02\x01\x01': raise ValueError('ELF envelope')
 phoff=struct.unpack_from('<Q',data,32)[0]; ents,num=struct.unpack_from('<HH',data,54)
 if (phoff,ents,num)!=(64,56,9): raise ValueError('program table')
 ph=[struct.unpack_from('<IIQQQQQQ',data,phoff+56*i) for i in range(num)]
 for v in ph:
  if v[2]>len(data) or v[5]>len(data)-v[2]:raise ValueError('segment bounds')
 v=ph[-1]
 if (v[0],v[1],v[2],v[5])!=(0,0x02000000,0x62000,0x1058):raise ValueError('hash segment')
 start=v[2]; fields=struct.unpack_from('<10I',data,start)
 if fields!=(0,7,24,0,224,432,0,0,104,3360):raise ValueError('MBNv7 header')
 common,qmeta,ometa,table,qsign,qcert,osign,ocert=fields[2:]
 end=start+40+common+qmeta+ometa+table+qsign+qcert+osign+ocert
 if end!=start+v[5] or end>len(data):raise ValueError('hash extent')
 table_start=start+40+common+qmeta+ometa
 if table != num*48:raise ValueError('hash table size')
 for i,entry in enumerate(ph):
  actual=data[table_start+i*48:table_start+(i+1)*48]
  expected=bytes(48) if i==num-1 else hashlib.sha384(data[entry[2]:entry[2]+entry[5]]).digest()
  if actual!=expected:raise ValueError('segment hash %d'%i)
 signed_end=table_start+table; sig=data[signed_end:signed_end+osign]
 if sig[:1]!=b'\x30' or sig[1]>=128 or sig[1]+2>len(sig):raise ValueError('signature bounds')
 sig_der=sig[:sig[1]+2];chain=data[signed_end+osign:end];certs=[];pos=0
 while pos<len(chain) and chain[pos]==0x30:
  n=chain[pos+1]; width=n&127
  if n<128: size=2+n
  else:
   if width==0 or width>4 or pos+2+width>len(chain):raise ValueError('certificate header')
   size=2+width+int.from_bytes(chain[pos+2:pos+2+width],'big')
  if size<4 or pos+size>len(chain):raise ValueError('certificate size')
  certs.append(x509.load_der_x509_certificate(chain[pos:pos+size]));pos+=size
 if len(certs)!=3 or chain[pos:]!=bytes([255])*(len(chain)-pos):raise ValueError('certificate chain or padding')
 certs[0].public_key().verify(sig_der,data[start:signed_end],ec.ECDSA(hashes.SHA384()))
 for i in range(2): certs[i+1].public_key().verify(certs[i].signature,certs[i].tbs_certificate_bytes,ec.ECDSA(certs[i].signature_hash_algorithm))
 return dict(segment_end=hex(end),signed_bytes=signed_end-start,hash_count=num,segment_hashes_verified=8,hash_segment_entry_zero=True,signature_verified=True,certificate_links_verified=2,certificate_sha256=[c.fingerprint(hashes.SHA256()).hex() for c in certs],certificate_padding=len(chain)-pos,partition_tail_zero=not any(data[end:]),authenticated_device_root=False)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--image',type=Path,required=True);ap.add_argument('--report',type=Path,required=True);a=ap.parse_args();d=a.image.read_bytes()
 if hashlib.sha256(d).hexdigest()!=PIN:raise ValueError('image SHA256 mismatch')
 result=inspect(d);mutations=[]
 for label,offset in [('segment',0x1000),('hash',0x62120),('signature',0x622e0),('cert_padding',0x63057),('header',0x62010)]:
  bad=bytearray(d);bad[offset]^=1
  try:inspect(bytes(bad))
  except Exception:mutations.append(label)
  else:raise AssertionError('mutation not rejected: '+label)
 result.update(result='passed',image_sha256=PIN,mutations_rejected=mutations,scope='offline segment hash, signer signature and intermediate certificate math; no hardware root trust, loader authorization or exact firmware file-length proof')
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
