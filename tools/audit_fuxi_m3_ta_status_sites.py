#!/usr/bin/env python3
"""Locate one AArch64 -40 immediate pattern in the fixed read-only TA image."""
import argparse,hashlib,json,struct
from pathlib import Path
PIN='2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--partition',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args();b=a.partition.read_bytes()
 if len(b)!=524288 or hashlib.sha256(b).hexdigest()!=PIN:raise ValueError('pinned keymaster_a partition mismatch')
 if b[:7]!=b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H',b,18)[0]!=183:raise ValueError('not AArch64 ELF64')
 phoff=struct.unpack_from('<Q',b,32)[0];ents,n=struct.unpack_from('<HH',b,54)
 if ents!=56 or n>32 or phoff+ents*n>len(b):raise ValueError('invalid program headers')
 segments=[]
 for i in range(n):
  kind,flags,off,va,_,size,memsize,_=struct.unpack_from('<IIQQQQQQ',b,phoff+i*ents)
  if kind!=1 or not flags&1:continue
  if size>memsize or off+size>len(b) or off%4 or va%4:raise ValueError('invalid executable segment')
  hits=[]
  for j in range(0,size-3,4):
   word=struct.unpack_from('<I',b,off+j)[0]
   if word&0xffffffe0==0x128004e0:hits.append({'virtual_address':hex(va+j),'file_offset':hex(off+j),'register':word&31})
  segments.append({'file_offset':hex(off),'virtual_address':hex(va),'file_bytes':size,'matching_words':hits})
 if len(segments)!=1 or len(segments[0]['matching_words'])!=16:raise ValueError('pinned instruction pattern changed')
 report={'result':'passed','partition_sha256':PIN,'pattern':'MOVN Wd, #39 (32-bit -40)','segments':segments,'scope':'Static instruction-word scan only. An executable segment may contain data. Other encodings exist; none of these matches is tied to the photographed response or proved reachable.'}
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
