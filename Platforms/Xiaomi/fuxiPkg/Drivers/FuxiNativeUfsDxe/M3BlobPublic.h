// SPDX-License-Identifier: BSD-2-Clause-Patent
// Unauthenticated public CBOR prefix only. Never visit the opaque tail.
// Matches tools/collect_fuxi_m3_blob_public.py; no input bytes/digests escape.
#ifndef FUXI_M3_BLOB_PUBLIC_H
#define FUXI_M3_BLOB_PUBLIC_H
#include <Uefi.h>
typedef struct { CONST UINT8 *Data; UINTN At, End; } FBP_READER;
typedef struct { UINT32 Present, Value[5]; BOOLEAN Fbe; } FBP_DOMAIN;
typedef struct {
  UINT64 Format;
  UINTN PrefixBytes;
  FBP_DOMAIN Domain[2]; // software=0, hardware=1; bits OS/OSP/boot/vendor/algorithm
} FBP_PUBLIC;

STATIC BOOLEAN FbpHead(FBP_READER *R, UINT8 *Major, UINT64 *Value) {
  UINT8 First, Ai; UINTN Width, I; UINT64 N=0, Minimum;
  if(R->At>=R->End)return FALSE;
  First=R->Data[R->At++];*Major=First>>5;Ai=First&31;
  if(Ai<24) { *Value=Ai;return TRUE; }
  if(Ai>27)return FALSE;
  Width=(UINTN)1<<(Ai-24);
  if(Width>R->End-R->At)return FALSE;
  for(I=0;I<Width;++I)N=(N<<8)|R->Data[R->At++];
  Minimum=Ai==24?24:Ai==25?256:Ai==26?65536:0x100000000ULL;
  if(N<Minimum)return FALSE;
  *Value=N;return TRUE;
}
STATIC BOOLEAN FbpUint(FBP_READER *R, UINT64 *Value) {
  UINT8 Major;return (BOOLEAN)(FbpHead(R,&Major,Value) && Major==0);
}
STATIC BOOLEAN FbpSkip(FBP_READER *R, UINTN Depth) {
  UINT8 Major;UINT64 N,I;
  if(Depth>8 || !FbpHead(R,&Major,&N))return FALSE;
  if(Major<=1 || (Major==7 && N>=20 && N<=22))return TRUE;
  if(Major==2 || Major==3) {
    if(N>R->End-R->At)return FALSE;
    R->At+=(UINTN)N;return TRUE;
  }
  if((Major!=4 && Major!=5) || N>128)return FALSE;
  if(Major==5)N*=2;
  for(I=0;I<N;++I)if(!FbpSkip(R,Depth+1))return FALSE;
  return TRUE;
}
STATIC BOOLEAN FbpAuthorization(FBP_READER *R, FBP_PUBLIC *Out) {
  STATIC CONST UINT32 Tags[5]={0x300002c1,0x300002c2,0x300002cf,0x300002ce,0x10000002};
  UINT8 Major;UINT64 N,Domain,Count,Tag,Value;UINTN D,I,J,K;UINT32 Domains=0,Seen[128];
  if(!FbpHead(R,&Major,&N) || Major!=5 || N!=2)return FALSE;
  for(D=0;D<2;++D) {
    if(!FbpUint(R,&Domain) || Domain>1 || (Domains&(1U<<Domain)))return FALSE;
    Domains|=1U<<Domain;
    if(!FbpHead(R,&Major,&Count) || Major!=5 || Count>128)return FALSE;
    for(I=0;I<(UINTN)Count;++I) {
      if(!FbpUint(R,&Tag) || Tag>0xffffffffU)return FALSE;
      for(J=0;J<I;++J)if(Seen[J]==(UINT32)Tag)return FALSE;
      Seen[I]=(UINT32)Tag;
      for(K=0;K<5;++K)if(Tag==Tags[K])break;
      if(K<5) {
        if(!FbpUint(R,&Value) || Value>0xffffffffU)return FALSE;
        Out->Domain[Domain].Value[K]=(UINT32)Value;
        Out->Domain[Domain].Present|=1U<<K;
      } else if(Tag==0x700002d2) {
        if(!FbpHead(R,&Major,&Value) || Major!=7 || Value!=21)return FALSE;
        Out->Domain[Domain].Fbe=TRUE;
      } else if(!FbpSkip(R,0))return FALSE;
    }
  }
  return (BOOLEAN)(R->At==R->End);
}
STATIC BOOLEAN FnuReadBlobPublic(CONST UINT8 *Blob,UINTN Bytes,FBP_PUBLIC *Out) {
  FBP_PUBLIC Public={0};FBP_READER R,Auth;UINT8 Major;UINT64 N,Magic,Opaque;
  // Transactional output: failures expose neither partial fields nor material.
  *Out=Public;
  if(Blob==NULL || Bytes<1 || Bytes>4096)return FALSE;
  R.Data=Blob;R.At=0;R.End=Bytes;
  if(!FbpHead(&R,&Major,&N) || Major!=4 || N<4 || N>16 ||
     !FbpUint(&R,&Magic) || Magic!=0x4b4d4b44 ||
     !FbpUint(&R,&Public.Format) || !FbpUint(&R,&Opaque) ||
     !FbpHead(&R,&Major,&N) || Major!=2 || N<1 || N>2048 || N>R.End-R.At)return FALSE;
  Auth.Data=Blob;Auth.At=R.At;Auth.End=R.At+(UINTN)N;
  if(!FbpAuthorization(&Auth,&Public))return FALSE;
  Public.PrefixBytes=Auth.End;
  *Out=Public;return TRUE;
}
#endif
