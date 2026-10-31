// SPDX-License-Identifier: BSD-2-Clause-Patent
// Narrow matched-TA COSE shape. Opaque byte fields are skipped, never exposed.
// Structural parsing ONLY: the COSE MAC is NOT verified by this diagnostic.
#ifndef FUXI_M3_ROOT_TRUST_PUBLIC_H
#define FUXI_M3_ROOT_TRUST_PUBLIC_H
#include <Uefi.h>
typedef struct { CONST UINT8 *Data;UINTN At,End; } FRT_READER;
STATIC BOOLEAN FrtHead(FRT_READER *R,UINT8 *Major,UINT64 *Value) {
  UINT8 B,A;UINTN N,I;UINT64 V=0,Min;
  if(R->At>=R->End)return FALSE;
  B=R->Data[R->At++];*Major=B>>5;A=B&31;
  if(A<24) { *Value=A;return TRUE; }
  if(A>27)return FALSE;
  N=(UINTN)1<<(A-24);if(N>R->End-R->At)return FALSE;
  for(I=0;I<N;++I)V=(V<<8)|R->Data[R->At++];
  Min=A==24?24:A==25?256:A==26?65536:0x100000000ULL;
  if(V<Min)return FALSE;
  *Value=V;return TRUE;
}
STATIC BOOLEAN FrtExpect(FRT_READER *R,UINT8 Type,UINT64 Value) {
  UINT8 M;UINT64 N;return (BOOLEAN)(FrtHead(R,&M,&N) && M==Type && N==Value);
}
STATIC BOOLEAN FrtBytes(FRT_READER *R,FRT_READER *Item) {
  UINT8 M;UINT64 N;
  if(!FrtHead(R,&M,&N) || M!=2 || N>R->End-R->At)return FALSE;
  Item->Data=R->Data;Item->At=R->At;Item->End=R->At+(UINTN)N;
  R->At=Item->End;return TRUE;
}
STATIC BOOLEAN FnuReadRootTrustBoot(CONST UINT8 *Data,UINTN Bytes,UINT32 *Boot) {
  FRT_READER R,Cose,Protected,Payload,Opaque;UINT8 M;UINT64 N;
  if(Boot==NULL)return FALSE;
  *Boot=0;
  if(Data==NULL || Bytes<1 || Bytes>256)return FALSE;
  R.Data=Data;R.At=0;R.End=Bytes;
  if(!FrtExpect(&R,5,1) || !FrtExpect(&R,0,36) || !FrtBytes(&R,&Cose) || R.At!=R.End ||
     !FrtExpect(&Cose,6,17) || !FrtExpect(&Cose,4,4) || !FrtBytes(&Cose,&Protected) ||
     Protected.End-Protected.At!=3 || !FrtExpect(&Protected,5,1) ||
     !FrtExpect(&Protected,0,1) || !FrtExpect(&Protected,0,5) || Protected.At!=Protected.End ||
     !FrtExpect(&Cose,5,0) || !FrtBytes(&Cose,&Payload) ||
     !FrtExpect(&Payload,6,40001) || !FrtExpect(&Payload,4,5) ||
     !FrtBytes(&Payload,&Opaque) || Opaque.End-Opaque.At!=32 ||
     !FrtHead(&Payload,&M,&N) || M!=7 || (N!=20 && N!=21) ||
     !FrtHead(&Payload,&M,&N) || M!=0 || N>3 ||
     !FrtBytes(&Payload,&Opaque) || Opaque.End-Opaque.At!=32 ||
     !FrtHead(&Payload,&M,&N) || M!=0 || N>0xffffffffU || Payload.At!=Payload.End)return FALSE;
  // Skip tag bytes without reading their values. No authentication assertion.
  if(!FrtBytes(&Cose,&Opaque) || Opaque.End-Opaque.At!=32 || Cose.At!=Cose.End)return FALSE;
  *Boot=(UINT32)N;return TRUE;
}
#endif
