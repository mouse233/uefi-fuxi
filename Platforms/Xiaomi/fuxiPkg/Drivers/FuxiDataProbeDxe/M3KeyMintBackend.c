// SPDX-License-Identifier: BSD-2-Clause-Patent
// Independent implementation from pinned vendor interface facts. No vendor code.
#include "M3KeyMintBackend.h"
STATIC VOID Wipe(VOID *Ptr, UINTN N) { volatile UINT8 *P=Ptr; while (N--) *P++=0; }
STATIC VOID Copy(VOID *Dst, CONST VOID *Src, UINTN N) {
  UINT8 *D=Dst; CONST UINT8 *S=Src; while (N--) *D++=*S++;
}
STATIC UINT32 Get32(CONST UINT8 *P) {
  return P[0]|((UINT32)P[1]<<8)|((UINT32)P[2]<<16)|((UINT32)P[3]<<24);
}
STATIC VOID Put32(UINT8 *P, UINT32 V) { UINTN I; for (I=0;I<4;++I) P[I]=(UINT8)(V>>(8*I)); }
STATIC UINTN Align8(UINTN N) { return (N+7U)&~(UINTN)7U; }
STATIC BOOLEAN Zero(CONST UINT8 *P, UINTN N) { while (N--) if (*P++) return FALSE; return TRUE; }
typedef struct { UINT8 *P; UINTN N, Cap; BOOLEAN Bad; } WRITER;
STATIC VOID Byte(WRITER *W, UINT8 V) {
  if (W->N==W->Cap) { W->Bad=TRUE; return; }
  W->P[W->N++]=V;
}
STATIC VOID Head(WRITER *W, UINT8 Type, UINT64 V) {
  UINTN N=0,I;
  if (V<24) { Byte(W,(UINT8)((Type<<5)|V)); return; }
  N=V<=0xff ? 1 : V<=0xffff ? 2 : V<=0xffffffffULL ? 4 : 8;
  Byte(W,(UINT8)((Type<<5)|(N==1 ? 24 : N==2 ? 25 : N==4 ? 26 : 27)));
  for (I=N;I>0;--I) Byte(W,(UINT8)(V>>(8*(I-1))));
}
STATIC VOID Pair(WRITER *W, UINT32 Tag, UINT64 V) { Head(W,0,Tag); Head(W,0,V); }
STATIC VOID BytesPair(WRITER *W, UINT32 Tag, CONST UINT8 *P, UINTN N) {
  UINTN I;
  // addParams uses ldrsw for the 32-bit tag before QCBOR's signed label API.
  if (Tag&0x80000000U) Head(W,1,(UINT32)~Tag); else Head(W,0,Tag);
  Head(W,2,N); for (I=0;I<N;++I) Byte(W,P[I]);
}
EFI_STATUS FkmEncode(FKR_STAGE Stage, CONST FKR_BEGIN_REQUEST *B, UINT64 Handle,
                     CONST UINT8 *Input, UINTN InputBytes, UINT8 *Out,
                     UINTN Capacity, UINTN *Bytes) {
  WRITER W;
  if (Bytes==NULL) return EFI_INVALID_PARAMETER;
  *Bytes=0;
  if (Out==NULL || Capacity==0 || Capacity>FKM_REQUEST_LIMIT) return EFI_INVALID_PARAMETER;
  W.P=Out; W.N=0; W.Cap=Capacity; W.Bad=FALSE;
  if (Stage==FkrBegin) {
    if (B==NULL || Handle || InputBytes || B->Purpose!=1 || B->BlockMode!=32 ||
        B->Padding!=1 || B->MacBits!=128 || B->Blob==NULL || B->BlobBytes==0 ||
        B->BlobBytes>FKR_BLOB_LIMIT || B->ApplicationId==NULL ||
        B->ApplicationIdBytes<64 || B->ApplicationIdBytes>64+FKR_SEED_LIMIT ||
        B->Nonce==NULL || B->NonceBytes!=12) return EFI_INVALID_PARAMETER;
    Head(&W,5,8); Pair(&W,22,6);
    Pair(&W,0x20000004,32); Pair(&W,0x20000006,1); Pair(&W,0x300003eb,128);
    BytesPair(&W,0x90000259,B->ApplicationId,B->ApplicationIdBytes);
    BytesPair(&W,0x900003e9,B->Nonce,12);
    Pair(&W,0x20000001,1); BytesPair(&W,23,B->Blob,B->BlobBytes);
  } else {
    if (!Handle || B || (Stage!=FkrUpdate && Stage!=FkrFinish && Stage!=FkrAbort) ||
        (Stage==FkrUpdate && (Input==NULL || InputBytes==0 || InputBytes>FKR_ENCRYPTED_LIMIT)) ||
        (Stage!=FkrUpdate && InputBytes)) return EFI_INVALID_PARAMETER;
    Head(&W,5,Stage==FkrUpdate ? 2 : 1); Pair(&W,34,Handle);
    if (Stage==FkrUpdate) BytesPair(&W,35,Input,InputBytes);
  }
  if (W.Bad) { Wipe(Out,Capacity); return EFI_BUFFER_TOO_SMALL; }
  *Bytes=W.N; return EFI_SUCCESS;
}

typedef struct { CONST UINT8 *P; UINTN N, At; } READER;
STATIC BOOLEAN ReadHead(READER *R, UINT8 Type, UINT64 *V) {
  UINT8 B, Ai; UINTN I,N;
  if (R->At==R->N) return FALSE;
  B=R->P[R->At++]; Ai=B&31;
  if ((B>>5)!=Type || Ai>27) return FALSE;
  if (Ai<24) { *V=Ai; return TRUE; }
  N=(UINTN)1<<(Ai-24);
  if (N>R->N-R->At) return FALSE;
  *V=0; for (I=0;I<N;++I) *V=(*V<<8)|R->P[R->At++];
  // Deliberately narrow: definite, shortest form, no tags/indefinite containers.
  if (*V<(N==1 ? 24ULL : N==2 ? 256ULL : N==4 ? 65536ULL : 0x100000000ULL)) return FALSE;
  return TRUE;
}
EFI_STATUS FkmDecode(FKR_STAGE Stage, CONST UINT8 *P, UINTN N, FKR_REPLY *Reply,
                     CONST UINT8 **Output, UINTN *OutputBytes) {
  READER R; FKR_REPLY Local; CONST UINT8 *Data=NULL;
  UINT64 Count,Key,V; UINTN I,DataBytes=0; UINT32 Seen=0,Bit;
  if (Reply==NULL || Output==NULL || OutputBytes==NULL) return EFI_INVALID_PARAMETER;
  Wipe(Reply,sizeof(*Reply)); *Output=NULL; *OutputBytes=0; Wipe(&Local,sizeof(Local));
  if (P==NULL || N==0 || N>FKR_ENCRYPTED_LIMIT+64 ||
      (Stage!=FkrBegin && Stage!=FkrUpdate && Stage!=FkrFinish)) return EFI_INVALID_PARAMETER;
  R.P=P; R.N=N; R.At=0;
  if (!ReadHead(&R,5,&Count) || Count>3) return EFI_COMPROMISED_DATA;
  for (I=0;I<(UINTN)Count;++I) {
    if (!ReadHead(&R,0,&Key)) return EFI_COMPROMISED_DATA;
    Bit=Key==22 ? 1 : Key==34 ? 2 : Key==36 ? 4 : Key==37 ? 8 : 0;
    if (!Bit || (Seen&Bit)) return EFI_COMPROMISED_DATA;
    Seen|=Bit;
    if (Key==36) {
      if (!ReadHead(&R,2,&V) || V>FKR_ENCRYPTED_LIMIT || V>R.N-R.At) return EFI_COMPROMISED_DATA;
      Data=R.P+R.At; DataBytes=(UINTN)V; R.At+=DataBytes;
    } else {
      if (!ReadHead(&R,0,&V)) return EFI_COMPROMISED_DATA;
      if (Key==22 && V!=0) return EFI_UNSUPPORTED; // no output authorization parameters
      if (Key==34) Local.Handle=V;
      if (Key==37) { if (V>FKR_ENCRYPTED_LIMIT) return EFI_COMPROMISED_DATA; Local.Consumed=(UINTN)V; }
    }
  }
  if (R.At!=R.N || (Stage==FkrBegin && (Seen!=3 || Local.Handle==0)) ||
      (Stage==FkrUpdate && Seen!=13) || (Stage==FkrFinish && Seen!=5)) return EFI_COMPROMISED_DATA;
  Local.Produced=DataBytes; *Reply=Local; *Output=Data; *OutputBytes=DataBytes;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS Quarantine(FKM_CONTEXT *C, FKR_REPLY *Reply) {
  C->Quarantined=TRUE; Reply->Terminal=FALSE; return EFI_NOT_READY;
}
STATIC EFI_STATUS Call(FKM_CONTEXT *C, FKR_STAGE Stage, CONST FKR_BEGIN_REQUEST *B,
                        UINT64 Handle, CONST UINT8 *Input, UINTN InputBytes,
                        UINT8 *Output, UINTN Capacity, FKR_REPLY *Reply) {
  EFI_STATUS Status; FKM_RETURN Ret; FKR_REPLY Parsed; CONST UINT8 *Data;
  UINTN Encoded, SendBytes, ResponseCap, Bi1, Bi3, Bo0, Bo1, I, OutReq, OutResp, Payload;
  UINT32 Command; UINT8 Header[96]; UINT8 *P; UINT32 TaStatus;
  if (Reply==NULL) return EFI_INVALID_PARAMETER;
  Wipe(Reply,sizeof(*Reply));
  if (C==NULL || !C->Ready || C->Quarantined) return EFI_NOT_READY;
  if ((Stage==FkrBegin && C->Handle) || (Stage!=FkrBegin && (!Handle || C->Handle!=Handle)))
    return Quarantine(C,Reply);
  if (Capacity && Output==NULL) return EFI_INVALID_PARAMETER;
  // Stage-specific callbacks cannot emit configure/generate/upgrade commands.
  Command=Stage==FkrBegin ? 0x310f : Stage==FkrUpdate ? 0x3111 : Stage==FkrFinish ? 0x3112 : 0x2113;
  Status=FkmEncode(Stage,B,Handle,Input,InputBytes,C->Request+4,sizeof(C->Request)-4,&Encoded);
  if (EFI_ERROR(Status)) { Reply->Terminal=TRUE; return Status; }
  Put32(C->Request,Command); C->RequestBytes=SendBytes=Encoded+4;
  ResponseCap=0xa000-((SendBytes+3)&~(UINTN)3);
  Bi1=Align8(96+SendBytes); Bi3=Align8(Bi1+ResponseCap);
  Bo0=Align8(Bi3+4); Bo1=Align8(Bo0+SendBytes);
  if (Bo1+ResponseCap>FKM_MESSAGE_BYTES) { Reply->Terminal=TRUE; return EFI_BAD_BUFFER_SIZE; }
  P=C->Shared; Wipe(P,FKM_SHARED_BYTES); Wipe(&Ret,sizeof(Ret));
  Put32(P,C->App); Put32(P+4,0); Put32(P+8,0x424);
  Put32(P+12,96); Put32(P+16,(UINT32)SendBytes);
  Put32(P+20,(UINT32)Bi1); Put32(P+24,(UINT32)ResponseCap);
  Put32(P+28,(UINT32)Bi3); Put32(P+32,0);
  Put32(P+36,(UINT32)Bi3); Put32(P+40,4);
  Put32(P+44,(UINT32)Bo0); Put32(P+48,(UINT32)SendBytes);
  Put32(P+52,(UINT32)Bo1); Put32(P+56,(UINT32)ResponseCap);
  Put32(P+Bi3,1); Copy(P+96,C->Request,SendBytes); Copy(Header,P,sizeof(Header));
  Status=C->Exchange(C->ExchangeContext,P,FKM_MESSAGE_BYTES,4096,&Ret);
  if (EFI_ERROR(Status) || Ret.A0 || Ret.A1 || Ret.A2 || Ret.A3) return Quarantine(C,Reply);
  if (!((Get32(P+FKM_MESSAGE_BYTES)==0 && Get32(P+FKM_MESSAGE_BYTES+4)==0) ||
        (Get32(P+FKM_MESSAGE_BYTES)==0x10002 &&
         (Get32(P+FKM_MESSAGE_BYTES+4)==0xfffd || Get32(P+FKM_MESSAGE_BYTES+4)==0xffff))) ||
      !Zero(P+FKM_MESSAGE_BYTES+8,4088)) return Quarantine(C,Reply);
  OutReq=Get32(P+48); OutResp=Get32(P+56);
  if (OutReq>SendBytes || OutResp<8 || OutResp>ResponseCap) return Quarantine(C,Reply);
  for (I=0;I<FKM_MESSAGE_BYTES;++I) {
    UINT8 Expected=0;
    if ((I>=48 && I<52) || (I>=56 && I<60) ||
        (I>=Bo0 && I<Bo0+OutReq) || (I>=Bo1 && I<Bo1+OutResp)) continue;
    if (I<96) Expected=Header[I];
    else if (I>=96 && I<96+SendBytes) Expected=C->Request[I-96];
    else if (I==Bi3) Expected=1;
    if (P[I]!=Expected) return Quarantine(C,Reply);
  }
  TaStatus=Get32(P+Bo1); Payload=Get32(P+Bo1+4);
  if (Payload>OutResp-8 || !Zero(P+Bo1+8+Payload,OutResp-8-Payload)) return Quarantine(C,Reply);
  if (TaStatus) {
    if (!(TaStatus&0x80000000U) || Payload) return Quarantine(C,Reply);
    if (Stage==FkrAbort) return Quarantine(C,Reply); // no verified closure
    Reply->Terminal=TRUE; Reply->KeyMintStatus=(INT32)TaStatus;
  } else if (Stage==FkrAbort) {
    if (Payload) return Quarantine(C,Reply);
    Reply->Terminal=TRUE; Reply->OperationClosed=TRUE; C->Handle=0;
  } else {
    Status=FkmDecode(Stage,P+Bo1+8,Payload,&Parsed,&Data,&Encoded);
    if (EFI_ERROR(Status) || Encoded>Capacity || (Stage==FkrUpdate && Parsed.Consumed>InputBytes))
      return Quarantine(C,Reply);
    *Reply=Parsed; Reply->Terminal=TRUE;
    if (Stage==FkrBegin) C->Handle=Reply->Handle;
    if (Stage==FkrFinish) { Reply->OperationClosed=TRUE; C->Handle=0; }
    if (Encoded) Copy(Output,Data,Encoded);
  }
  // Only the command completed. The app/bridge remain owned by the caller;
  // an active operation is retained across calls, freed only by finish/abort.
  Wipe(P,FKM_SHARED_BYTES); Wipe(C->Request,sizeof(C->Request)); C->RequestBytes=0;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS Begin(VOID *C, CONST FKR_BEGIN_REQUEST *B, FKR_REPLY *R) {
  return Call(C,FkrBegin,B,0,NULL,0,NULL,0,R);
}
STATIC EFI_STATUS Update(VOID *C, UINT64 H, CONST UINT8 *I, UINTN N, UINT8 *O, UINTN Cap, FKR_REPLY *R) {
  return Call(C,FkrUpdate,NULL,H,I,N,O,Cap,R);
}
STATIC EFI_STATUS Finish(VOID *C, UINT64 H, UINT8 *O, UINTN Cap, FKR_REPLY *R) {
  return Call(C,FkrFinish,NULL,H,NULL,0,O,Cap,R);
}
STATIC EFI_STATUS Abort(VOID *C, UINT64 H, FKR_REPLY *R) {
  return Call(C,FkrAbort,NULL,H,NULL,0,NULL,0,R);
}
EFI_STATUS FkmInitialize(FKM_CONTEXT *C, UINT32 App, UINT8 *Shared, UINTN SharedBytes,
                         FKM_EXCHANGE Exchange, VOID *ExchangeContext,
                         BOOLEAN SessionVerified, FKR_OPS *Ops) {
  if (C==NULL || Ops==NULL) return EFI_INVALID_PARAMETER;
  if (C->Ready || C->Quarantined || C->Handle) return EFI_ACCESS_DENIED;
  Wipe(Ops,sizeof(*Ops));
  if (!SessionVerified) return EFI_NOT_READY;
  if (App<=1 || (App&0x80000000U) || Shared==NULL || ((UINTN)Shared&4095) ||
      SharedBytes!=FKM_SHARED_BYTES || Exchange==NULL) return EFI_INVALID_PARAMETER;
  C->App=App; C->Shared=Shared; C->SharedBytes=SharedBytes; C->Exchange=Exchange;
  C->ExchangeContext=ExchangeContext; C->Ready=TRUE;
  Ops->Context=C; Ops->Begin=Begin; Ops->Update=Update; Ops->Finish=Finish; Ops->Abort=Abort;
  return EFI_SUCCESS;
}
