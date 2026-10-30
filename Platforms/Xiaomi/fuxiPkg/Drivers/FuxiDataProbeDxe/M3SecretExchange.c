// SPDX-License-Identifier: BSD-2-Clause-Patent
// Fixed fuxi SMCI object ABI. No request/response/secret/handle logging.
#include "M3SecretExchange.h"
#ifndef FUXI_M3_SECRET_EXCHANGE
#define FUXI_M3_SECRET_EXCHANGE 0
#endif
#if FUXI_M3_SECRET_EXCHANGE
#include <Library/ArmSmcLib.h>
#include <Library/CacheMaintenanceLib.h>

STATIC VOID Erase(VOID *Pointer, UINTN Bytes) { volatile UINT8 *P=Pointer; while(Bytes--) *P++=0; }
STATIC UINT32 U32(CONST UINT8 *P) { return P[0]|((UINT32)P[1]<<8)|((UINT32)P[2]<<16)|((UINT32)P[3]<<24); }
STATIC BOOLEAN Zero(CONST UINT8 *P,UINTN N) { while(N--)if(*P++)return FALSE;return TRUE; }
STATIC EFI_STATUS Quarantine(FSE_CONTEXT *C) { C->State=FseQuarantined;return EFI_NOT_READY; }
STATIC BOOLEAN ValidLease(CONST FSE_CONTEXT *C) {
  return C->Page!=NULL && C->Physical==(UINT64)(UINTN)C->Page && C->Physical>=4096 &&
         (C->Physical&4095)==0 && C->RegisteredBytes>=FKM_SHARED_BYTES &&
         C->RegisteredBytes<=0x100000 && (C->RegisteredBytes&4095)==0 &&
         C->Physical<=0x100000000ULL-C->RegisteredBytes && C->Bridge!=0 &&
         C->App>1 && (C->App&0x80000000U)==0;
}
EFI_STATUS FseInitialize(FSE_CONTEXT *C,UINT8 *Page,UINT64 Physical,UINTN Bytes,
                         UINT64 Bridge,UINT32 App,BOOLEAN LeaseVerified) {
  FSE_CONTEXT Candidate;
  if(C==NULL)return EFI_INVALID_PARAMETER;
  if(C->State!=FseEmpty)return EFI_ACCESS_DENIED;
  if(!LeaseVerified)return EFI_NOT_READY;
  Erase(&Candidate,sizeof(Candidate));
  Candidate.Page=Page;Candidate.Physical=Physical;Candidate.RegisteredBytes=Bytes;
  Candidate.Bridge=Bridge;Candidate.App=App;
  if(!ValidLease(&Candidate))return EFI_INVALID_PARAMETER;
  Candidate.State=FseBound;*C=Candidate;return EFI_SUCCESS;
}
EFI_STATUS FseExchange(VOID *Context,UINT8 *Shared,UINTN InBytes,UINTN OutBytes,FKM_RETURN *Result) {
  FSE_CONTEXT *C=Context;ARM_SMC_ARGS Args;UINTN Resume=0;UINT32 Command;
  if(Result==NULL)return EFI_INVALID_PARAMETER;
  Erase(Result,sizeof(*Result));
  if(C==NULL)return EFI_INVALID_PARAMETER;
  if(C->State!=FseBound)return EFI_ACCESS_DENIED;
  if(!ValidLease(C) || Shared!=C->Page || InBytes!=FKM_MESSAGE_BYTES || OutBytes!=4096 ||
     C->Calls>=FSE_CALL_LIMIT)return Quarantine(C);
  if(U32(Shared)!=C->App || U32(Shared+4)!=0 || U32(Shared+8)!=0x424 ||
     U32(Shared+12)!=96 || U32(Shared+16)<4 || U32(Shared+16)>FKM_REQUEST_LIMIT)
    return Quarantine(C);
  Command=U32(Shared+96);
  if(Command!=0x310f && Command!=0x3111 && Command!=0x3112 && Command!=0x2113
#if FUXI_M3_CHARACTERISTICS_PROBE
     && Command!=0x2109
#endif
    ) return Quarantine(C);
  C->State=FseBusy;++C->Calls;
  // Submit exactly the two fixed extents, both wholly inside the registered
  // lease. No DMA window/physical address derived from a TA response.
  WriteBackInvalidateDataCacheRange(Shared,FKM_SHARED_BYTES);
  Erase(&Args,sizeof(Args));
  Args.Arg0=0x72000602ULL;Args.Arg1=0x224;
  Args.Arg2=(UINTN)C->Physical;Args.Arg3=FKM_MESSAGE_BYTES;
  Args.Arg4=(UINTN)(C->Physical+FKM_MESSAGE_BYTES);Args.Arg5=4096;
  ArmCallSmc(&Args);
  while(Args.Arg0==1 && Resume<FSE_RESUME_LIMIT) {
    UINT64 Token=(UINT64)Args.Arg6;
    Erase(&Args,sizeof(Args));
    Args.Arg0=1;Args.Arg1=0x224;Args.Arg2=(UINTN)C->Physical;
    Args.Arg3=FKM_MESSAGE_BYTES;Args.Arg4=(UINTN)(C->Physical+FKM_MESSAGE_BYTES);
    Args.Arg5=4096;Args.Arg6=(UINTN)Token;
    ++Resume;++C->Resumes;ArmCallSmc(&Args);
  }
  Result->A0=(UINT64)Args.Arg0;Result->A1=(UINT64)Args.Arg1;
  Result->A2=(UINT64)Args.Arg2;Result->A3=(UINT64)Args.Arg3;
  if(C->State!=FseBusy || Args.Arg0 || Args.Arg1 || Args.Arg2 || Args.Arg3)
    return Quarantine(C);
  InvalidateDataCacheRange(Shared,FKM_SHARED_BYTES);
  C->State=FseBound;
  return EFI_SUCCESS; // backend still checks piggyback/descriptors/TA payload
}
EFI_STATUS FsePermitCleanup(FSE_CONTEXT *C,FKM_CONTEXT *B) {
  if(C==NULL || B==NULL)return EFI_INVALID_PARAMETER;
  if(C->State!=FseBound || !ValidLease(C) || !B->Ready || B->Quarantined ||
     B->Handle || B->App!=C->App || B->Shared!=C->Page ||
     B->SharedBytes!=FKM_SHARED_BYTES || B->RequestBytes ||
     !Zero(B->Request,sizeof(B->Request)) || !Zero(C->Page,FKM_SHARED_BYTES))
    return EFI_ACCESS_DENIED;
  // Fkm's volatile CPU wipe must reach physical memory before bridge deletion.
  WriteBackInvalidateDataCacheRange(C->Page,FKM_SHARED_BYTES);
  C->State=FseClosed;B->Ready=FALSE;
  return EFI_SUCCESS;
}
#else
EFI_STATUS FseInitialize(FSE_CONTEXT *C,UINT8 *P,UINT64 Raw,UINTN N,UINT64 B,UINT32 A,BOOLEAN V) {
  (VOID)C;(VOID)P;(VOID)Raw;(VOID)N;(VOID)B;(VOID)A;(VOID)V;return EFI_UNSUPPORTED;
}
EFI_STATUS FseExchange(VOID *C,UINT8 *P,UINTN I,UINTN O,FKM_RETURN *R) {
  (VOID)C;(VOID)P;(VOID)I;(VOID)O;
  if(R!=NULL) { R->A0=R->A1=R->A2=R->A3=0; }
  return EFI_UNSUPPORTED;
}
EFI_STATUS FsePermitCleanup(FSE_CONTEXT *C,FKM_CONTEXT *B) { (VOID)C;(VOID)B;return EFI_UNSUPPORTED; }
#endif
