// SPDX-License-Identifier: BSD-2-Clause-Patent
// All key/ciphertext data here are SYNTHETIC. OpenSSL is a host-only oracle.
#include "M3KeyRecoveryF2fs.h"
#include <openssl/evp.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  UINT8 Sec[16384], Blob[208], Enc[276], Plain[248], ExpectedHash[64];
  UINT8 Input[264], Temporary[248];
  UINTN InputBytes, Updates, Begins, Finishes, Aborts, Reads, SeedBytes;
  int Mode, ReadFail, BadVersion, ShortSec, TinyCipher, EmptyBlob;
  EVP_CIPHER_CTX *Cipher;
  FKR_WORK *Work;
} MODEL;
static const UINT8 Key[32] = {0x73, 0x79, 0x6e, 0x74, 0x68, 0x65, 0x74, 0x69, 0x63};
static const UINT8 Seed[3] = {1,2,3};
static int Checks;
static int Zero(const void *P, UINTN N) {
  const UINT8 *B=P; for (UINTN I=0; I<N; ++I) if (B[I]) return 0; return 1;
}
static void NoResult(const FKR_WORK *W) {
  const UINT8 *P=(const UINT8 *)1; UINTN N=123;
  assert(FkrGetRecovered(W,&P,&N)==EFI_NOT_READY && P==NULL && N==0);
}
static void Init(MODEL *M, const UINT8 Hash[64]) {
  int N,T; EVP_CIPHER_CTX *C=EVP_CIPHER_CTX_new(); assert(C);
  memset(M,0,sizeof(*M)); M->ReadFail=-1;
  memcpy(M->ExpectedHash,Hash,64);
  for(UINTN I=0;I<sizeof(M->Sec);++I) M->Sec[I]=(UINT8)(I*7+0xa5);
  for(UINTN I=0;I<sizeof(M->Blob);++I) M->Blob[I]=(UINT8)(I*3+0x42);
  for(UINTN I=0;I<sizeof(M->Plain);++I) M->Plain[I]=(UINT8)(I*5+0x31);
  for(UINTN I=0;I<12;++I) M->Enc[I]=(UINT8)(I+0x70);
  assert(EVP_EncryptInit_ex(C,EVP_aes_256_gcm(),NULL,Key,M->Enc)==1);
  assert(EVP_EncryptUpdate(C,M->Enc+12,&N,M->Plain,sizeof(M->Plain))==1 && N==248);
  assert(EVP_EncryptFinal_ex(C,M->Enc+12+N,&T)==1 && T==0);
  assert(EVP_CIPHER_CTX_ctrl(C,EVP_CTRL_GCM_GET_TAG,16,M->Enc+260)==1);
  EVP_CIPHER_CTX_free(C);
}
static EFI_STATUS ReadFile(void *Context, FKR_FILE Which, void *Out, UINTN Cap, UINTN *Bytes) {
  MODEL *M=Context; const UINT8 *P=NULL; UINTN N=0; static const UINT8 Version='1';
  ++M->Reads; *Bytes=0;
  if((int)Which==M->ReadFail) { memset(Out,0xa5,Cap); return EFI_DEVICE_ERROR; }
  switch(Which) {
  case FkrVersionFile:P=&Version;N=1;break;
  case FkrSecdiscardableFile:P=M->Sec;N=sizeof(M->Sec)-(M->ShortSec?1:0);break;
  case FkrKeymasterBlobFile:P=M->Blob;N=M->EmptyBlob?0:sizeof(M->Blob);break;
  case FkrEncryptedKeyFile:P=M->Enc;N=M->TinyCipher?28:sizeof(M->Enc);break;
  }
  assert(P && N<=Cap); memcpy(Out,P,N); *Bytes=N;
  if(Which==FkrVersionFile && M->BadVersion) *(UINT8 *)Out='2';
  return EFI_SUCCESS;
}
static EFI_STATUS Begin(void *Context, const FKR_BEGIN_REQUEST *R, FKR_REPLY *Reply) {
  MODEL *M=Context; ++M->Begins; NoResult(M->Work);
  assert(R->Purpose==1 && R->BlockMode==32 && R->Padding==1 && R->MacBits==128);
  assert(R->BlobBytes==208 && !memcmp(R->Blob,M->Blob,208));
  assert(R->ApplicationIdBytes==64+M->SeedBytes && !memcmp(R->ApplicationId,M->ExpectedHash,64));
  if(M->SeedBytes) assert(!memcmp(R->ApplicationId+64,Seed,M->SeedBytes));
  assert(R->NonceBytes==12 && !memcmp(R->Nonce,M->Enc,12));
  Reply->Terminal=TRUE;
  if(M->Mode==1) { Reply->KeyMintStatus=-62;return EFI_SUCCESS; }
  if(M->Mode==2) { Reply->Terminal=FALSE;return EFI_TIMEOUT; }
  if(M->Mode==16) { Reply->KeyMintStatus=-62;Reply->Handle=0x11223344;return EFI_SUCCESS; }
  if(M->Mode==13) return EFI_SUCCESS; // malformed successful begin: no handle
  Reply->Handle=0x11223344;
  M->Cipher=EVP_CIPHER_CTX_new();assert(M->Cipher);
  assert(EVP_DecryptInit_ex(M->Cipher,EVP_aes_256_gcm(),NULL,Key,R->Nonce)==1);
  return EFI_SUCCESS;
}
static EFI_STATUS Update(void *Context, UINT64 Handle, const UINT8 *Input, UINTN Bytes,
                          UINT8 *Out, UINTN Cap, FKR_REPLY *Reply) {
  MODEL *M=Context; int N; UINTN Take=Bytes;
  ++M->Updates; NoResult(M->Work);assert(Handle==0x11223344);
  Reply->Terminal=TRUE;
  if(M->Mode==5) return EFI_SUCCESS; // zero progress
  if(M->Mode==6) { Reply->Consumed=Bytes+1;return EFI_SUCCESS; }
  if(M->Mode==7) { Reply->Consumed=Bytes;Reply->Produced=Cap+1;return EFI_SUCCESS; }
  if(M->Mode==9 || M->Mode==10) { Reply->KeyMintStatus=-1;return EFI_SUCCESS; }
  if(M->Mode==14 && Take>64) Take=64;
  if(M->Mode==15) Take=1;
  assert(M->InputBytes+Take<=sizeof(M->Input));
  memcpy(M->Input+M->InputBytes,Input,Take);M->InputBytes+=Take;Reply->Consumed=Take;
  if(M->InputBytes==sizeof(M->Input)) {
    assert(Cap>=240);
    assert(EVP_DecryptUpdate(M->Cipher,M->Temporary,&N,M->Input,248)==1 && N==248);
    assert(EVP_CIPHER_CTX_ctrl(M->Cipher,EVP_CTRL_GCM_SET_TAG,16,M->Input+248)==1);
    memcpy(Out,M->Temporary,240);Reply->Produced=240;
  }
  if(M->Mode==3) { Reply->Terminal=FALSE;return EFI_TIMEOUT; }
  return EFI_SUCCESS;
}
static EFI_STATUS Finish(void *Context, UINT64 Handle, UINT8 *Out, UINTN Cap, FKR_REPLY *Reply) {
  MODEL *M=Context; int N,Good; UINT8 Last[16];
  ++M->Finishes;NoResult(M->Work);assert(Handle==0x11223344 && Cap==8);
  Reply->Terminal=TRUE;
  if(M->Mode==4) { Reply->Terminal=FALSE;return EFI_TIMEOUT; }
  if(M->Mode==11) return EFI_SUCCESS; // no verified operation closure
  Good=EVP_DecryptFinal_ex(M->Cipher,Last,&N);
  Reply->OperationClosed=TRUE;
  if(!Good || M->Mode==8) { Reply->KeyMintStatus=-30;return EFI_SUCCESS; }
  assert(N==0);
  if(M->Mode!=12) { memcpy(Out,M->Temporary+240,8);Reply->Produced=8; }
  return EFI_SUCCESS;
}
static EFI_STATUS Abort(void *Context, UINT64 Handle, FKR_REPLY *Reply) {
  MODEL *M=Context;++M->Aborts;NoResult(M->Work);assert(Handle==0x11223344);
  Reply->Terminal=M->Mode!=9;Reply->OperationClosed=TRUE;
  if(M->Mode==10) Reply->KeyMintStatus=-1;
  return EFI_SUCCESS;
}
static void Run(MODEL *M, FKR_READ_FILE Reader, void *ReadContext, int Success, int Quarantined) {
  FKR_WORK W={0}; const UINT8 *P;UINTN Bytes;
  FKR_OPS Ops={M,Begin,Update,Finish,Abort};
  M->Work=&W;
  assert(FkrPrepare(&W,Reader,ReadContext,TRUE,Seed,M->SeedBytes)==EFI_SUCCESS);
  assert(Zero(W.Secdiscardable,sizeof(W.Secdiscardable)));
  NoResult(&W);
  EFI_STATUS Status=FkrRecoverExisting(&W,&Ops);
  if(Success) {
    assert(Status==EFI_SUCCESS && W.State==FkrRecovered && W.Handle==0);
    assert(FkrGetRecovered(&W,&P,&Bytes)==EFI_SUCCESS && Bytes==248 && !memcmp(P,M->Plain,248));
    assert(Zero(W.Blob,sizeof(W.Blob)) && Zero(W.Encrypted,sizeof(W.Encrypted)));
    assert(Zero(W.ApplicationId,sizeof(W.ApplicationId)) && M->Aborts==0);
  } else {
    assert(EFI_ERROR(Status));NoResult(&W);
    if(Quarantined) {
      FKR_WORK Before=W;
      assert(W.State==FkrQuarantined && FkrReset(&W)==EFI_ACCESS_DENIED);
      assert(!memcmp(&W,&Before,sizeof(W)));
      assert(FkrRecoverExisting(&W,&Ops)==EFI_ACCESS_DENIED);
      assert(FkrPrepare(&W,Reader,ReadContext,TRUE,NULL,0)==EFI_ACCESS_DENIED);
      assert(!memcmp(&W,&Before,sizeof(W)));
    } else {
      assert(W.State==FkrFailed && Zero(W.Candidate,sizeof(W.Candidate)));
      assert(Zero(W.Blob,sizeof(W.Blob)) && Zero(W.Encrypted,sizeof(W.Encrypted)));
      assert(Zero(W.ApplicationId,sizeof(W.ApplicationId)));
    }
  }
  if(!Quarantined) { assert(FkrReset(&W)==EFI_SUCCESS && Zero(&W,sizeof(W))); }
  // HOST-ONLY teardown: no real remote/DMA owner exists in these tests.
  EVP_CIPHER_CTX_free(M->Cipher);M->Cipher=NULL;++Checks;
}
static FILE *Image;
static int FailDisk;
static EFI_STATUS DiskRead(void *Context, UINT64 Lba, UINTN Count, void *Out) {
  (void)Context;assert(Count==1 && Lba<32768);
  if(FailDisk && Lba==4506) return EFI_DEVICE_ERROR;
  return fseek(Image,(long)(Lba*4096),SEEK_SET) || fread(Out,4096,1,Image)!=1 ? EFI_DEVICE_ERROR:EFI_SUCCESS;
}
int main(int Argc, char **Argv) {
  MODEL M; UINT8 Hashes[3][64],Digest[64],Data[16384];FILE *Vectors;
  assert(Argc==3);
  if(!strcmp(Argv[1],"--emit")) {
    memset(Hashes,0,sizeof(Hashes));Init(&M,Hashes[2]);
    FILE *F=fopen(Argv[2],"wb");assert(F && fwrite(M.Enc,276,1,F)==1);fclose(F);return 0;
  }
  Vectors=fopen(Argv[2],"rb");assert(Vectors && fread(Hashes,sizeof(Hashes),1,Vectors)==1);fclose(Vectors);
  for(UINTN Mode=0;Mode<3;++Mode) {
    for(UINTN I=0;I<sizeof(Data);++I) Data[I]=Mode==0?0:Mode==1?255:(UINT8)(I*7+0xa5);
    assert(FkrHashSecdiscardable(Data,sizeof(Data),Digest)==EFI_SUCCESS && !memcmp(Digest,Hashes[Mode],64));++Checks;
  }
  assert(FkrHashSecdiscardable(Data,sizeof(Data)-1,Digest)==EFI_INVALID_PARAMETER);
  for(int Mode=0;Mode<=16;++Mode) {
    Init(&M,Hashes[2]);M.Mode=Mode;
    int Q=Mode==2 || Mode==3 || Mode==4 || Mode==9 || Mode==10 || Mode==11 || Mode==13 || Mode==16;
    Run(&M,ReadFile,&M,Mode==0 || Mode==14,Q);
    if(Mode==1) assert(M.Begins==1 && M.Updates==0 && M.Aborts==0);
    if(Mode==3 || Mode==4) assert(M.Aborts==0);
    if(Mode==15) assert(M.Updates==FKR_UPDATE_LIMIT && M.Aborts==1 && M.Finishes==0);
  }
  for(int Which=0;Which<3;++Which) {
    Init(&M,Hashes[2]);M.Enc[Which==0?275:Which==1?12:0]^=1;
    Run(&M,ReadFile,&M,0,0); // actual GCM tag/ciphertext/nonce authentication failures
  }
  Init(&M,Hashes[2]);M.SeedBytes=3;Run(&M,ReadFile,&M,1,0);
  for(int I=0;I<9;++I) {
    FKR_WORK W={0};Init(&M,Hashes[2]);
    if(I<4) M.ReadFail=I;
    if(I==4) M.BadVersion=1;
    if(I==5) M.ShortSec=1;
    if(I==6) M.TinyCipher=1;
    if(I==7) M.EmptyBlob=1;
    assert(EFI_ERROR(FkrPrepare(&W,ReadFile,&M,I!=8,NULL,0)) && W.State==FkrFailed);
    assert(Zero(W.Candidate,sizeof(W.Candidate)) && Zero(W.ApplicationId,sizeof(W.ApplicationId)));
    assert(Zero(W.Secdiscardable,sizeof(W.Secdiscardable)) && Zero(W.Blob,sizeof(W.Blob)));
    assert(Zero(W.Encrypted,sizeof(W.Encrypted)) && M.Begins==0);
    if(I==8) assert(M.Reads==0);
    ++Checks;
  }
  for(int I=0;I<4;++I) {
    FKR_WORK Invalid={0};Init(&M,Hashes[2]);M.Work=&Invalid;
    FKR_OPS Ops={&M,Begin,Update,Finish,Abort};
    assert(FkrPrepare(&Invalid,ReadFile,&M,TRUE,NULL,0)==EFI_SUCCESS);
    if(I==0) Invalid.EncryptedBytes=0;
    if(I==1) Invalid.EncryptedBytes=FKR_ENCRYPTED_LIMIT+1;
    if(I==2) Invalid.Request.Nonce=NULL;
    if(I==3) Invalid.Request.Padding=0;
    assert(FkrRecoverExisting(&Invalid,&Ops)==EFI_INVALID_PARAMETER && M.Begins==0);
    NoResult(&Invalid);assert(Zero(Invalid.Blob,sizeof(Invalid.Blob)));++Checks;
  }
  F2R_VOLUME Volume={0};UINT8 FsWork[F2R_WORK_BYTES],Small[16];UINTN Got;
  FDP_DISK Disk={NULL,DiskRead,4096,32767};FDP_PARTITION Part={0,32767,TRUE};
  FKR_F2FS_CONTEXT Fs={&Volume,FsWork,sizeof(FsWork)};
  Image=fopen(Argv[1],"rb");assert(Image);
  assert(F2rPrepare(&Disk,&Part,&Volume,FsWork,sizeof(FsWork))==EFI_SUCCESS);
  Init(&M,Hashes[2]);Run(&M,FkrReadF2fsFile,&Fs,1,0); // real reader -> preparation -> crypto core
  memset(Small,0xa5,sizeof(Small));
  assert(FkrReadF2fsFile(&Fs,FkrSecdiscardableFile,Small,sizeof(Small),&Got)==EFI_BAD_BUFFER_SIZE);
  assert(Got==0 && Zero(Small,sizeof(Small)) && Zero(FsWork,sizeof(FsWork)));++Checks;
  FailDisk=1;
  FKR_WORK W={0};assert(FkrPrepare(&W,FkrReadF2fsFile,&Fs,TRUE,NULL,0)==EFI_DEVICE_ERROR);
  assert(W.State==FkrFailed && Zero(W.Secdiscardable,sizeof(W.Secdiscardable)));++Checks;
  fclose(Image);
  printf("PASS recovery cases=%d; synthetic AES-GCM only, no device/KeyMint\n",Checks);
  return 0;
}
