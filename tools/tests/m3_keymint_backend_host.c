// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "M3KeyMintBackend.h"
static unsigned Cases;
static const UINT64 Handle=0x1020304050607080ULL;
static UINT8 Blob[FKR_BLOB_LIMIT], AppId[64], Nonce[12], Data[32];
static FKR_BEGIN_REQUEST request(UINTN size) {
  FKR_BEGIN_REQUEST b={1,32,1,128,Blob,size,AppId,64,Nonce,12}; return b;
}
static unsigned get32(const UINT8 *p) { return p[0]|((unsigned)p[1]<<8)|((unsigned)p[2]<<16)|((unsigned)p[3]<<24); }
static void put32(UINT8 *p,unsigned n) { for (unsigned i=0;i<4;i++) p[i]=(UINT8)(n>>(i*8)); }
static int zero(const void *p,size_t n) { const UINT8 *b=p; while(n--) if(*b++)return 0;return 1; }
static UINTN response(unsigned cmd, UINT8 *p, int mode) {
  static const UINT8 begin[]={0xa2,0x16,0,0x18,0x22,0x1b,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80};
  static const UINT8 finish[]={0xa2,0x16,0,0x18,0x24,0x40};
  if(cmd==0x310f) { memcpy(p,begin,sizeof(begin));if(mode==14)p[13]=0;return sizeof(begin); }
  if(cmd==0x3111) {
    UINT8 head[]={0xa3,0x16,0,0x18,0x24,0x58,0x20};
    memcpy(p,head,sizeof(head));memcpy(p+sizeof(head),Data,32);
    p[39]=0x18;p[40]=0x25;p[41]=0x18;p[42]=0x30;
    if(mode==19) { p[41]=0;p[42]=0;return 42; }
    return 43;
  }
  if(cmd==0x3112) { memcpy(p,finish,sizeof(finish));return sizeof(finish); }
  assert(cmd==0x2113);return 0;
}
typedef struct { int mode; unsigned calls,abort; UINT8 *snapshot; } MOCK;
static EFI_STATUS exchange(void *ctx,UINT8 *p,UINTN in,UINTN out,FKM_RETURN *r) {
  MOCK *m=ctx;unsigned cmd=get32(p+96),bo=get32(p+52),cap=get32(p+56);UINTN n;
  assert(in==FKM_MESSAGE_BYTES&&out==4096&&get32(p)==4&&get32(p+8)==0x424);
  assert(cmd==0x310f||cmd==0x3111||cmd==0x3112||cmd==0x2113);
  if(m->mode==100)assert(fwrite(p,1,in,stdout)==in); // synthetic independent layout oracle
  m->calls++;if(cmd==0x2113)m->abort++;
  if(m->mode>=1&&m->mode<=5) {
    if(m->mode==1)r->A0=1;if(m->mode==2)r->A1=1;if(m->mode==3)r->A2=3;if(m->mode==4)r->A3=1;
    return m->mode==5?EFI_DEVICE_ERROR:EFI_SUCCESS;
  }
  n=response(cmd,p+bo+8,m->mode);
  put32(p+bo+4,(unsigned)n);
  if(m->mode==6)p[12]++;
  if(m->mode==7)p[96+10]^=1;
  if(m->mode==8)p[95]=1;
  if(m->mode==9)put32(p+56,cap+1);
  if(m->mode==10)put32(p+48,get32(p+16)+1);
  if(m->mode==11)p[in+8]=1;
  if(m->mode==12)p[in]=1;
  if(m->mode==13)p[bo+8]=0xa1;
  if(m->mode==14&&cmd==0x310f)memset(p+bo+8+6,0,8);
  if((m->mode>=15&&m->mode<=18&&m->mode!=16&&cmd==0x3111)||(m->mode==16&&cmd==0x3112)) {
    // Known TA failure, no output: abort is the only permitted cleanup call.
    memset(p+bo,0,cap);put32(p+bo,0xffffffdfU);
  }
  if(m->mode==17&&cmd==0x2113)put32(p+bo,0xffffffdfU);
  if(m->mode==18&&cmd==0x2113)r->A0=1;
  if(m->mode==20&&cmd==0x3111) { p[bo+8+42]=0x31; } // consume beyond request
  if(m->mode==21)put32(p+bo+4,cap); // envelope length beyond received buffer
  if(m->mode==22)put32(p+56,7); // truncated envelope
  if(m->mode==23)p[bo+8+n]=1; // nonzero envelope tail
  if(m->mode==24)p[get32(p+20)]=1; // modified BI response template
  if(m->mode==25)put32(p+bo,0xffffffc2U); // negative status with nonempty payload
  if(m->mode==26){memset(p+bo,0,cap);put32(p+bo,1);} // positive status
  return EFI_SUCCESS;
}
static EFI_STATUS read_file(void *unused,FKR_FILE f,void *out,UINTN cap,UINTN *n) {
  (void)unused;
  *n=f==FkrVersionFile?1:f==FkrSecdiscardableFile?16384:f==FkrKeymasterBlobFile?208:60;
  assert(*n<=cap);
  if(f==FkrVersionFile) *(UINT8*)out='1';
  else for(UINTN i=0;i<*n;i++) ((UINT8*)out)[i]=(UINT8)(i%251);
  return EFI_SUCCESS;
}
static void backend_cases(void) {
  for(int mode=0;mode<=26;mode++) {
    FKM_CONTEXT *c=calloc(1,sizeof(*c));FKR_WORK *w=calloc(1,sizeof(*w));FKR_OPS ops;
    UINT8 *shared=aligned_alloc(4096,FKM_SHARED_BYTES);MOCK m={mode,0,0,NULL};
    const UINT8 *plain=(void*)1;UINTN bytes=1;EFI_STATUS s;
    assert(c&&w&&shared);memset(shared,0,FKM_SHARED_BYTES);
    assert(FkmInitialize(c,4,shared,FKM_SHARED_BYTES,exchange,&m,FALSE,&ops)==EFI_NOT_READY);
    assert(m.calls==0&&!c->Ready);
    assert(FkmInitialize(c,4,shared,FKM_SHARED_BYTES,exchange,&m,TRUE,&ops)==EFI_SUCCESS);
    assert(FkrPrepare(w,read_file,NULL,TRUE,NULL,0)==EFI_SUCCESS);
    assert(FkrGetRecovered(w,&plain,&bytes)==EFI_NOT_READY&&plain==NULL&&bytes==0);
    s=FkrRecoverExisting(w,&ops);
    if(mode==0) {
      assert(s==EFI_SUCCESS&&w->State==FkrRecovered&&m.calls==3&&!m.abort&&!c->Handle);
      assert(FkrGetRecovered(w,&plain,&bytes)==EFI_SUCCESS&&bytes==32&&!memcmp(plain,Data,32));
      assert(zero(shared,FKM_SHARED_BYTES)&&zero(c->Request,sizeof(c->Request)));
    } else if(mode==15||mode==16||mode==19) {
      if (!(EFI_ERROR(s)&&w->State==FkrFailed&&m.abort==1&&!c->Handle)) fprintf(stderr,"failed cleanup mode=%d state=%u backend-quarantine=%u calls=%u abort=%u\n",mode,w->State,c->Quarantined,m.calls,m.abort);
      assert(EFI_ERROR(s)&&w->State==FkrFailed&&m.abort==1&&!c->Handle);
      assert(zero(shared,FKM_SHARED_BYTES)&&zero(w->Candidate,sizeof(w->Candidate)));
    } else {
      if (!(EFI_ERROR(s)&&w->State==FkrQuarantined&&c->Quarantined)) fprintf(stderr,"unexpected mode=%d state=%u backend-quarantine=%u calls=%u\n",mode,w->State,c->Quarantined,m.calls);
      assert(EFI_ERROR(s)&&w->State==FkrQuarantined&&c->Quarantined);
      unsigned calls=m.calls;
      m.snapshot=malloc(FKM_SHARED_BYTES);assert(m.snapshot);memcpy(m.snapshot,shared,FKM_SHARED_BYTES);
      assert(FkrReset(w)==EFI_ACCESS_DENIED);
      FKR_REPLY r;FKR_BEGIN_REQUEST b=request(208);
      assert(EFI_ERROR(ops.Begin(ops.Context,&b,&r))&&!r.Terminal&&m.calls==calls);
      assert(!memcmp(m.snapshot,shared,FKM_SHARED_BYTES));free(m.snapshot);
      assert(!zero(c->Request,sizeof(c->Request)));
      if(mode==25||mode==26){
        assert(c->Fault==7&&c->ResponseHeaderSeen&&m.calls==1&&!c->Handle);
        assert(c->ResponseStatus==(mode==25?0xffffffc2U:1));
        assert(c->ResponsePayloadBytes==(mode==25?14:0));
      }
    }
    // Host mock teardown only. Never a production way to free quarantine.
    free(shared);free(c);free(w);Cases++;
  }
}
static void decode_cases(void) {
  UINT8 good[]={0xa2,0x16,0,0x18,0x22,0x1b,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80};
  FKR_REPLY r;const UINT8 *out;UINTN n;
  assert(FkmDecode(FkrBegin,good,sizeof(good),&r,&out,&n)==EFI_SUCCESS&&r.Handle==Handle&&!n);Cases++;
  for(UINTN len=0;len<sizeof(good);len++) {
    assert(EFI_ERROR(FkmDecode(FkrBegin,good,len,&r,&out,&n))&&out==NULL&&n==0&&zero(&r,sizeof(r)));Cases++;
  }
  UINT8 bad[][20]={
    {0xa2,0x16,0,0x16,0}, // duplicate keys
    {0xa2,0x16,0,0x18,0x22,0}, // zero handle
    {0xa2,0x18,0x16,0,0x18,0x22,1}, // non-shortest key
    {0xbf,0x16,0,0x18,0x22,1,0xff}, // indefinite map
    {0xa3,0x16,0,0x18,0x22,1,0x18,0x24,0x40}, // unexpected output
    {0xa2,0x16,1,0x18,0x22,1}, // unknown output params
  };
  UINTN lengths[]={5,6,7,7,9,6};
  for(UINTN i=0;i<sizeof(lengths)/sizeof(lengths[0]);i++) {
    assert(EFI_ERROR(FkmDecode(FkrBegin,bad[i],lengths[i],&r,&out,&n))&&out==NULL&&n==0);Cases++;
  }
  UINT32 seed=0x17682395;UINT8 fuzz[128];
  for(unsigned i=0;i<2000;i++) {
    for(unsigned j=0;j<sizeof(fuzz);j++) { seed=seed*1664525+1013904223;fuzz[j]=(UINT8)(seed>>24); }
    (void)FkmDecode(i%3==0?FkrBegin:i%3==1?FkrUpdate:FkrFinish,fuzz,1+i%sizeof(fuzz),&r,&out,&n);
  }
  Cases++;
}
static void gate_cases(void) {
  FKM_CONTEXT c={0};FKR_OPS ops;MOCK m={0};UINT8 *shared=aligned_alloc(4096,FKM_SHARED_BYTES);
  assert(shared);
  assert(FkmInitialize(&c,1,shared,FKM_SHARED_BYTES,exchange,&m,TRUE,&ops)==EFI_INVALID_PARAMETER);
  assert(FkmInitialize(&c,4,shared+1,FKM_SHARED_BYTES,exchange,&m,TRUE,&ops)==EFI_INVALID_PARAMETER);
  assert(FkmInitialize(&c,4,shared,FKM_SHARED_BYTES-1,exchange,&m,TRUE,&ops)==EFI_INVALID_PARAMETER);
  UINT8 output[10];UINTN n;FKR_BEGIN_REQUEST b=request(208);
  assert(FkmEncode(FkrBegin,&b,0,NULL,0,output,sizeof(output),&n)==EFI_BUFFER_TOO_SMALL&&n==0&&zero(output,sizeof(output)));
  assert(FkmEncode(FkrUpdate,NULL,0,Data,32,output,sizeof(output),&n)==EFI_INVALID_PARAMETER);
  b.Purpose=0;assert(FkmEncode(FkrBegin,&b,0,NULL,0,output,sizeof(output),&n)==EFI_INVALID_PARAMETER);
  assert(!m.calls&&!c.Ready);free(shared);Cases+=6;
}
int main(int argc,char **argv) {
  for(UINTN i=0;i<sizeof(Blob);i++)Blob[i]=(UINT8)(i%251);
  for(UINTN i=0;i<64;i++)AppId[i]=(UINT8)i;
  for(UINTN i=0;i<12;i++)Nonce[i]=(UINT8)i;
  for(UINTN i=0;i<32;i++)Data[i]=(UINT8)i;
  if(argc==3&&!strcmp(argv[1],"frame")) {
    FKM_CONTEXT *c=calloc(1,sizeof(*c));FKR_OPS ops;MOCK m={100,0,0,NULL};
    UINT8 *shared=aligned_alloc(4096,FKM_SHARED_BYTES);FKR_REPLY reply;
    FKR_BEGIN_REQUEST req=request((UINTN)strtoul(argv[2],NULL,10));
    assert(c&&shared);assert(FkmInitialize(c,4,shared,FKM_SHARED_BYTES,exchange,&m,TRUE,&ops)==EFI_SUCCESS);
    assert(ops.Begin(ops.Context,&req,&reply)==EFI_SUCCESS);free(shared);free(c);return 0;
  }
  if(argc==5&&!strcmp(argv[1],"encode")) {
    UINTN size=(UINTN)strtoul(argv[3],NULL,10),n;UINT64 h=strtoull(argv[4],NULL,10);UINT8 b[8192];
    FKR_STAGE stage=!strcmp(argv[2],"begin")?FkrBegin:!strcmp(argv[2],"update")?FkrUpdate:!strcmp(argv[2],"finish")?FkrFinish:FkrAbort;
    FKR_BEGIN_REQUEST req=request(size);
    assert(FkmEncode(stage,stage==FkrBegin?&req:NULL,stage==FkrBegin?0:h,
                     stage==FkrUpdate?Data:NULL,stage==FkrUpdate?32:0,b,sizeof(b),&n)==EFI_SUCCESS);
    assert(fwrite(b,1,n,stdout)==n);return 0;
  }
  if(argc==4&&!strcmp(argv[1],"decode")) {
    FILE *f=fopen(argv[3],"rb");UINT8 raw[5000];assert(f);UINTN n=fread(raw,1,sizeof(raw),f);assert(!ferror(f)&&feof(f));fclose(f);
    FKR_STAGE s=!strcmp(argv[2],"begin")?FkrBegin:!strcmp(argv[2],"update")?FkrUpdate:FkrFinish;
    FKR_REPLY r;const UINT8 *p;UINTN bytes;
    assert(FkmDecode(s,raw,n,&r,&p,&bytes)==EFI_SUCCESS);
    if(s==FkrBegin)assert(r.Handle==Handle&&!bytes);
    else {assert(bytes==32&&!memcmp(p,Data,32));if(s==FkrUpdate)assert(r.Consumed==48);}
    return 0;
  }
  backend_cases();decode_cases();gate_cases();printf("backend synthetic cases=%u; no TA/GCM execution\n",Cases);return 0;
}
