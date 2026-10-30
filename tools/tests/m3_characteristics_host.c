// SPDX-License-Identifier: BSD-2-Clause-Patent
// Host-only probe test: synthetic TA answers, no SMC, no real blob or key.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "M3KeyMintBackend.h"
static unsigned Cases;
static UINT8 Blob[FKR_BLOB_LIMIT], AppId[64];
static unsigned get32(const UINT8 *p) { return p[0]|((unsigned)p[1]<<8)|((unsigned)p[2]<<16)|((unsigned)p[3]<<24); }
static void put32(UINT8 *p,unsigned n) { for (unsigned i=0;i<4;i++) p[i]=(UINT8)(n>>(i*8)); }

typedef struct { int mode; unsigned calls, status; UINTN sent; } MOCK;

static EFI_STATUS exchange(void *ctx,UINT8 *p,UINTN in,UINTN out,FKM_RETURN *r) {
  MOCK *m=ctx; unsigned bo=get32(p+52), cap=get32(p+56), cmd=get32(p+96);
  UINTN n;
  assert(in==FKM_MESSAGE_BYTES&&out==4096&&cmd==0x2109);
  assert(get32(p)==4&&get32(p+8)==0x424&&get32(p+12)==96);
  m->calls++; m->sent=get32(p+16);
  // 4-byte command then map(2){23: blob, 29: bstr(map(1){app-id: bytes})}, as
  // the pinned HAL serializes 0x2109 with additional params.
  assert(p[100]==0xa2&&p[101]==0x17);
  assert(p[102]==0x58&&p[103]==0xd0&&memcmp(p+104,Blob,208)==0);
  assert(p[312]==0x18&&p[313]==0x1d&&p[314]==0x58&&p[315]==0x48&&get32(p+16)==292);
  // Inner param map uses the same sign-extended app-id label as begin.
  assert(p[316]==0xa1&&p[317]==0x3a&&p[318]==0x6f&&p[319]==0xff&&p[320]==0xfd&&p[321]==0xa6);
  assert(p[322]==0x58&&p[323]==0x40&&memcmp(p+324,AppId,64)==0);
  if(m->mode==1) { r->A0=1; return EFI_SUCCESS; }
  if(m->mode==2) { p[12]++; return EFI_SUCCESS; }
  if(m->mode==3) { p[in+8]=1; return EFI_SUCCESS; }
  if(m->mode==4) { put32(p+56,cap+1); return EFI_SUCCESS; }
  if(m->mode==5) { put32(p+48,get32(p+16)+1); return EFI_SUCCESS; }
  if(m->mode==10) { // negative status, fixed no-output wrapper shape
    put32(p+bo,0xffffffc2U); put32(p+bo+4,cap-8); return EFI_SUCCESS;
  }
  if(m->mode==11) { put32(p+bo,5); put32(p+bo+4,0); return EFI_SUCCESS; }
  if(m->mode==12) { // truncated definite-length string
    p[bo+8]=0x58; p[bo+9]=0xff; put32(p+bo+4,2); return EFI_SUCCESS;
  }
  if(m->mode==13) { // tag present, value absent
    static const UINT8 body[]={0xa1,0x1a,0x30,0x00,0x02,0xc1};
    memcpy(p+bo+8,body,sizeof(body)); put32(p+bo+4,sizeof(body)); return EFI_SUCCESS;
  }
  if(m->mode==20) { // flat map of tag:value
    static const UINT8 body[]={0xa2,0x1a,0x30,0x00,0x02,0xc1,0x1a,0x00,0x02,0x98,0x10,
                               0x1a,0x30,0x00,0x02,0xc2,0x1a,0x00,0x03,0x17,0x72};
    memcpy(p+bo+8,body,sizeof(body)); put32(p+bo+4,sizeof(body)); return EFI_SUCCESS;
  }
  if(m->mode==21) { // nested arrays, same pairs
    static const UINT8 body[]={0xa2,0x00,0x82,0x1a,0x30,0x00,0x02,0xc1,0x1a,0x00,0x02,0x98,0x10,
                               0x01,0x82,0x1a,0x30,0x00,0x02,0xc2,0x1a,0x00,0x03,0x17,0x72};
    memcpy(p+bo+8,body,sizeof(body)); put32(p+bo+4,sizeof(body)); return EFI_SUCCESS;
  }
  if(m->mode==22) { // unrelated tags only
    static const UINT8 body[]={0xa2,0x1a,0x30,0x00,0x03,0xeb,0x18,0x80,0x1a,0x30,0x00,0x02,0xc3,0x18,0x05};
    memcpy(p+bo+8,body,sizeof(body)); put32(p+bo+4,sizeof(body)); return EFI_SUCCESS;
  }
  n=0; put32(p+bo+4,(unsigned)n); return EFI_SUCCESS;
}

static void run(int mode,FKM_CONTEXT *c,MOCK *m) {
  static UINT8 shared[FKM_SHARED_BYTES+4096];
  FKM_CHARACTERISTICS ch; EFI_STATUS s;
  memset(c,0,sizeof(*c)); memset(m,0,sizeof(*m)); m->mode=mode;
  c->Shared=shared; c->SharedBytes=FKM_SHARED_BYTES; c->App=4; c->Ready=TRUE;
  c->Exchange=exchange; c->ExchangeContext=m;
  memset(&ch,0xa5,sizeof(ch));
  s=FkmProbeCharacteristics(c,Blob,208,AppId,64,&ch);
  Cases++;
  switch(mode) {
  case 20:
    assert(s==EFI_SUCCESS&&ch.HaveOsVersion&&ch.OsVersion==170000&&
           ch.HaveOsPatchLevel&&ch.OsPatchLevel==202610&&ch.TagsScanned>0);
    assert(!c->Quarantined&&c->ResponseStatus==0&&c->ResponseHeaderSeen);
    break;
  case 21:
    assert(s==EFI_SUCCESS&&ch.HaveOsVersion&&ch.OsVersion==170000&&
           ch.HaveOsPatchLevel&&ch.OsPatchLevel==202610);
    break;
  case 22:
    assert(s==EFI_SUCCESS&&!ch.HaveOsVersion&&!ch.HaveOsPatchLevel&&ch.TagsScanned>0);
    break;
  case 0:
    assert(s==EFI_SUCCESS&&!ch.HaveOsVersion&&!ch.HaveOsPatchLevel);
    break;
  case 10:
    assert(s==EFI_DEVICE_ERROR&&!c->Quarantined&&c->ResponseStatus==0xffffffc2U);
    assert(!ch.HaveOsVersion&&!ch.HaveOsPatchLevel);
    break;
  case 11:
    assert(s==EFI_DEVICE_ERROR&&c->Quarantined);
    break;
  case 12: case 13:
    assert(s==EFI_COMPROMISED_DATA&&!c->Quarantined);
    break;
  case 1:
    assert(s==EFI_NOT_READY&&c->Quarantined&&c->Fault==2);
    break;
  case 2:
    assert(s==EFI_NOT_READY&&c->Quarantined&&c->Fault==5);
    break;
  case 3:
    assert(s==EFI_NOT_READY&&c->Quarantined&&c->Fault==3);
    break;
  case 4:
    assert(s==EFI_NOT_READY&&c->Quarantined&&c->Fault==4);
    break;
  case 5:
    assert(s==EFI_NOT_READY&&c->Quarantined&&c->Fault==4);
    break;
  default: assert(0);
  }
  assert(m->calls<=1);
  // The request buffer and shared page are cleared after every outcome.
  for(unsigned i=0;i<sizeof(c->Request);++i) assert(c->Request[i]==0);
  for(unsigned i=0;i<FKM_SHARED_BYTES;++i) assert(shared[i]==0);
}

int main(void) {
  FKM_CONTEXT c; MOCK m;
  memset(Blob,0x5a,sizeof(Blob)); memset(AppId,0x3c,sizeof(AppId));
  for(int mode=0;mode<=5;++mode) run(mode,&c,&m);
  run(10,&c,&m); run(11,&c,&m); run(12,&c,&m); run(13,&c,&m);
  run(20,&c,&m); run(21,&c,&m); run(22,&c,&m);
  // Preconditions never reach the transport.
  static UINT8 shared[FKM_SHARED_BYTES];
  FKM_CHARACTERISTICS ch;
  memset(&c,0,sizeof(c)); memset(&m,0,sizeof(m));
  assert(FkmProbeCharacteristics(NULL,Blob,208,AppId,64,&ch)==EFI_INVALID_PARAMETER);
  c.Shared=shared; c.SharedBytes=FKM_SHARED_BYTES; c.App=4; c.Ready=TRUE;
  c.Exchange=exchange; c.ExchangeContext=&m;
  assert(FkmProbeCharacteristics(&c,NULL,208,AppId,64,&ch)==EFI_INVALID_PARAMETER);
  assert(FkmProbeCharacteristics(&c,Blob,0,AppId,64,&ch)==EFI_INVALID_PARAMETER);
  assert(FkmProbeCharacteristics(&c,Blob,FKR_BLOB_LIMIT+1,AppId,64,&ch)==EFI_INVALID_PARAMETER);
  assert(FkmProbeCharacteristics(&c,Blob,208,NULL,64,&ch)==EFI_INVALID_PARAMETER);
  assert(FkmProbeCharacteristics(&c,Blob,208,AppId,63,&ch)==EFI_INVALID_PARAMETER);
  c.Handle=1;
  assert(FkmProbeCharacteristics(&c,Blob,208,AppId,64,&ch)==EFI_NOT_READY);
  c.Handle=0; c.Quarantined=TRUE;
  assert(FkmProbeCharacteristics(&c,Blob,208,AppId,64,&ch)==EFI_NOT_READY);
  c.Quarantined=FALSE; c.Ready=FALSE;
  assert(FkmProbeCharacteristics(&c,Blob,208,AppId,64,&ch)==EFI_NOT_READY);
  assert(m.calls==0);
  printf("PASS %u probe cases; synthetic transport only\n",Cases);
  return 0;
}
