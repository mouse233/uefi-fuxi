// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "RamBulk.h"
#ifdef RAMBULK_UEFI
#include <Library/BaseMemoryLib.h>
#define COPY(d,s,n) CopyMem(d,s,(UINTN)(n))
#define ZERO(d,n) ZeroMem(d,(UINTN)(n))
#define SAME(a,b,n) (CompareMem(a,b,n)==0)
#else
#include <string.h>
#define COPY(d,s,n) memcpy(d,s,(size_t)(n))
#define ZERO(d,n) memset(d,0,(size_t)(n))
#define SAME(a,b,n) (memcmp(a,b,n)==0)
#endif
static const RB8 Magic[8]={'U','N','X','R','A','M','0','1'};
RB64 RbRead(const RB8 *p,unsigned n) {
  RB64 v=0; for(unsigned i=0;i<n;i++) v|=(RB64)p[i]<<(i*8); return v;
}
void RbWrite(RB8 *p,RB64 v,unsigned n) {
  for(unsigned i=0;i<n;i++) p[i]=(RB8)(v>>(i*8));
}
int RbHeaderLength(const RB8 h[RB_HEADER],RB32 *bytes) {
  if(!SAME(h,Magic,8) || RbRead(h+8,2)!=1 || RbRead(h+28,4)!=0) return 0;
  *bytes=(RB32)RbRead(h+24,4);
  return *bytes<=RB_CHUNK;
}
static void ClearObject(RB_SESSION *s,RB_OBJECT *o) {
  if(o->Data) {s->Release(s->Context,o->Data,o->Bytes);s->Allocated-=o->Bytes;}
  ZERO(o,sizeof(*o));
}
void RbClear(RB_SESSION *s) {
  for(unsigned i=0;i<RB_OBJECTS;i++) ClearObject(s,&s->Object[i]);
}
void RbHandle(RB_SESSION *s,const RB8 h[RB_HEADER],const RB8 *p,RB32 bytes,RB8 reply[RB_HEADER]) {
  RB32 length=0,id=(RB32)RbRead(h+12,4),error=RbOk;
  RB16 op=(RB16)RbRead(h+10,2);
  RB64 offset=RbRead(h+16,8),limit;
  RB8 digest[32]; RB_OBJECT *o=id<RB_OBJECTS?&s->Object[id]:0;
  ZERO(reply,RB_HEADER);COPY(reply,Magic,8);RbWrite(reply+8,1,2);
  RbWrite(reply+10,op|0x8000,2);RbWrite(reply+12,id,4);
  if(!RbHeaderLength(h,&length)) {error=RbBadHeader;goto Done;}
  if(length!=bytes || (bytes && !p)) {error=RbBadLength;goto Done;}
  if(bytes && (!s->Hash(p,bytes,digest) || !SAME(digest,h+32,32))) {error=RbBadHash;goto Done;}
  if(op==RbHello) {
    if(bytes || offset || id) {error=RbBadLength;goto Done;}
    RbWrite(reply+16,RB_CHUNK,8);goto Done;
  }
  if(!o) {error=RbBadObject;goto Done;}
  switch(op) {
  case RbBegin:
    if(bytes!=40 || offset) {error=RbBadLength;break;}
    if(o->State) {error=RbBadState;break;}
    limit=id==0?(1ULL<<20):id==1?(8ULL<<30):(4ULL<<30);
    offset=RbRead(p,8);
    if(!offset || offset>limit || s->Allocated>RB_TOTAL_LIMIT ||
       offset>RB_TOTAL_LIMIT-s->Allocated) {error=RbBadLength;break;}
    o->Data=s->Allocate(s->Context,offset);
    if(!o->Data) {error=RbNoMemory;break;}
    o->Bytes=offset;o->State=1;s->Allocated+=offset;COPY(o->Digest,p+8,32);break;
  case RbData:
    if(o->State!=1) {error=RbBadState;break;}
    if(offset!=o->Received) {error=RbBadOffset;break;}
    if(!bytes || o->Received>o->Bytes || bytes>o->Bytes-o->Received) {error=RbBadLength;break;}
    COPY(o->Data+o->Received,p,bytes);o->Received+=bytes;break;
  case RbEnd:
    if(bytes || offset!=o->Received) {error=RbBadLength;break;}
    if(o->State!=1 || o->Received!=o->Bytes) {error=RbBadState;break;}
    // Hash the actual RAM contents, not just the incoming stream.
    if(!s->Hash(o->Data,o->Bytes,digest) || !SAME(digest,o->Digest,32)) {
      o->State=3;error=RbBadHash;break;
    }
    o->State=2;COPY(reply+32,digest,32);break;
  case RbAbort:
    if(bytes || offset) {error=RbBadLength;break;}
    ClearObject(s,o);break;
  default:error=RbBadHeader;break;
  }
  RbWrite(reply+16,o->Received,8);
Done:
  RbWrite(reply+28,error,4);
}
