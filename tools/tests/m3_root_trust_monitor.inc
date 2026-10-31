// SPDX-License-Identifier: BSD-2-Clause-Patent
// Simulated transport only, not secure-world or cryptographic success evidence.
#include "m3_root_trust_fixture.inc"
static BOOLEAN mReady,mPoisoned;
static int RootMode,RootConfigs,RootQueries;
static UINT8 *RootSnapshot,*RootPending;
static void RootSave(void){
 if(!RootSnapshot){RootSnapshot=malloc(TEST_BYTES);assert(RootSnapshot);}
 memcpy(RootSnapshot,Page,TEST_BYTES);
}
static int RootMonitor(ARM_SMC_ARGS *a){
 UINT32 cmd=*(UINT32*)(Page+96);int config=cmd==0x2116;
 if(!config&&cmd!=0x311f)return 0;
 const UINT8 cfg[]={0x16,0x21,0,0,0xa4,0x16,3,0x1a,0x30,0,2,0xc1,0x1a,0,2,0x98,0x10,0x1a,0x30,0,2,0xc2,0x1a,1,0x35,0x28,0x8d,0x1a,0x30,0,2,0xce,0x1a,1,0x35,0x28,0x8d};
 const UINT8 query[]={0x1f,0x31,0,0,0xa1,4,0x50,'F','U','X','I','-','R','O','T','-','P','R','O','B','E','0','1'};
 const UINT8 *req=config?cfg:query;UINTN n=config?sizeof(cfg):sizeof(query);
 assert(Calls==6&&*(UINT32*)Page==App());
 assert(a->Arg1==0x224&&a->Arg2==(UINTN)Page&&a->Arg3==0x15000&&a->Arg4==(UINTN)(Page+0x15000)&&a->Arg5==4096&&!a->Arg7);
 if(config){++RootConfigs;assert(RootConfigs==1&&a->Arg0==0x72000602&&!RootQueries);}
 else{
  ++RootQueries;assert(RootConfigs==1);
  if(RootQueries==1)assert(a->Arg0==0x72000602);
  else{assert(a->Arg0==1&&a->Arg6==(UINTN)(0xc020+RootQueries-1));assert(RootPending&&!memcmp(RootPending,Page,TEST_BYTES));}
 }
 UINT8 *want=calloc(1,TEST_BYTES);assert(want);
 Put(want,App());Put(want+8,0x424);Put(want+12,96);Put(want+16,(UINT32)n);
 Put(want+20,0x88);Put(want+24,0x9fd8);Put(want+28,0xa060);
 Put(want+36,0xa060);Put(want+40,4);Put(want+44,0xa068);Put(want+48,(UINT32)n);
 Put(want+52,0xa090);Put(want+56,0x9fd8);Put(want+0xa060,1);memcpy(want+96,req,n);
 assert(!memcmp(want,Page,TEST_BYTES));free(want);
 a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
 if(!config&&(RootMode==27||RootMode==28||RootMode==29)){
  if(RootQueries==1||RootMode==28){
   if(!RootPending){RootPending=malloc(TEST_BYTES);assert(RootPending);memcpy(RootPending,Page,TEST_BYTES);}
   a->Arg0=1;a->Arg6=0xc020+RootQueries;
   if(RootMode==28)RootSave();
   return 1;
  }
  if(RootMode==29){a->Arg0=2;RootSave();return 1;}
 }
 Put(Page+0x15000,0x10002);Put(Page+0x15004,0xffff);
 if(config){
  Put(Page+0xa094,0x9fd0);
  if(RootMode==23)Put(Page+0xa090,0xffffffe2);
  if(RootMode==24)Page[0x15008]=1;
  if(RootMode==25)Page[0]^=1;
  if(RootMode>=23&&RootMode<=25)RootSave();
  return 1;
 }
 UINT8 *body=Page+0xa098;memcpy(body,RootReply,sizeof(RootReply));
 Put(Page+0xa094,sizeof(RootReply));Put(Page+56,sizeof(RootReply)+8);
 if(RootMode==1)Put(Page+56,0x9fd8);
 if(RootMode==2){Put(Page+0x15000,0);Put(Page+0x15004,0);}
 if(RootMode==3)Put(Page+0x15004,0xfffd);
 if(RootMode==4)body[sizeof(RootReply)-1]^=0xff; // MAC unverified by design
 if(RootMode==5){Put(Page+0xa090,0xffffffe2);Put(Page+0xa094,0);Put(Page+56,8);memset(body,0,sizeof(RootReply));}
 if(RootMode==6){Put(Page+0xa090,0xffffffcf);Put(Page+0xa094,0x9fd0);Put(Page+56,0x9fd8);}
 if(RootMode==7)a->Arg0=2;
 if(RootMode==8)a->Arg1=1;
 if(RootMode==9)a->Arg2=1;
 if(RootMode==10)a->Arg3=1;
 if(RootMode==11)Page[0x15008]=1;
 if(RootMode==12)Page[0]^=1;
 if(RootMode==13)Page[96]^=1;
 if(RootMode==14)Put(Page+56,7);
 if(RootMode==15)Put(Page+48,(UINT32)n+1);
 if(RootMode==16)Put(Page+0xa094,sizeof(RootReply)+1);
 if(RootMode==17)Page[0x14000]=1;
 if(RootMode==18)body[5]^=1;
 if(RootMode==19)body[sizeof(RootReply)-33]=31;
 if(RootMode==20)body[sizeof(RootReply)]=1;
 if(RootMode==21){for(UINTN i=0;i+2<sizeof(RootReply);++i)if(body[i]==0xa1&&body[i+1]==1&&body[i+2]==5){body[i+2]=6;break;}}
 if(RootMode==22)body[sizeof(RootReply)-39]=0x3a;
 if(RootMode>=5&&RootMode<=22)RootSave();
 return 1;
}
