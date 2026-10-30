// SPDX-License-Identifier: BSD-2-Clause-Patent
// Synthetic PUBLIC configure monitor; no real secure-world success hook.
static int ConfigureMonitor(ARM_SMC_ARGS *a){
 const UINT8 packet[]={0x16,0x21,0,0,0xa4,0x16,3,0x1a,0x30,0,2,0xc1,0x1a,0,2,0x98,0x10,0x1a,0x30,0,2,0xc2,0x1a,1,0x35,0x28,0x8d,0x1a,0x30,0,2,0xce,0x1a,1,0x35,0x28,0x8d};
 assert(Calls==6&&!SecretCalls&&!SecretUnknown&&!mRecoveryAttempted&&!mRecoverySession);
 assert(mRecoveryWork&&mRecoveryWork->State==FkrPrepared);
 ++ConfigureCalls;
 assert(a->Arg0==(ConfigurePending?1:0x72000602)&&a->Arg1==0x224&&a->Arg2==(UINTN)Page&&a->Arg3==0x15000&&a->Arg4==(UINTN)(Page+0x15000)&&a->Arg5==4096&&!a->Arg7);
 if(ConfigurePending)assert(a->Arg6==(UINTN)(0xc010+ConfigureCalls-1));
 assert(*(UINT32*)Page==App()&&*(UINT32*)(Page+8)==0x424);
 assert(*(UINT32*)(Page+16)==sizeof(packet)&&!memcmp(Page+96,packet,sizeof(packet)));
 assert(*(UINT32*)(Page+20)==0x88&&*(UINT32*)(Page+24)==0x9fd8);
 assert(*(UINT32*)(Page+28)==0xa060&&*(UINT32*)(Page+36)==0xa060&&*(UINT32*)(Page+40)==4);
 assert(*(UINT32*)(Page+44)==0xa068&&*(UINT32*)(Page+52)==0xa090&&*(UINT32*)(Page+56)==0x9fd8);
 a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
 if((Scenario==24&&ConfigureCalls==1)||Scenario==25){
   a->Arg0=1;a->Arg6=0xc010+ConfigureCalls;ConfigurePending=1;
   if(ConfigureCalls<9)return 1;
 }else{
   Put(Page+0xa094,0x9fd0);
   if(Scenario==17)a->Arg0=3;
   if(Scenario==18)Put(Page+0xa090,0xffffffdaU);
   if(Scenario==19)Page[100]^=1;
   if(Scenario==20)Put(Page+56,0x9fd9);
   if(Scenario==21)Page[0x15008]=1;
   if(Scenario==22)Put(Page+0xa094,0);
   if(Scenario==23)Page[0xa098]=1;
   if(Scenario==26)Page[0]^=1;
 }
 if((Scenario>=17&&Scenario<=23)||Scenario==25||Scenario==26){
   SecretUnknown=1;SecretSnapshot=malloc(TEST_BYTES);assert(SecretSnapshot);memcpy(SecretSnapshot,Page,TEST_BYTES);
 }
 return 1;
}
