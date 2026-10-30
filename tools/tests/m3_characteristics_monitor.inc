// SPDX-License-Identifier: BSD-2-Clause-Patent
// Synthetic monitor responses for the actual characteristics/session entry.
static int CharacteristicsMonitor(ARM_SMC_ARGS *a){
 UINT32 bo=*(UINT32*)(Page+52),cap=*(UINT32*)(Page+56);
 assert(!SecretUnknown);
 assert(a->Arg1==0x224&&a->Arg2==(UINTN)Page&&a->Arg3==FKM_MESSAGE_BYTES);
 assert(a->Arg4==(UINTN)(Page+FKM_MESSAGE_BYTES)&&a->Arg5==4096);
 ++CharacteristicsCalls;
 a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
 if(CharacteristicsScenario==11){
   a->Arg0=1;a->Arg6=0x1234;
   if(CharacteristicsCalls<=8)return 1;
 }else if(CharacteristicsScenario==1){Put(Page+bo,0xffffffdfU);Put(Page+bo+4,0);}
 else if(CharacteristicsScenario==2){Put(Page+bo,0xffffffc2U);Put(Page+bo+4,cap-8);}
 else if(CharacteristicsScenario==3){Put(Page+bo,1);Put(Page+bo+4,0);}
 else if(CharacteristicsScenario==4)a->Arg0=3;
 else if(CharacteristicsScenario==5)Page[FKM_MESSAGE_BYTES+8]=1;
 else if(CharacteristicsScenario==6)Put(Page+56,cap+1);
 else if(CharacteristicsScenario==7)Page[12]^=1;
 else if(CharacteristicsScenario==8)Put(Page+bo+4,cap);
 else if(CharacteristicsScenario==9){Page[bo+8]=0x58;Page[bo+9]=0xff;Put(Page+bo+4,2);}
 else if(CharacteristicsScenario==10){
   UINT8 b[]={0xa2,0x1a,0x30,0,2,0xc1,0x1a,0,2,0x98,0x10,
              0x1a,0x30,0,2,0xc2,0x58,0xff};
   memcpy(Page+bo+8,b,sizeof(b));Put(Page+bo+4,sizeof(b));
 }else{
   assert(!CharacteristicsScenario);
   UINT8 b[]={0xa2,0x1a,0x30,0,2,0xc1,0x1a,0,2,0x98,0x10,
              0x1a,0x30,0,2,0xc2,0x1a,1,0x35,0x28,0x2d};
   memcpy(Page+bo+8,b,sizeof(b));Put(Page+bo+4,sizeof(b));
 }
 if(CharacteristicsScenario){
   SecretUnknown=1;SecretSnapshot=malloc(TEST_BYTES);assert(SecretSnapshot);
   memcpy(SecretSnapshot,Page,TEST_BYTES);
 }
 return 1;
}
