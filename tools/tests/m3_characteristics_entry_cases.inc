// SPDX-License-Identifier: BSD-2-Clause-Patent
int main(void){
 for(CharacteristicsScenario=0;CharacteristicsScenario<=12;CharacteristicsScenario++){
   Scenario=0;
   Calls=Frees=TaFrees=LogCalls=SecretCalls=SecretUnknown=PoolCalls=ConfigureCalls=ConfigurePending=CharacteristicsCalls=0;
   Phase=Fault=Special=ResumeTarget=ResumePending=0;
   mPoisoned=FALSE;mReady=TRUE;mRecoveryStatus=EFI_NOT_READY;
   mRecoveryRetained=mRecoveryVersionOk=mRecoveryAttempted=FALSE;
   assert(!mRecoveryWork&&!mRecoverySession&&!Page&&!TaBuf&&!PoolLive&&!SecretSnapshot);
   memset(&Report,0,sizeof(Report));
   VOID *scratch=calloc(1,F2R_WORK_BYTES);assert(scratch);
   FDP_DISK disk={0};FDP_PARTITION part={0};part.Present=TRUE;
   FnuPrepareRecovery(&disk,&part,scratch);free(scratch);
   assert(mRecoveryStatus==EFI_SUCCESS&&mRecoveryWork->State==FkrPrepared);
   if(CharacteristicsScenario==12)mRecoveryWork->ApplicationIdBytes=63;
   mReady=FALSE;SetupTa();FnuSmciRootProbe();
   assert(ConfigureCalls==1&&TaFrees==1&&!TaBuf);
   if(!CharacteristicsScenario){
     assert(mSmciStatus==EFI_SUCCESS&&CharacteristicsCalls==1&&SecretCalls==3);
     assert(Calls==10&&Frees==1&&!mRecoveryWork&&!mRecoverySession&&mRecoveryAttempted);
   }else{
     assert(EFI_ERROR(mSmciStatus)&&Calls==6&&!Frees&&Page);
     assert(!SecretCalls&&!mRecoveryAttempted&&mRecoveryRetained);
     assert(mRecoveryWork&&mRecoveryWork->State==FkrPrepared&&mRecoverySession);
     FKM_CONTEXT *b=&mRecoverySession->Backend;
     assert(b->Quarantined&&!b->Handle&&mRecoverySession->Exchange.State!=FseClosed);
     if(CharacteristicsScenario==12){
       assert(!CharacteristicsCalls&&!b->RequestBytes);
       for(UINTN i=0;i<FKM_SHARED_BYTES;i++)assert(!Page[i]);
     }else{
       assert(CharacteristicsCalls==(CharacteristicsScenario==11?9:1));
       assert(SecretSnapshot&&!memcmp(SecretSnapshot,Page,TEST_BYTES));
       assert(b->RequestBytes&&b->Request[0]==9&&b->Request[1]==0x21);
       FKM_CHARACTERISTICS fields;FKR_OPS ops={0};FKR_REPLY reply;
       assert(FkmProbeCharacteristics(b,mRecoveryWork->Blob,208,mRecoveryWork->ApplicationId,64,&fields)==EFI_NOT_READY);
       assert(FsePermitCleanup(&mRecoverySession->Exchange,b)==EFI_ACCESS_DENIED);
       assert(FkmInitialize(b,App(),Page,FKM_SHARED_BYTES,FseExchange,&mRecoverySession->Exchange,TRUE,&ops)==EFI_ACCESS_DENIED);
       (void)reply;
       assert(!memcmp(SecretSnapshot,Page,TEST_BYTES));
     }
   }
   // Host-only disposal of fake allocations; production remains parked.
   if(Page){munmap(Page,TEST_BYTES);Page=NULL;}
   if(SecretSnapshot){free(SecretSnapshot);SecretSnapshot=NULL;}
   while(PoolLive)free(Pools[--PoolLive].p);
   mRecoveryWork=NULL;mRecoverySession=NULL;
 }
 puts("PASS 13 characteristics entry/session cases; production flow, monitor/filesystem simulated");
 return 0;
}
