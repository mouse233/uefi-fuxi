// SPDX-License-Identifier: BSD-2-Clause-Patent
int main(void){
 for(Scenario=0;Scenario<=26;Scenario++){
   Calls=Frees=TaFrees=LogCalls=SecretCalls=SecretUnknown=PoolCalls=ConfigureCalls=ConfigurePending=0;
   Phase=Scenario==14?99:0;Fault=Special=ResumeTarget=ResumePending=0;
   mPoisoned=FALSE;mReady=TRUE;mRecoveryStatus=EFI_NOT_READY;mRecoveryRetained=mRecoveryVersionOk=mRecoveryAttempted=FALSE;
   assert(!mRecoveryWork&&!mRecoverySession&&!Page&&!TaBuf&&!PoolLive&&!SecretSnapshot);
   memset(&Report,0,sizeof(Report));
   VOID *scratch=calloc(1,F2R_WORK_BYTES);assert(scratch);FDP_DISK disk={0};FDP_PARTITION part={0};part.Present=TRUE;
   FnuPrepareRecovery(&disk,&part,scratch);free(scratch);
   if(Scenario==12){assert(EFI_ERROR(mRecoveryStatus)&&!mRecoveryWork&&!PoolLive);continue;}
   assert(mRecoveryStatus==EFI_SUCCESS&&mRecoveryWork&&mRecoveryWork->State==FkrPrepared);
   mReady=Scenario==13;SetupTa();FnuSmciRootProbe();
   if(Scenario==0||Scenario==24){assert(mSmciStatus==EFI_SUCCESS&&SecretCalls==3&&Calls==10&&Frees==1&&!mRecoveryWork&&!mRecoverySession);}
   if(Scenario==1||Scenario==2||Scenario==3||Scenario==11){
     assert(EFI_ERROR(mSmciStatus)&&Calls==10&&Frees==1&&!mRecoveryWork&&!mRecoverySession&&!mRecoveryRetained);
   }
   if((Scenario>=4&&Scenario<=9)||Scenario==15||Scenario==16){
     assert(EFI_ERROR(mSmciStatus)&&Calls==6&&!Frees&&Page&&mRecoveryRetained&&mRecoveryWork&&mRecoverySession);
     assert(SecretSnapshot&&!memcmp(SecretSnapshot,Page,TEST_BYTES));
   }
   if(Scenario==10||Scenario==13||(Scenario>=17&&Scenario!=24)){
     assert(EFI_ERROR(mSmciStatus)&&Calls==6&&!Frees&&Page&&!mRecoveryWork&&!mRecoverySession&&!mRecoveryRetained&&!SecretCalls);
     if(Scenario>=17)assert(SecretSnapshot&&!memcmp(SecretSnapshot,Page,TEST_BYTES));
   }
   if(Scenario==14){assert(!Calls&&!Frees&&!Page&&!mRecoveryWork&&!PoolLive);}
   if(Scenario==10||Scenario==13||Scenario==14)assert(!ConfigureCalls);
   else assert(ConfigureCalls==(Scenario==24?2:Scenario==25?9:1));
   assert(TaFrees==1&&!TaBuf);
   // Only fake host allocations are freed after a simulated quarantine.
   if(Page){munmap(Page,TEST_BYTES);Page=NULL;}
   if(SecretSnapshot){free(SecretSnapshot);SecretSnapshot=NULL;}
   while(PoolLive){free(Pools[--PoolLive].p);}
   mRecoveryWork=NULL;mRecoverySession=NULL;
 }
#if FUXI_M3_RECOVERY_PUBLIC
 // Malformed public input after preparation: configure still uses the same
 // fixed public request; no begin or secret exchange is allowed afterward.
 for(int bad=0;bad<2;++bad){
   Scenario=0;Calls=Frees=TaFrees=LogCalls=SecretCalls=SecretUnknown=PoolCalls=ConfigureCalls=ConfigurePending=0;
   Phase=Fault=Special=ResumeTarget=ResumePending=0;
   mPoisoned=FALSE;mReady=TRUE;mRecoveryStatus=EFI_NOT_READY;mRecoveryRetained=mRecoveryVersionOk=mRecoveryAttempted=FALSE;
   memset(&Report,0,sizeof(Report));
   VOID *scratch=calloc(1,F2R_WORK_BYTES);assert(scratch);FDP_DISK disk={0};FDP_PARTITION part={0};part.Present=TRUE;
   FnuPrepareRecovery(&disk,&part,scratch);free(scratch);assert(mRecoveryStatus==EFI_SUCCESS);
   if(bad)mRecoveryWork->BlobBytes=1;else mRecoveryWork->Blob[0]=0xff;
   mReady=FALSE;SetupTa();FnuSmciRootProbe();
   assert(EFI_ERROR(mSmciStatus)&&ConfigureCalls==1&&Calls==10&&Frees==1&&TaFrees==1);
   assert(!SecretCalls&&!mRecoveryAttempted&&!mRecoveryRetained&&!mRecoveryWork&&!mRecoverySession&&!PoolLive&&!Page&&!TaBuf);
 }
 puts("PASS 29 public-observation recovery/session cases; same App and submitted blob checked");return 0;
#endif
 puts("PASS 27 configured recovery/session cases; production flow, monitor/filesystem simulated");return 0;
}
