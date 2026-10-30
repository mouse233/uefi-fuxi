// SPDX-License-Identifier: BSD-2-Clause-Patent
int main(void){
 for(Scenario=0;Scenario<=16;Scenario++){
   Calls=Frees=TaFrees=LogCalls=SecretCalls=SecretUnknown=PoolCalls=0;
   Phase=Scenario==14?99:0;Fault=Special=ResumeTarget=ResumePending=0;
   mPoisoned=FALSE;mReady=TRUE;mRecoveryStatus=EFI_NOT_READY;mRecoveryRetained=mRecoveryVersionOk=mRecoveryAttempted=FALSE;
   assert(!mRecoveryWork&&!mRecoverySession&&!Page&&!TaBuf&&!PoolLive&&!SecretSnapshot);
   memset(&Report,0,sizeof(Report));
   VOID *scratch=calloc(1,F2R_WORK_BYTES);assert(scratch);FDP_DISK disk={0};FDP_PARTITION part={0};part.Present=TRUE;
   FnuPrepareRecovery(&disk,&part,scratch);free(scratch);
   if(Scenario==12){assert(EFI_ERROR(mRecoveryStatus)&&!mRecoveryWork&&!PoolLive);continue;}
   assert(mRecoveryStatus==EFI_SUCCESS&&mRecoveryWork&&mRecoveryWork->State==FkrPrepared);
   mReady=Scenario==13;SetupTa();FnuSmciRootProbe();
   if(Scenario==0){assert(mSmciStatus==EFI_SUCCESS&&SecretCalls==3&&Calls==10&&Frees==1&&!mRecoveryWork&&!mRecoverySession);}
   if(Scenario==1||Scenario==2||Scenario==3||Scenario==11||Scenario==13){
     assert(EFI_ERROR(mSmciStatus)&&Calls==10&&Frees==1&&!mRecoveryWork&&!mRecoverySession&&!mRecoveryRetained);
   }
   if((Scenario>=4&&Scenario<=9)||Scenario==15||Scenario==16){
     assert(EFI_ERROR(mSmciStatus)&&Calls==6&&!Frees&&Page&&mRecoveryRetained&&mRecoveryWork&&mRecoverySession);
     assert(SecretSnapshot&&!memcmp(SecretSnapshot,Page,TEST_BYTES));
     if(Scenario==15||Scenario==16){
       FKM_CONTEXT *c=&mRecoverySession->Backend;
       assert(c->Fault==7&&c->ResponseHeaderSeen&&SecretCalls==1);
       assert(c->ResponseStatus==(Scenario==15?0xffffffc2U:1));
       assert(c->ResponsePayloadBytes==(Scenario==15?6:0));
       assert(c->ResponseWireBytes<=0xa000&&!c->Handle);
     }
   }
   if(Scenario==10){assert(Calls==6&&!Frees&&Page&&!mRecoveryWork&&!mRecoverySession&&!mRecoveryRetained&&!SecretCalls);}
   if(Scenario==14){assert(!Calls&&!Frees&&!Page&&!mRecoveryWork&&!PoolLive);}
   assert(TaFrees==1&&!TaBuf);
   // Host teardown only: fake allocations/monitor, never a production way out.
   if(Page){munmap(Page,TEST_BYTES);Page=NULL;}
   if(SecretSnapshot){free(SecretSnapshot);SecretSnapshot=NULL;}
   while(PoolLive){free(Pools[--PoolLive].p);}
   mRecoveryWork=NULL;mRecoverySession=NULL;
 }
 puts("PASS 17 recovery entry/session cases; production flow, monitor/filesystem simulated");return 0;
}
