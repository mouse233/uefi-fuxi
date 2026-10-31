// SPDX-License-Identifier: BSD-2-Clause-Patent
int main(void){
 for(RootMode=0;RootMode<32;++RootMode){
  Calls=Frees=TaFrees=LogCalls=RootConfigs=RootQueries=0;
  Phase=RootMode==31?99:RootMode==30?6:0;Fault=RootMode==30?13:0;
  Special=ResumeTarget=ResumeCalls=ResumePending=0;
  mReady=RootMode==26;mPoisoned=FALSE;
  mRootTrustBatchStarted=mRootTrustVersionOk=mRootTrustConfigureSent=mRootTrustConfigured=mRootTrustQuerySent=FALSE;
  assert(!Page&&!TaBuf&&!RootSnapshot&&!RootPending);
  memset(&Report,0,sizeof(Report));
  for(int i=0;i<128;++i)FnuReportAppend(&Report,L"synthetic pre-M3 baseline");
  SetupTa();FnuSmciRootProbe();
  assert(TaFrees==1&&!TaBuf&&!mTaImage);
  assert(!Report.Dropped&&!Report.Truncated&&Report.Count==(UINTN)(128+LogCalls));
  int success=RootMode<=4||RootMode==27;
  if(success){assert(mSmciStatus==EFI_SUCCESS&&Calls==10&&Frees==1&&!Page&&RootConfigs==1&&RootQueries==(RootMode==27?2:1));}
  else{
   assert(EFI_ERROR(mSmciStatus)&&!Frees);
   if(RootMode==26||RootMode==31){assert(!Calls&&!Page&&!RootConfigs&&!RootQueries);}
   else{assert(Calls==6&&Page);if(RootSnapshot)assert(!memcmp(RootSnapshot,Page,TEST_BYTES));}
   if((RootMode>=23&&RootMode<=26)||RootMode>=30)assert(!RootQueries);
  }
  if(RootMode==28)assert(RootQueries==9);
  if(RootMode==29)assert(RootQueries==2);
  if(Page){munmap(Page,TEST_BYTES);Page=NULL;} // fake allocations only
  if(RootSnapshot){free(RootSnapshot);RootSnapshot=NULL;}
  if(RootPending){free(RootPending);RootPending=NULL;}
 }
 puts("PASS 32 ROOTCTX production session cases; query-only, snapshot retention, simulated monitor");return 0;
}
