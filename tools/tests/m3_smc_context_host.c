// SPDX-License-Identifier: BSD-2-Clause-Patent
#define FUXI_M3_SMC_CONTEXT 1
#define FUXI_M3_SCM_BRIDGE_CALL 1
#define FUXI_M3_SMCI_ROOT 1
#include "DataReadOnly.h"
#include <Library/ArmSmcLib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define FNU_STAGE(N) ((void)(N))
static BOOLEAN mScmAvailable;
static int Calls,Mode;
static void *ZeroMem(void *p,UINTN n){return memset(p,0,n);}
static void FnuLog(CONST CHAR16 *f,...){(void)f;}
VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS *a){
 ++Calls;
 assert(a->Arg0==0x42000601 && a->Arg1==1 && a->Arg2==FDP_SCM_INFO_AVAIL);
 assert(!a->Arg3 && !a->Arg4 && !a->Arg5 && !a->Arg6 && !a->Arg7);
 a->Arg0=Mode==1?1:Mode==2?0xffffffff80000001ULL:0;
 a->Arg1=Mode==3?0:1;
}
#include "M3BridgeDiagnostic.inc"
#include "M3SmcContext.inc"
int main(void){
 Calls=0;mScmAvailable=FALSE;FnuSmcContextProbe(4,0x3c0);assert(Calls==0);
 mScmAvailable=TRUE;
 for(Mode=0;Mode<4;++Mode){Calls=0;FnuSmcContextProbe(4,0x3c0);assert(Calls==1);}
 puts("PASS context INFO control: exact query, no call without fast gate, one call/no retry for 4 responses");return 0;
}
