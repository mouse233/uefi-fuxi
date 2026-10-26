// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <assert.h>
#include <stdio.h>
#include <string.h>
#undef NULL
#include "DataReadOnly.h"
static UINTN Calls;static BOOLEAN Change,Fail;
static EFI_STATUS Read(VOID *Context,UINT64 Lba,UINTN Blocks,VOID *Buffer) {
  (void)Context;assert(Lba==8 && Blocks==1);++Calls;
  if(Fail && Calls==2) return EFI_TIMEOUT;
  memset(Buffer,Change && Calls==2?0x43:0x42,4096);return EFI_SUCCESS;
}
int main(void) {
  FDP_DISK Disk={NULL,Read,4096,255};FDP_PARTITION Part={8,15,TRUE};
  UINT8 First[4096],Repeat[4096];UINTN Done;
  assert(FdpVerifyPartitionRead(&Disk,&Part,0,1,First,Repeat,4096,3,&Done)==EFI_SUCCESS && Done==3 && Calls==3);
  puts("PASS three independent reads into disjoint buffers");
  Calls=0;Change=TRUE;
  assert(FdpVerifyPartitionRead(&Disk,&Part,0,1,First,Repeat,4096,3,&Done)==EFI_CRC_ERROR && Done==2 && Calls==2);
  puts("PASS mismatch stops before a third read");
  Calls=0;Change=FALSE;Fail=TRUE;
  assert(FdpVerifyPartitionRead(&Disk,&Part,0,1,First,Repeat,4096,3,&Done)==EFI_TIMEOUT && Done==1 && Calls==2);
  puts("PASS transport error is propagated without retry");
  Calls=0;
  assert(FdpVerifyPartitionRead(&Disk,&Part,0,1,First,First,4096,3,&Done)==EFI_INVALID_PARAMETER && Calls==0);
  assert(FdpVerifyPartitionRead(&Disk,&Part,0,1,First,Repeat,4095,3,&Done)==EFI_INVALID_PARAMETER && Calls==0);
  assert(FdpVerifyPartitionRead(&Disk,&Part,8,1,First,Repeat,4096,3,&Done)==EFI_BAD_BUFFER_SIZE && Calls==0);
  assert(FdpVerifyPartitionRead(&Disk,&Part,0,1,First,Repeat,4096,9,&Done)==EFI_INVALID_PARAMETER && Calls==0);
  puts("PASS alias, capacity, partition boundary and sample budget rejected before IO");
  return 0;
}
