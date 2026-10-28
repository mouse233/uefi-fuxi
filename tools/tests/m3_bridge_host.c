// SPDX-License-Identifier: BSD-2-Clause-Patent
// Host vectors for the scalar SMC64 builders; no device, SMC or key material.
#include "DataReadOnly.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void expect(const char *name, int ok) {
  if (!ok) printf("FAIL %s\n", name);
  assert(ok);
}

int main(void) {
  UINT64 Args[8], Regs[8];
  UINT64 Handle = 0xdeadbeefU;
  FDP_SCM64_CALL Call;

  // The already-proven INFO form must not change.
  assert(FdpMakeAvailabilityQuery(FDP_SCM_INFO_AVAIL, TRUE, Args) == EFI_SUCCESS);
  expect("info fnid", Args[0] == 0xc2000601ULL);
  expect("info arginfo", Args[1] == 1);
  expect("info subject", Args[2] == FDP_SCM_INFO_AVAIL);
  expect("info unused", Args[3] == 0 && Args[7] == 0);

  assert(FdpBuildBridgeEnable(Regs) == EFI_SUCCESS);
  expect("enable fnid", Regs[0] == 0x42000c1cULL);
  expect("enable arginfo", Regs[1] == 0);
  expect("enable args", Regs[2] == 0 && Regs[5] == 0 && Regs[7] == 0);

  assert(FdpBuildBridgeDelete(0x1234, Regs) == EFI_SUCCESS);
  expect("delete fnid", Regs[0] == 0x42000c1dULL);
  expect("delete arginfo", Regs[1] == 1);
  expect("delete handle", Regs[2] == 0x1234);

  memset(Regs, 0xff, sizeof(Regs));
  assert(FdpBuildBridgeCreate(0x10000000ULL, 4096, 0, 0, Regs) == EFI_SUCCESS);
  expect("create fnid", Regs[0] == 0x42000c1eULL);
  expect("create arginfo", Regs[1] == 4);
  expect("create base", Regs[2] == 0x10000000ULL);
  expect("create base+flags", Regs[3] == 0x10000006ULL);
  expect("create size", Regs[4] == 4096);
  expect("create vmid", Regs[5] == 0);
  expect("create tail", Regs[6] == 0 && Regs[7] == 0);

  assert(FdpBuildBridgeCreate(0x20000000ULL, 0x2000, 1, 0x0042, Regs) == EFI_SUCCESS);
  expect("vm count bit9", Regs[4] == (0x2000ULL | (1ULL << 9)));
  expect("vmid bits", Regs[5] == 0x0042);

  expect("create rejects unaligned", FdpBuildBridgeCreate(0x10000001ULL, 4096, 0, 0, Regs) == EFI_INVALID_PARAMETER);
  expect("create rejects zero size", FdpBuildBridgeCreate(0x10000000ULL, 0, 0, 0, Regs) == EFI_INVALID_PARAMETER);
  expect("create rejects odd size", FdpBuildBridgeCreate(0x10000000ULL, 0x1001, 0, 0, Regs) == EFI_INVALID_PARAMETER);
  expect("create rejects vms", FdpBuildBridgeCreate(0x10000000ULL, 4096, 5, 0, Regs) == EFI_INVALID_PARAMETER);
  expect("create rejects null", FdpBuildBridgeCreate(0x10000000ULL, 4096, 0, 0, NULL) == EFI_INVALID_PARAMETER);
  expect("enable rejects null", FdpBuildBridgeEnable(NULL) == EFI_INVALID_PARAMETER);
  expect("delete rejects null", FdpBuildBridgeDelete(1, NULL) == EFI_INVALID_PARAMETER);

  assert(FdpBuildBridgeCreateHlos(0x10000000ULL,8192,Regs)==EFI_SUCCESS);
  expect("HLOS standard fnid", Regs[0]==0x42000c1eULL && Regs[1]==4);
  expect("HLOS NS permission6", Regs[2]==0x10000006ULL);
  expect("HLOS secure permission6", Regs[3]==0x10000006ULL);
  expect("HLOS one VM", Regs[4]==0x2200);
  expect("HLOS VMID3", Regs[5]==3 && Regs[6]==0 && Regs[7]==0);
  expect("HLOS rejects alignment", FdpBuildBridgeCreateHlos(0x10000001ULL,8192,Regs)==EFI_INVALID_PARAMETER);
  expect("HLOS rejects null", FdpBuildBridgeCreateHlos(0x10000000ULL,8192,NULL)==EFI_INVALID_PARAMETER);

  // Generic builder: scalar path only, at most four arguments.
  memset(&Call, 0, sizeof(Call));
  Call.Svc = 0x0c; Call.Cmd = 0x1e; Call.ArgCount = 2;
  Call.Args[0] = 0x11; Call.Args[1] = 0x22; Call.Args[2] = 0x33;
  assert(FdpBuildScm64(&Call, Regs) == EFI_SUCCESS);
  expect("generic fnid", Regs[0] == 0x42000c1eULL);
  expect("generic count", Regs[1] == 2);
  expect("generic args", Regs[2] == 0x11 && Regs[3] == 0x22 && Regs[4] == 0);
  Call.ArgCount = 5;
  expect("generic rejects five", FdpBuildScm64(&Call, Regs) == EFI_INVALID_PARAMETER);
  Call.ArgCount = 1; Call.Svc = 0x100;
  expect("generic rejects svc", FdpBuildScm64(&Call, Regs) == EFI_INVALID_PARAMETER);
  Call.Svc = 0x0c; Call.Cmd = 0x100;
  expect("generic rejects cmd", FdpBuildScm64(&Call, Regs) == EFI_INVALID_PARAMETER);
  expect("generic rejects null", FdpBuildScm64(NULL, Regs) == EFI_INVALID_PARAMETER);

  expect("decode success", FdpDecodeBridgeCreate(0, 0, 0x100000055ULL, &Handle) == EFI_SUCCESS && Handle == 0x100000055ULL);
  expect("decode busy", FdpDecodeBridgeCreate(1, 0, 0x55, &Handle) == EFI_NOT_READY);
  expect("decode null", FdpDecodeBridgeCreate(0, 0, 1, NULL) == EFI_INVALID_PARAMETER);
  expect("reject old observed tuple", FdpDecodeBridgeCreate(0, 0x5c, 0, &Handle) == EFI_NOT_READY && Handle == 0);
  expect("reject service error", FdpDecodeBridgeCreate(0, 1, 0x55, &Handle) == EFI_NOT_READY);
  expect("reject zero handle", FdpDecodeBridgeCreate(0, 0, 0, &Handle) == EFI_NOT_READY);
  printf("PASS scalar SMC64 builders\n");
  return 0;
}
