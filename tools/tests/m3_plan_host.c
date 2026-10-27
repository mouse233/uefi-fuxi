// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "M3DefaultKeyPlan.h"
#include <assert.h>
#include <stdio.h>

static void rejected(const FDP_DISK *disk, const FDP_PARTITION *part,
                     const FDM_MAPPING *map, UINT64 sector, UINT64 count,
                     EFI_STATUS expected) {
  FDM_PLAN plan = { 111, 222, 333 };
  assert(FdmPlanMetadataRead(disk,part,map,sector,count,&plan)==expected);
  assert(plan.DiskLba==0 && plan.FirstDun==0 && plan.Blocks==0);
}

int main(void) {
  FDP_DISK disk = {0}; FDP_PARTITION part = {100, 199, TRUE};
  FDM_MAPPING map = {16, 400, 24, 40, 4096, TRUE, TRUE, TRUE, TRUE};
  FDM_MAPPING bad; FDP_PARTITION p; FDM_PLAN result;
  disk.BlockSize=4096; disk.LastBlock=999;
  // target offset=16 sectors, backing offset=24 sectors; IV offset=40
  // sectors. The physical partition base is not included in the DUN.
  assert(FdmPlanMetadataRead(&disk,&part,&map,32,24,&result)==EFI_SUCCESS);
  assert(result.DiskLba==105 && result.FirstDun==7 && result.Blocks==3);
  assert(FdmPlanMetadataRead(&disk,&part,&map,408,8,&result)==EFI_SUCCESS);
  assert(result.DiskLba==152 && result.FirstDun==54 && result.Blocks==1);
  rejected(&disk,&part,&map,408,16,EFI_INVALID_PARAMETER);
  rejected(&disk,&part,&map,8,8,EFI_INVALID_PARAMETER);
  rejected(&disk,&part,&map,17,8,EFI_INVALID_PARAMETER);
  rejected(&disk,&part,&map,16,0,EFI_INVALID_PARAMETER);
  rejected(&disk,&part,&map,16,9,EFI_INVALID_PARAMETER);
  bad=map; bad.MappingVerified=FALSE; rejected(&disk,&part,&bad,16,8,EFI_UNSUPPORTED);
  bad=map; bad.WrappedKeyV0=FALSE; rejected(&disk,&part,&bad,16,8,EFI_UNSUPPORTED);
  bad=map; bad.Aes256Xts=FALSE; rejected(&disk,&part,&bad,16,8,EFI_UNSUPPORTED);
  bad=map; bad.IvLargeSectors=FALSE; rejected(&disk,&part,&bad,16,8,EFI_UNSUPPORTED);
  bad=map; bad.CryptoUnitBytes=512; rejected(&disk,&part,&bad,16,8,EFI_UNSUPPORTED);
  bad=map; bad.DeviceStart512=25; rejected(&disk,&part,&bad,16,8,EFI_INVALID_PARAMETER);
  bad=map; bad.IvOffset512=41; rejected(&disk,&part,&bad,16,8,EFI_INVALID_PARAMETER);
  bad=map; bad.TargetLength512=0; rejected(&disk,&part,&bad,16,8,EFI_INVALID_PARAMETER);
  bad=map; bad.TargetLength512=800; rejected(&disk,&part,&bad,16,8,EFI_INVALID_PARAMETER);
  bad=map; bad.TargetBegin512=MAX_UINT64-7; bad.TargetLength512=16;
  rejected(&disk,&part,&bad,MAX_UINT64-7,8,EFI_INVALID_PARAMETER);
  bad=map; bad.IvOffset512=MAX_UINT64-7; rejected(&disk,&part,&bad,16,8,EFI_INVALID_PARAMETER);
  p=part; p.Last=1000; rejected(&disk,&p,&map,16,8,EFI_INVALID_PARAMETER);
  p=part; p.Present=FALSE; rejected(&disk,&p,&map,16,8,EFI_INVALID_PARAMETER);
  assert(FdmPlanMetadataRead(&disk,&part,&map,16,8,NULL)==EFI_INVALID_PARAMETER);
  // Geometry observed through sanitized TWRP DM status and UEFI GPT. This
  // exercises only arithmetic; it does not establish key access or plaintext.
  disk.LastBlock=0x3afc3ff; p.First=0x2f7840; p.Last=0x3afc3fa; p.Present=TRUE;
  bad=(FDM_MAPPING){0,469917144,0,0,4096,TRUE,TRUE,TRUE,TRUE};
  assert(FdmPlanMetadataRead(&disk,&p,&bad,0,8,&result)==EFI_SUCCESS);
  assert(result.DiskLba==0x2f7840 && result.FirstDun==0 && result.Blocks==1);
  assert(FdmPlanMetadataRead(&disk,&p,&bad,469917136,8,&result)==EFI_SUCCESS);
  assert(result.DiskLba==0x3afc3fa && result.FirstDun==58739642 && result.Blocks==1);
  rejected(&disk,&p,&bad,469917136,16,EFI_INVALID_PARAMETER);
  puts("M3 metadata mapping planner: all cases passed");
  return 0;
}
