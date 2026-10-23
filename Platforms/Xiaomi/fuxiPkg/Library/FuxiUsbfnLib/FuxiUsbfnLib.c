// SPDX-License-Identifier: BSD-2-Clause-Patent
// First bring-up: preserve the PHY/clocks left by ABL, then reset the DWC3
// core through the generic driver. This is not a cold-start SM8550 PHY driver.
#include <Library/PlatformUsbfnLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Device/Dwc3.h>
#include "UsbSmmuAudit.h"
#include "UsbSmmuRoute.h"
STATIC FUR_STATE UsbRoute;
STATIC FUA32 SmmuRead(VOID *Context,FUA32 Offset);
STATIC VOID SmmuWrite(VOID *Context,FUA32 Offset,FUA32 Value);
#define FUXI_DWC3 0x0a600000ULL

EFI_STATUS UsbfnPlatformGetData(USBFN_PLATFORM_DATA *Data) {
  UINT32 Config,Id;
  if(Data==NULL) return EFI_INVALID_PARAMETER;
  ZeroMem(Data,sizeof(*Data));
  Id=MmioRead32(FUXI_DWC3+DWC3_GSNPSID);
  DEBUG((DEBUG_ERROR,"FUXI USB: controller ID %08x at %lx\n",Id,FUXI_DWC3));
  if((Id&DWC3_GSNPSID_MASK)!=DWC3_GSNPSID_USB3 &&
     (Id&DWC3_GSNPSID_MASK)!=DWC3_GSNPSID_USB31) return EFI_UNSUPPORTED;
  Data->ControllerBase=FUXI_DWC3;
  Data->MaximumSpeed=UsbBusSpeedHigh;
  Data->SuperSpeedPhyDisabled=TRUE;
  Config=MmioRead32(FUXI_DWC3+DWC3_GUSB2PHYCFG(0));
  Data->UtmiWidth=(Config&DWC3_GUSB2PHYCFG_PHYIF_MASK)?UsbfnUtmiWidth16Bit:UsbfnUtmiWidth8Bit;
  Data->Usb2FreeClockExists=(BOOLEAN)((Config&DWC3_GUSB2PHYCFG_U2_FREECLK_EXISTS)!=0);
  // Experimental diagnostic identity; not a production VID/PID assignment.
  Data->VendorId=0x1209;Data->ProductId=0x0001;
  return EFI_SUCCESS;
}
EFI_STATUS UsbfnPlatformPhyInit(VOID) {
  UINT32 Id=MmioRead32(FUXI_DWC3+DWC3_GSNPSID);
  UINT32 Phy=MmioRead32(FUXI_DWC3+DWC3_GUSB2PHYCFG(0));
  DEBUG((DEBUG_ERROR,"FUXI USB: inherited SNPS=%08x USB2PHY=%08x\n",Id,Phy));
  if((Id&DWC3_GSNPSID_MASK)!=DWC3_GSNPSID_USB3 &&
     (Id&DWC3_GSNPSID_MASK)!=DWC3_GSNPSID_USB31) return EFI_UNSUPPORTED;
  if(Phy&DWC3_GUSB2PHYCFG_PHYSOFTRST) return EFI_NOT_READY;
  return EFI_SUCCESS;
}
EFI_STATUS UsbfnPlatformPhyExit(VOID) {
  UINT32 Result=FurRemove(SmmuRead,SmmuWrite,NULL,&UsbRoute);
  DEBUG((DEBUG_ERROR,"FUXI USB: route release result=%u restored=%u\n",Result,UsbRoute.RestoreOk));
  return Result==FurOk?EFI_SUCCESS:EFI_DEVICE_ERROR;
}
BOOLEAN UsbfnPlatformIsVbusPresent(VOID) { return TRUE; }

// USB SID and aperture independently confirmed in this unit's saved live DT:
// /soc/ssusb@a600000/dwc3@a600000 iommus=<apps_smmu 0x40 0>.
#define FUXI_APPS_SMMU 0x15000000ULL
STATIC FUA32 SmmuRead(VOID *Context,FUA32 Offset) {
  UINT32 Value;
  (VOID)Context;
  if(Offset>=0x1000) DEBUG((DEBUG_ERROR,"FUXI SMMU: read offset %08x\n",Offset));
  Value=MmioRead32(FUXI_APPS_SMMU+Offset);
  if(Offset==0 || Offset==0x20 || Offset==0x24 || Offset==0x48)
    DEBUG((DEBUG_ERROR,"FUXI SMMU: GR0[%x]=%08x\n",Offset,Value));
  return Value;
}
STATIC VOID SmmuWrite(VOID *Context,FUA32 Offset,FUA32 Value) {
  (VOID)Context;
  DEBUG((DEBUG_ERROR,"FUXI USB ROUTE: write offset=%x value=%08x\n",Offset,Value));
  MmioWrite32(FUXI_APPS_SMMU+Offset,Value);
  MemoryFence();
}
EFI_STATUS FuxiUsbAuditDma(VOID) {
  FUA_REPORT R;
  DEBUG((DEBUG_ERROR,"\fUSBRAM SMMU AUDIT before first DMA; SID=0040 (read only)\n"));
  FuaCapture(SmmuRead,NULL,0x100000,0x40,&R);
  DEBUG((DEBUG_ERROR,"SMMU ID0=%08x ID1=%08x CR0=%08x GFSR=%08x\n",R.Id0,R.Id1,R.Cr0,R.Gfsr));
  DEBUG((DEBUG_ERROR,"SMMU groups=%u scanned=%u matches=%u stored=%u partial=%u unsupported=%u invalidCB=%u\n",
    R.Groups,R.Scanned,R.Matches,R.Stored,R.Partial,R.Unsupported,R.InvalidContext));
  DEBUG((DEBUG_ERROR,"SMMU pageShift=%u CBbase=%08x CBcount=%u\n",R.PageShift,R.ContextBase,R.ContextCount));
  for(UINT32 I=0;I<R.Stored;I++) {
    FUA_MATCH *M=&R.Match[I];
    DEBUG((DEBUG_ERROR,"USB SID0040 slot=%u SMR=%08x S2CR=%08x CB=%u read=%u\n",M->Slot,M->Smr,M->S2cr,M->Context,M->ContextRead));
    if(M->ContextRead) {
      DEBUG((DEBUG_ERROR,"CBAR=%08x CBA2R=%08x SCTLR=%08x TCR=%08x TCR2=%08x\n",M->Cbar,M->Cba2r,M->Sctlr,M->Tcr,M->Tcr2));
      DEBUG((DEBUG_ERROR,"TTBR0=%016lx TTBR1=%016lx FSR=%08x FAR=%016lx\n",M->Ttbr0,M->Ttbr1,M->Fsr,M->Far));
    }
  }
#if FUXI_USB_TRY_SID_ROUTE
  if(R.Matches==0 && !R.Partial && !R.Unsupported && !R.InvalidContext) {
    UINT32 Result=FurInstallViaContext(SmmuRead,SmmuWrite,NULL,&UsbRoute);
    DEBUG((DEBUG_ERROR,"USB CONTEXT existing bank=%u checked=%u CBAR=%08x SCTLR=%08x desiredS2CR=%08x\n",
      UsbRoute.Context,UsbRoute.ContextChecked,UsbRoute.ContextCbar,UsbRoute.ContextSctlr,UsbRoute.DesiredS2cr));
    DEBUG((DEBUG_ERROR,"USB ROUTE result=%u slot=%u SMR=%08x S2CR=%08x active=%u restored=%u\n",
      Result,UsbRoute.Slot,UsbRoute.ObservedSmr,UsbRoute.ObservedS2cr,UsbRoute.Active,UsbRoute.RestoreOk));
    DEBUG((DEBUG_ERROR,"USB ROUTE attempted readback SMR=%08x S2CR=%08x saved=%08x/%08x\n",
      UsbRoute.TestSmr,UsbRoute.TestS2cr,UsbRoute.SavedSmr,UsbRoute.SavedS2cr));
    if(Result==FurOk) {
      DEBUG((DEBUG_ERROR,"USB ROUTE VERIFIED; first DMA permitted (hardware transfer unproven)\n"));
      return EFI_SUCCESS;
    }
  }
#endif
  // Neither a BYPASS encoding nor SCTLR.M=0 proves physical access under a
  // Qualcomm hypervisor. Do not change routes or issue DMA on that assumption.
  DEBUG((DEBUG_ERROR,"USBRAM AUDIT STOP: no STARTTRANSFER issued; retain this screen\n"));
  return EFI_NOT_READY;
}
