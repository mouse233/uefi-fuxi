// SPDX-License-Identifier: BSD-2-Clause-Patent
// First bring-up: preserve the PHY/clocks left by ABL, then reset the DWC3
// core through the generic driver. This is not a cold-start SM8550 PHY driver.
#include <Library/PlatformUsbfnLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Device/Dwc3.h>
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
EFI_STATUS UsbfnPlatformPhyExit(VOID) { return EFI_SUCCESS; }
BOOLEAN UsbfnPlatformIsVbusPresent(VOID) { return TRUE; }
