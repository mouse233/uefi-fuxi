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

// The live DT of this unit describes the high-speed PHY as
// "qcom,usb-snps-eusb2-phy" at 0x88e3000 with a PMIC eUSB2 repeater, so the
// DWC3 UTMI port is driven by an eUSB2 PHY that firmware must initialise.
// Offsets and values follow the upstream qcom-snps-eusb2 driver; the PMIC
// repeater, regulators and ref clock are still inherited from ABL.
#define FUXI_EUSB2_PHY 0x088e3000ULL
// Qualcomm puts the USB wrapper (QSCRATCH) at core_base + 0xF8800; the DWC3
// core itself only starts at +0xC100, so the two do not overlap.
#define FUXI_QSCRATCH 0x0a6f8800ULL
#define FUXI_CORE_PROBE 0x0a600000ULL
STATIC UINT32 PhyPre[16];
STATIC UINT32 PhyPost[16];
STATIC VOID PhySnapshot(UINT32 *V) {
  V[0]=MmioRead32(FUXI_EUSB2_PHY+0x3C);V[1]=MmioRead32(FUXI_EUSB2_PHY+0x50);
  V[2]=MmioRead32(FUXI_EUSB2_PHY+0x54);V[3]=MmioRead32(FUXI_EUSB2_PHY+0x58);
  V[4]=MmioRead32(FUXI_EUSB2_PHY+0x5C);V[5]=MmioRead32(FUXI_EUSB2_PHY+0x60);
  V[6]=MmioRead32(FUXI_EUSB2_PHY+0x64);V[7]=MmioRead32(FUXI_EUSB2_PHY+0x68);
  V[8]=MmioRead32(FUXI_EUSB2_PHY+0x6C);V[9]=MmioRead32(FUXI_EUSB2_PHY+0x70);
  V[10]=MmioRead32(FUXI_EUSB2_PHY+0x78);V[11]=MmioRead32(FUXI_EUSB2_PHY+0x7C);
  V[12]=MmioRead32(FUXI_EUSB2_PHY+0x94);V[13]=MmioRead32(FUXI_EUSB2_PHY+0x98);
  V[14]=MmioRead32(FUXI_EUSB2_PHY+0xB8);V[15]=MmioRead32(FUXI_EUSB2_PHY+0x130);
}
STATIC VOID PhyPrint(CONST CHAR8 *Stage,CONST UINT32 *V) {
  DEBUG((DEBUG_ERROR,"FUXI PHY %a UTMI0=%08x UTMI5=%08x COMMON0=%08x CTL1=%08x CTL2=%08x CTL3=%08x HSCTL2=%08x\n",
    Stage,V[0],V[1],V[2],V[3],V[4],V[5],V[6]));
  DEBUG((DEBUG_ERROR,"FUXI PHY %a CTL4=%08x CTL5=%08x CTL6=%08x CTL8=%08x CTL9=%08x CFG0=%08x CMN0=%08x FSEL=%08x APBCMD=%08x\n",
    Stage,V[7],V[8],V[9],V[10],V[11],V[12],V[13],V[14],V[15]));
  DEBUG((DEBUG_ERROR,"FUXI PHY %a QSCRATCH GEN=%08x HS=%08x SS=%08x core+10=%08x core+30=%08x\n",Stage,
    MmioRead32(FUXI_QSCRATCH+0x08),MmioRead32(FUXI_QSCRATCH+0x10),MmioRead32(FUXI_QSCRATCH+0x30),
    MmioRead32(FUXI_CORE_PROBE+0x10),MmioRead32(FUXI_CORE_PROBE+0x30)));
}
#if defined(FUXI_USB_EUSB2_INIT)
STATIC VOID PhyMask(UINT32 Off,UINT32 Mask,UINT32 Value) {
  UINT32 Reg=(MmioRead32(FUXI_EUSB2_PHY+Off)&~Mask)|(Value&Mask);
  MmioWrite32(FUXI_EUSB2_PHY+Off,Reg);
  (VOID)MmioRead32(FUXI_EUSB2_PHY+Off);
}
// Mirrors qcom_snps_eusb2_hsphy_init for a 19.2 MHz reference clock. It does
// not touch the PMIC repeater, the vdd/vdda12 rails or the ref clock, because
// this firmware has no driver for any of them and ABL leaves them running.
STATIC VOID FuxiEusb2PhyInit(VOID) {
  // The inherited FSEL field selects the reference clock: ABL leaves 4 for the
  // 38.4 MHz source. Pick the matching PLL divider instead of assuming 19.2 MHz.
  UINT32 Fsel=(MmioRead32(FUXI_EUSB2_PHY+0x54)>>4)&7;
  DEBUG((DEBUG_ERROR,"FUXI PHY eUSB2 init sequence applied; inherited FSEL=%u\n",Fsel));
  PhyMask(0x94,1u<<1,1u<<1);
  PhyMask(0x50,1u<<1,1u<<1);
  PhyMask(0x54,(1u<<0)|(1u<<3),(1u<<0)|(1u<<3));
  PhyMask(0x130,1u<<2,1u<<2);
  PhyMask(0x98,1u<<6,0);
  PhyMask(0xB8,1u<<0,1u<<0);
  if(Fsel==4) {
    PhyMask(0x54,0x70,0x40);   // FSEL = 38.4 MHz
    PhyMask(0x5C,0xFF,0xC8);   // PLL FB divider 7:0
    PhyMask(0x60,0x0F,0x00);   // PLL FB divider 11:8
  } else {
    PhyMask(0x54,0x70,0x00);   // FSEL = 19.2 MHz
    PhyMask(0x5C,0xFF,0x90);
    PhyMask(0x60,0x0F,0x01);
  }
  PhyMask(0x60,0xF0,0x00);
  PhyMask(0x58,0xFE,0x00);
  PhyMask(0x68,0xFC,0x20);
  PhyMask(0x68,0x03,0x01);
  PhyMask(0x6C,0x1F,0x10);
  PhyMask(0x70,0x07,0x00);
  PhyMask(0x6C,0xC0,0x40);
  PhyMask(0x64,1u<<4,1u<<4);
  PhyMask(0x7C,0x07,0x00);
  PhyMask(0x7C,0x60,0x40);
  PhyMask(0x7C,0x18,0x08);
  PhyMask(0x78,0x38,0x18);
  PhyMask(0x78,0xC0,0x00);
  PhyMask(0x64,(1u<<3)|(1u<<2),(1u<<3)|(1u<<2));
  PhyMask(0x3C,1u<<0,1u<<0);
  PhyMask(0x54,1u<<1,1u<<1);
  PhyMask(0x54,1u<<2,0);
  PhyMask(0x50,1u<<1,0);
  PhyMask(0x64,1u<<3,0);
  PhyMask(0x94,1u<<1,0);
}
#endif

// Read-only comparison point: lets the bootloader state, which does reach the
// host, be diffed against the state this firmware programs. The bootloader
// values are captured early and reprinted once the link should be up, which is
// late enough that the console scroll has not discarded them yet.
STATIC UINT32 AblSnap[11];
STATIC UINT32 PostSnap[11];
STATIC BOOLEAN AblSnapValid;
STATIC VOID FuxiDwc3Capture(UINT32 *V) {
  V[0]=MmioRead32(FUXI_DWC3+DWC3_GSNPSID);V[1]=MmioRead32(FUXI_DWC3+DWC3_GCTL);
  V[2]=MmioRead32(FUXI_DWC3+DWC3_GUSB2PHYCFG(0));V[3]=MmioRead32(FUXI_DWC3+DWC3_GUSB3PIPECTL(0));
  V[4]=MmioRead32(FUXI_DWC3+DWC3_DCFG);V[5]=MmioRead32(FUXI_DWC3+DWC3_DCTL);
  V[6]=MmioRead32(FUXI_DWC3+DWC3_DSTS);V[7]=MmioRead32(FUXI_DWC3+DWC3_DEVTEN);
  V[8]=MmioRead32(FUXI_DWC3+DWC3_GEVNTADRHI(0));V[9]=MmioRead32(FUXI_DWC3+DWC3_GEVNTADRLO(0));
  V[10]=MmioRead32(FUXI_DWC3+DWC3_GEVNTSIZ(0));
}
// The Qualcomm wrapper shares the DWC3 window at low offsets. In device mode
// dwc3-qcom overrides the VBUS and session signals in software; without it the
// controller runs but never presents a connection to the host.
STATIC VOID FuxiVbusOverride(VOID) {
  UINT32 Hs,Ss;
  Hs=MmioRead32(FUXI_QSCRATCH+0x10)|(1u<<20)|(1u<<28);
  MmioWrite32(FUXI_QSCRATCH+0x10,Hs);(VOID)MmioRead32(FUXI_QSCRATCH+0x10);
  Ss=MmioRead32(FUXI_QSCRATCH+0x30)|(1u<<24);
  MmioWrite32(FUXI_QSCRATCH+0x30,Ss);(VOID)MmioRead32(FUXI_QSCRATCH+0x30);
  DEBUG((DEBUG_ERROR,"FUXI USB: qscratch vbus/session override HS=%08x SS=%08x\n",Hs,Ss));
}
STATIC VOID FuxiDwc3Print(CONST CHAR8 *Stage,CONST UINT32 *V) {
  DEBUG((DEBUG_ERROR,
    "FUXI SNAP %a GSNPSID=%08x GCTL=%08x PHYCFG=%08x PIPECTL=%08x DCFG=%08x DCTL=%08x DSTS=%08x DEVTEN=%08x EVTADR=%08x%08x EVTSIZ=%08x EVTCNT=%u\n",
    Stage,V[0],V[1],V[2],V[3],V[4],V[5],V[6],V[7],V[8],V[9],V[10],
    MmioRead32(FUXI_DWC3+DWC3_GEVNTCOUNT(0))&DWC3_GEVNTCOUNT_MASK));
}

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
  FuxiDwc3Capture(AblSnap);AblSnapValid=TRUE;FuxiDwc3Print("ABL",AblSnap);
  PhySnapshot(PhyPre);
#if defined(FUXI_USB_EUSB2_INIT)
  FuxiEusb2PhyInit();
#endif
  PhySnapshot(PhyPost);
  FuxiVbusOverride();
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
  FuxiDwc3Capture(PostSnap);
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
      DEBUG((DEBUG_ERROR,"USB ROUTE baseline GFSR=%08x (install raised no fault)\n",
        MmioRead32(FUXI_APPS_SMMU+0x48)));
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
// Prints both snapshots. Called once the link should be up, because the console
// keeps only the most recent screen and earlier lines are overwritten.
VOID FuxiUsbSnapshotReport(VOID) {
  PhyPrint("PRE",PhyPre);
  PhyPrint("POST",PhyPost);
  if(AblSnapValid) FuxiDwc3Print("ABL",AblSnap);
  FuxiDwc3Print("POST",PostSnap);
}
// Read-only failure snapshot: separates "this stream still aborts" from a
// controller-side rejection. It writes nothing and does not clear any fault.
VOID FuxiUsbFaultReport(VOID) {
  UINT32 Id1=MmioRead32(FUXI_APPS_SMMU+0x24);
  UINT32 Shift=(Id1&(1u<<31))?16:12;
  DEBUG((DEBUG_ERROR,"USB FAULT GFSR=%08x GFSYNR0=%08x GFSYNR1=%08x GFSYNR2=%08x\n",
    MmioRead32(FUXI_APPS_SMMU+0x48),MmioRead32(FUXI_APPS_SMMU+0x50),
    MmioRead32(FUXI_APPS_SMMU+0x54),MmioRead32(FUXI_APPS_SMMU+0x58)));
  DEBUG((DEBUG_ERROR,"USB FAULT slot=%u SMR=%08x S2CR=%08x active=%u ctx=%u\n",
    UsbRoute.Slot,MmioRead32(FUXI_APPS_SMMU+0x800+4*UsbRoute.Slot),
    MmioRead32(FUXI_APPS_SMMU+0xc00+4*UsbRoute.Slot),UsbRoute.Active,UsbRoute.Context));
  if(UsbRoute.ContextChecked) {
    UINT32 Cb=UsbRoute.ContextBase;
    DEBUG((DEBUG_ERROR,"USB FAULT ctx=%u SCTLR=%08x CBAR=%08x FSR=%08x FAR=%08x%08x\n",
      UsbRoute.Context,MmioRead32(FUXI_APPS_SMMU+Cb),
      MmioRead32(FUXI_APPS_SMMU+(1u<<Shift)+4*UsbRoute.Context),
      MmioRead32(FUXI_APPS_SMMU+Cb+0x58),MmioRead32(FUXI_APPS_SMMU+Cb+0x64),
      MmioRead32(FUXI_APPS_SMMU+Cb+0x60)));
  }
}
