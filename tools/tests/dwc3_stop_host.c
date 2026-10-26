// Production stop transaction under simulated MMIO. No hardware claims.
#include <assert.h>
#include <stdio.h>
#include <string.h>
#undef NULL
#include <Uefi.h>
#include "Dwc3Stop.c"

static DWC3_DEV Dev;
static UINT32 Dctl, Count, EndMask;
static unsigned Ends, Acks, CoreExits, RouteExits, Stalls;
static BOOLEAN Halted, NeverHalt, RejectEnd, RejectRoute, BadCount;

static EFI_STATUS EFIAPI Stall (UINTN Us) {
  assert (Us == 1);
  Stalls++;
  return EFI_SUCCESS;
}
static EFI_BOOT_SERVICES Services = { .Stall = Stall };
EFI_BOOT_SERVICES *gBS = &Services;

UINT32 EFIAPI MmioRead32 (UINTN Address) {
  if (Address == DWC3_DCTL) { return Dctl; }
  if (Address == DWC3_GEVNTCOUNT (0)) { return BadCount ? 8192 : Count; }
  assert (Address == DWC3_DSTS);
  if (!(Dctl & DWC3_DCTL_RUN_STOP) && Count == 0 && !NeverHalt) {
    Halted = TRUE;
  }
  return Halted ? DWC3_DSTS_DEVCTRLHLT : 0;
}
UINT32 EFIAPI MmioWrite32 (UINTN Address, UINT32 Value) {
  if (Address == DWC3_DCTL) {
    assert (Ends == 2 || RejectEnd || EndMask != 0 || !Dev.Endpoints[0].TransferStarted);
    Dctl = Value;
  } else {
    assert (Address == DWC3_GEVNTCOUNT (0));
    assert (Value <= Count && Value % 4 == 0);
    Count -= Value;
    Acks++;
  }
  return Value;
}
EFI_STATUS Dwc3SendEpCommand (DWC3_DEV *Device, UINT8 Ep, UINT32 Command,
                            UINT32 P0, UINT32 P1, UINT32 P2, UINT32 *Result) {
  assert (Device == &Dev && Dev.Stopping && !Halted);
  assert (DWC3_DEPCMD_CMD (Command) == DWC3_DEPCMD_ENDTRANSFER);
  assert ((Command & (DWC3_DEPCMD_HIPRI_FORCERM | DWC3_DEPCMD_CMDIOC)) ==
          (DWC3_DEPCMD_HIPRI_FORCERM | DWC3_DEPCMD_CMDIOC));
  assert (DWC3_DEPCMD_GET_RSC_IDX (Command) == Dev.Endpoints[Ep].ResourceIndex);
  assert (P0 == 0 && P1 == 0 && P2 == 0 && Result == NULL);
  assert ((EndMask & (1U << Ep)) == 0);
  EndMask |= 1U << Ep;
  Ends++;
  if (RejectEnd) { return EFI_DEVICE_ERROR; }
  Count += 4;
  return EFI_SUCCESS;
}
VOID Dwc3CoreExit (DWC3_DEV *Device) {
  assert (Device == &Dev && Halted && Count == 0);
  assert (!Dev.Endpoints[0].TransferStarted && !Dev.Endpoints[2].TransferStarted);
  assert (!Dev.Endpoints[0].Enabled && !Dev.Endpoints[2].Enabled);
  CoreExits++;
}
EFI_STATUS UsbfnPlatformPhyExit (VOID) {
  assert (Halted && CoreExits == 1);
  RouteExits++;
  return RejectRoute ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static void Init (void) {
  memset (&Dev, 0, sizeof (Dev));
  Dctl = DWC3_DCTL_RUN_STOP;
  Count = EndMask = Ends = Acks = CoreExits = RouteExits = Stalls = 0;
  Halted = NeverHalt = RejectEnd = RejectRoute = BadCount = FALSE;
  Dev.Signature = DWC3_DEV_SIGNATURE;
  Dev.Started = TRUE;
  Dev.NumPhysicalEps = 4;
  Dev.EventPos = DWC3_EVENT_BUFFER_SIZE - 4;
  Dev.Endpoints[0].Enabled = Dev.Endpoints[2].Enabled = TRUE;
  Dev.Endpoints[0].TransferStarted = Dev.Endpoints[2].TransferStarted = TRUE;
  Dev.Endpoints[0].ResourceIndex = 0;
  Dev.Endpoints[2].ResourceIndex = 3;
}
int main (void) {
  assert (Dwc3StopController (NULL) == EFI_INVALID_PARAMETER);
  puts ("PASS null protocol rejected");
  Init ();
  assert (Dwc3StopController (&Dev.UsbfnIo) == EFI_SUCCESS);
  assert (Ends == 2 && Acks == 1 && Halted && CoreExits == 1 && RouteExits == 1);
  assert (!Dev.Started && !Dev.Stopping && Dev.EventPos == 4);
  puts ("PASS OUT resource zero and Bulk END precede halt; drain permits halt; route released last");
  assert (Dwc3StopController (&Dev.UsbfnIo) == EFI_SUCCESS && RouteExits == 1);
  puts ("PASS completed stop is idempotent");
  Init ();
  Dev.Endpoints[0].EndTransferPending = TRUE;
  Count = 4;
  EndMask = 1;
  assert (Dwc3StopController (&Dev.UsbfnIo) == EFI_SUCCESS && Ends == 1);
  puts ("PASS an already pending END is not resubmitted");
  Init ();
  RejectEnd = TRUE;
  assert (Dwc3StopController (&Dev.UsbfnIo) == EFI_DEVICE_ERROR);
  assert (Dctl & DWC3_DCTL_RUN_STOP);
  assert (Dev.Started && Dev.Stopping && Dev.Endpoints[0].TransferStarted);
  assert (CoreExits == 0 && RouteExits == 0);
  assert (Dwc3StopController (&Dev.UsbfnIo) == EFI_NOT_READY && Ends == 1);
  puts ("PASS END rejection preserves DMA ownership and route; no uncertain END retry");
  Init ();
  NeverHalt = TRUE;
  assert (Dwc3StopController (&Dev.UsbfnIo) == EFI_TIMEOUT);
  assert (Stalls == DWC3_RUNSTOP_TIMEOUT_US && Dev.Started && Dev.Stopping);
  assert (Dev.Endpoints[0].TransferStarted && CoreExits == 0 && RouteExits == 0);
  puts ("PASS bounded halt timeout retains buffers and route");
  Init ();
  BadCount = TRUE;
  assert (Dwc3StopController (&Dev.UsbfnIo) == EFI_DEVICE_ERROR);
  assert (CoreExits == 0 && RouteExits == 0 && Acks == 0);
  puts ("PASS malformed event count refuses cleanup");
  Init ();
  Count = DWC3_EVENT_BUFFER_SIZE;
  Dev.Endpoints[0].TransferStarted = Dev.Endpoints[2].TransferStarted = FALSE;
  assert (Dwc3StopController (&Dev.UsbfnIo) == EFI_SUCCESS);
  assert (Dev.EventPos == DWC3_EVENT_BUFFER_SIZE - 4 && Acks == 1 && Ends == 0);
  puts ("PASS full ring drained with correct wrap and no synthetic endpoint commands");
  Init ();
  RejectRoute = TRUE;
  assert (Dwc3StopController (&Dev.UsbfnIo) == EFI_DEVICE_ERROR);
  assert (!Dev.Started && Dev.Stopping && CoreExits == 1 && RouteExits == 1);
  RejectRoute = FALSE;
  assert (Dwc3StopController (&Dev.UsbfnIo) == EFI_SUCCESS);
  assert (!Dev.Stopping && CoreExits == 1 && RouteExits == 2);
  puts ("PASS failed route release remains an error; retry only repeats checked rollback");
  return 0;
}
