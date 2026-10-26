// Execute the production endpoint driver with simulated MMIO, not USB hardware.
#include <assert.h>
#include <stdio.h>
#include <string.h>
#undef NULL
#include <Uefi.h>
#include "Dwc3Endpoint.c"
#include "Dwc3Stop.c"

static UINT32 Registers[0x10000 / sizeof (UINT32)];
static BOOLEAN Active[DWC3_MAX_PHYSICAL_EP];
static unsigned Ends, StaleEnds, Configs, RejectedStarts, CommandWrites;
static UINT32 PendingEnds;
static UINT8 TestRing[DWC3_EVENT_BUFFER_SIZE];
static BOOLEAN RejectEnd;
static BOOLEAN TimeoutEnd;
static DWC3_DEV Dev;
static DWC3_TRB Trbs[DWC3_MAX_PHYSICAL_EP][DWC3_TRB_PER_EP];
static UINT8 SetupBuffer[DWC3_EP0_BOUNCE_SIZE];

VOID *EFIAPI CopyMem (VOID *To, CONST VOID *From, UINTN Size) {
  return memcpy (To, From, Size);
}

VOID *EFIAPI ZeroMem (VOID *Buffer, UINTN Size) {
  return memset (Buffer, 0, Size);
}

VOID *EFIAPI InvalidateDataCacheRange (VOID *Buffer, UINTN Size) {
  (void)Size;
  return Buffer;
}

static EFI_STATUS EFIAPI Stall (UINTN Microseconds) {
  (void)Microseconds;
  return EFI_SUCCESS;
}

static EFI_BOOT_SERVICES Services = { .Stall = Stall };
EFI_BOOT_SERVICES *gBS = &Services;

UINT32 EFIAPI MmioRead32 (UINTN Address) {
  assert (Address < sizeof (Registers) && (Address % 4) == 0);
  return Registers[Address / 4];
}

UINT32 EFIAPI MmioWrite32 (UINTN Address, UINT32 Value) {
  UINT32 Command, Result = 0;
  UINTN Ep;
  assert (Address < sizeof (Registers) && (Address % 4) == 0);
  if (Address >= DWC3_DEP_BASE (0) &&
      Address < DWC3_DEP_BASE (DWC3_MAX_PHYSICAL_EP) &&
      (Address & 0xF) == DWC3_DEPCMD) {
    Ep = (Address - DWC3_DEP_BASE (0)) / 0x10;
    Command = DWC3_DEPCMD_CMD (Value);
    CommandWrites++;
    if (Command == DWC3_DEPCMD_STARTTRANSFER) {
      if (Active[Ep]) {
        RejectedStarts++;
        Result = BIT12; // command status 1: no resource
      } else {
        Active[Ep] = TRUE;
        Result = DWC3_DEPCMD_PARAM (Ep); // observed EP0 OUT=0, IN=1
      }
    } else if (Command == DWC3_DEPCMD_ENDTRANSFER) {
      Ends++;
      if (!Active[Ep] || DWC3_DEPCMD_GET_RSC_IDX (Value) != Ep) {
        StaleEnds++;
        Result = BIT12;
      }
      if (RejectEnd) {
        Result = BIT12;
      } else if (!TimeoutEnd) {
        PendingEnds |= (UINT32)1 << Ep;
      }
    } else if (Command == DWC3_DEPCMD_DEPSTARTCFG ||
               Command == DWC3_DEPCMD_SETTRANSFRESOURCE) {
      Configs++;
    }
    Registers[Address / 4] = (TimeoutEnd && Command == DWC3_DEPCMD_ENDTRANSFER) ?
                            Value : Command | Result;
  } else {
    Registers[Address / 4] = Value;
  }
  return Value;
}

static void Init (void) {
  memset (&Dev, 0, sizeof (Dev));
  memset (Registers, 0, sizeof (Registers));
  memset (Trbs, 0, sizeof (Trbs));
  memset (Active, 0, sizeof (Active));
  Ends = StaleEnds = Configs = RejectedStarts = CommandWrites = 0;
  PendingEnds = 0;
  RejectEnd = FALSE;
  TimeoutEnd = FALSE;
  Dev.Started = TRUE;
  Dev.NumPhysicalEps = 2;
  Dev.Ep0Buffer = SetupBuffer;
  Dev.Ep0BufferPhys = (UINTN)SetupBuffer;
  for (UINTN Ep = 0; Ep < 2; Ep++) {
    Dev.Endpoints[Ep].Enabled = TRUE;
    Dev.Endpoints[Ep].TrbPool = Trbs[0]; // production EP0 IN/OUT share one TRB pool
    Dev.Endpoints[Ep].TrbPoolPhys = (UINTN)Trbs[0];
    Dev.Endpoints[Ep].MaxPacketSize = 64;
  }
  assert (Dwc3Ep0OutStart (&Dev) == EFI_SUCCESS);
}

static void CompleteEnd (UINT8 Ep) {
  assert ((PendingEnds & ((UINT32)1 << Ep)) != 0);
  PendingEnds &= ~((UINT32)1 << Ep);
  Active[Ep] = FALSE;
  Dwc3HandleEpEvent (&Dev, (DWC3_DEPCMD_ENDTRANSFER << 24) |
                          (DWC3_DEPEVT_EPCMDCMPLT << 6) | (Ep << 1));
}

static void DrainEnds (void) {
  for (UINT8 Ep = 0; Ep < 2; Ep++) {
    if ((PendingEnds & ((UINT32)1 << Ep)) != 0) {
      CompleteEnd (Ep);
    }
  }
}

static void Event (UINT8 Ep, UINT8 Type, UINT8 Status) {
  if (Type == DWC3_DEPEVT_XFERCOMPLETE) {
    assert (Active[Ep]);
    Active[Ep] = FALSE; // hardware retires the resource before notifying software
    Dev.Endpoints[Ep].TrbPool[0].Control &= ~DWC3_TRB_CTRL_HWO;
    Dev.Endpoints[Ep].TrbPool[0].Size = 0;
  }
  Dwc3HandleEpEvent (&Dev, ((UINT32)Status << 12) | ((UINT32)Type << 6) | (Ep << 1));
}

static void Setup (UINT8 RequestType, UINT8 Request, UINT16 Length) {
  EFI_USB_DEVICE_REQUEST Packet = { .RequestType = RequestType,
                                   .Request = Request, .Length = Length };
  memcpy (SetupBuffer, &Packet, sizeof (Packet));
  Event (0, DWC3_DEPEVT_XFERCOMPLETE, DEPEVT_STATUS_IOC | DEPEVT_STATUS_LST);
  assert (!Dev.Endpoints[0].TransferStarted);
  assert (Dev.Endpoints[0].ResourceIndex == 0);
}

static void ThreeStage (BOOLEAN In) {
  UINT8 DataEp = In ? 1 : 0;
  UINT8 StatusEp = In ? 0 : 1;
  Init ();
  Setup (In ? 0xC0 : 0x40, 0x55, 18);
  assert (Dev.Ep0State == Dwc3Ep0StateData);
  assert (Dwc3StartTransfer (&Dev, DataEp, (UINTN)SetupBuffer, 18,
                             DWC3_TRBCTL_CONTROL_DATA) == EFI_SUCCESS);
  Dev.Endpoints[DataEp].TransferTrbLength = 18;
  Event (DataEp, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_DATA);
  assert (Dev.Endpoints[DataEp].TransferStarted);
  assert (Dev.Endpoints[DataEp].ResourceIndex == DataEp);
  Event (DataEp, DWC3_DEPEVT_XFERCOMPLETE, DEPEVT_STATUS_IOC | DEPEVT_STATUS_LST);
  assert (Dev.Endpoints[DataEp].ResourceIndex == 0);
  Event (StatusEp, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  assert (Dev.Ep0StatusStarted && Active[StatusEp]);
  assert ((Dev.Endpoints[StatusEp].TrbPool[0].Control & DWC3_TRB_CTRL_TRBCTL (0x3F)) ==
          DWC3_TRBCTL_CONTROL_STATUS3);
  Event (StatusEp, DWC3_DEPEVT_XFERCOMPLETE, DEPEVT_STATUS_IOC | DEPEVT_STATUS_LST);
  assert (Dev.Ep0State == Dwc3Ep0StateSetup && Active[0]);
  assert (!Dev.Endpoints[1].TransferStarted && !Active[1]);
  assert (Ends == 0 && StaleEnds == 0 && Configs == 0);
}

int main (void) {
  ThreeStage (TRUE);
  puts ("PASS three-stage IN: SETUP, data, status, next SETUP without stale ENDTRANSFER");
  ThreeStage (FALSE);
  puts ("PASS three-stage OUT: data resource retained on NOTREADY and retired on COMPLETE");
  Init ();
  Setup (0, USB_REQ_SET_ADDRESS, 0);
  Event (1, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  assert ((Dev.Endpoints[1].TrbPool[0].Control & DWC3_TRB_CTRL_TRBCTL (0x3F)) == DWC3_TRBCTL_CONTROL_STATUS2);
  Event (1, DWC3_DEPEVT_XFERCOMPLETE, DEPEVT_STATUS_IOC | DEPEVT_STATUS_LST);
  assert (Active[0] && !Active[1] && Ends == 0 && StaleEnds == 0);
  puts ("PASS two-stage SET_ADDRESS status completion re-arms SETUP");
  Init ();
  Dwc3HandleDeviceEvent (&Dev, DWC3_DEVICE_EVENT_RESET << 8);
  assert (Dev.Endpoints[0].EndTransferPending && Dev.Ep0SetupPending);
  DrainEnds ();
  assert (Configs == 0);
  assert (Active[0] && Dev.Endpoints[0].TransferStarted);
  assert (Ends == 1 && StaleEnds == 0 && Configs == 0);
  puts ("PASS bus reset aborts active SETUP and re-arms without reallocating resources");
  Init ();
  Setup (0xC0, 0x55, 18);
  assert (Dwc3StartTransfer (&Dev, 1, (UINTN)SetupBuffer, 18,
                             DWC3_TRBCTL_CONTROL_DATA) == EFI_SUCCESS);
  Dwc3HandleDeviceEvent (&Dev, DWC3_DEVICE_EVENT_RESET << 8);
  DrainEnds ();
  assert (Active[0] && !Active[1]);
  assert (Ends == 1 && StaleEnds == 0 && Configs == 0);
  puts ("PASS bus reset during IN data cancels the live resource before re-arming SETUP");
  Init ();
  assert (Dev.Endpoints[0].ResourceIndex == 0 && Active[0]);
  assert (Dwc3Ep0OutStart (&Dev) == EFI_SUCCESS);
  assert (Dev.Endpoints[0].EndTransferPending);
  DrainEnds ();
  assert (Active[0] && Ends == 1 && StaleEnds == 0 && RejectedStarts == 0);
  puts ("PASS active EP0 OUT resource zero is ended before replacing SETUP");
  Init ();
  Dwc3EndTransfer (&Dev, 0);
  Dwc3EndTransfer (&Dev, 0);
  Dwc3EndTransfer (&Dev, 1);
  DrainEnds ();
  assert (!Active[0] && Ends == 1 && StaleEnds == 0);
  puts ("PASS inactive zero resource is not ended a second time");
  Init ();
  Setup (0x80, USB_REQ_GET_DESCRIPTOR, 18);
  assert (Dwc3StartTransfer (&Dev, 1, (UINTN)SetupBuffer, 18,
                             DWC3_TRBCTL_CONTROL_DATA) == EFI_SUCCESS);
  Dev.Endpoints[1].TransferTrbLength = 18;
  // IMG_6930: STATUS NOTREADY on IN arrives while IN DATA is still live.
  Event (1, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  assert (Dev.Ep0State == Dwc3Ep0StateData && !Dev.Ep0StatusStarted);
  assert (Active[1] && Ends == 0 && Dev.Endpoints[1].ResourceIndex == 1);
  Event (0, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  assert (Dev.Ep0State == Dwc3Ep0StateData && !Active[0]);
  Event (1, DWC3_DEPEVT_XFERCOMPLETE, DEPEVT_STATUS_IOC | DEPEVT_STATUS_LST);
  assert (Dev.Ep0State == Dwc3Ep0StateStatus && !Active[1]);
  assert (Dev.Messages[1].Payload.utr.BytesTransferred == 18);
  Event (1, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  assert (!Active[1] && !Dev.Ep0StatusStarted);
  Event (0, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  assert (Active[0] && Dev.Ep0StatusStarted);
  Event (0, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  assert (RejectedStarts == 0 && Ends == 0);
  Event (0, DWC3_DEPEVT_XFERCOMPLETE, DEPEVT_STATUS_IOC | DEPEVT_STATUS_LST);
  assert (Dev.Ep0State == Dwc3Ep0StateSetup && Active[0] && !Active[1]);
  puts ("PASS photo replay: early/wrong-direction STATUS cannot cancel DATA or re-arm SETUP early");
  Init ();
  Setup (0x80, 0x55, 0);
  Event (0, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  assert (!Dev.Ep0StatusStarted && !Active[0]);
  Event (1, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  assert (Dev.Ep0StatusStarted && Active[1]);
  puts ("PASS no-data request uses IN status regardless of the request direction bit");
  Init ();
  Setup (0x80, USB_REQ_GET_DESCRIPTOR, 18);
  assert (Dwc3StartTransfer (&Dev, 1, (UINTN)SetupBuffer, 18,
                             DWC3_TRBCTL_CONTROL_DATA) == EFI_SUCCESS);
  Dev.Endpoints[1].TransferTrbLength = 18;
  Event (1, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  Event (1, DWC3_DEPEVT_XFERCOMPLETE, DEPEVT_STATUS_IOC | DEPEVT_STATUS_LST);
  assert (Dev.Ep0State == Dwc3Ep0StateStatus && !Dev.Ep0StatusStarted);
  UINT32 Tail = Dev.MessageTail;
  // IMG_6931: no OUT STATUS has been submitted, but an old OUT COMPLETE arrives.
  Dwc3HandleEp0Event (&Dev, 0, DWC3_DEPEVT_XFERCOMPLETE, 12);
  Dwc3HandleEp0Event (&Dev, 1, DWC3_DEPEVT_XFERCOMPLETE, 12);
  assert (Dev.Ep0State == Dwc3Ep0StateStatus && !Dev.Ep0StatusStarted);
  assert (!Active[0] && !Active[1] && Dev.MessageTail == Tail);
  Event (0, DWC3_DEPEVT_XFERNOTREADY, DEPEVT_STATUS_CONTROL_STATUS);
  assert (Active[0] && Dev.Ep0StatusStarted);
  Event (0, DWC3_DEPEVT_XFERCOMPLETE, 12);
  Tail = Dev.MessageTail;
  Dwc3HandleEp0Event (&Dev, 1, DWC3_DEPEVT_XFERCOMPLETE, 12);
  assert (Dev.Ep0State == Dwc3Ep0StateSetup && Dev.MessageTail == Tail && Active[0]);
  assert (RejectedStarts == 0 && Ends == 0);
  puts ("PASS v20 photo replay: inactive completions cannot finish unarmed STATUS or invent SETUP");
  Init ();
  EFI_USB_DEVICE_REQUEST Packet = { .RequestType = 0x80,
    .Request = USB_REQ_GET_DESCRIPTOR, .Value = 0x100, .Length = 18 };
  memcpy (SetupBuffer, &Packet, sizeof (Packet));
  // v21 photo: COMPLETE arrives with the shared SETUP TRB still 0xC23 / 8.
  Active[0] = FALSE;
  Dwc3HandleEp0Event (&Dev, 0, DWC3_DEPEVT_XFERCOMPLETE, 12);
  assert (Dev.Ep0State == Dwc3Ep0StateData && Dev.MessageTail == 1);
  assert (Dev.Messages[0].Payload.udr.Request == USB_REQ_GET_DESCRIPTOR);
  puts ("PASS EP0 completion is not rejected solely because shared TRB HWO remains set");
  Init ();
  // Even if an old IN transfer is marked active, SETUP belongs to OUT only.
  Dev.Endpoints[1].TransferStarted = TRUE;
  Dev.Endpoints[1].ResourceIndex = 1;
  Active[1] = TRUE;
  Dev.Endpoints[1].TrbPool[0].Control &= ~DWC3_TRB_CTRL_HWO;
  Dwc3HandleEp0Event (&Dev, 1, DWC3_DEPEVT_XFERCOMPLETE, 12);
  assert (Dev.Ep0State == Dwc3Ep0StateSetup && Dev.MessageTail == 0);
  assert (Dev.Endpoints[1].TransferStarted && Dev.Endpoints[1].ResourceIndex == 1);
  puts ("PASS wrong-direction COMPLETE cannot parse SETUP or retire unrelated endpoint bookkeeping");
  Init ();
  DWC3_TRB Before = Dev.Endpoints[0].TrbPool[0];
  assert (Dwc3Ep0OutStart (&Dev) == EFI_SUCCESS);
  assert (Dev.Ep0SetupPending && Dev.Endpoints[0].EndTransferPending);
  assert (memcmp (&Before, &Dev.Endpoints[0].TrbPool[0], sizeof (Before)) == 0);
  unsigned Commands = CommandWrites;
  Dwc3HandleEp0Event (&Dev, 0, DWC3_DEPEVT_XFERCOMPLETE, 12);
  Dwc3HandleEpEvent (&Dev, (DWC3_DEPCMD_SETEPCONFIG << 24) |
                          (DWC3_DEPEVT_EPCMDCMPLT << 6));
  assert (Dev.MessageTail == 0 && Dev.Endpoints[0].EndTransferPending);
  assert (CommandWrites == Commands);
  assert (Dwc3StartTransfer (&Dev, 1, (UINTN)SetupBuffer, 18,
                             DWC3_TRBCTL_CONTROL_DATA) == EFI_NOT_READY);
  CompleteEnd (0);
  assert (!Dev.Ep0SetupPending && Active[0] && !Dev.Endpoints[0].EndTransferPending);
  Commands = CommandWrites;
  Dwc3HandleEpEvent (&Dev, (DWC3_DEPCMD_ENDTRANSFER << 24) |
                          (DWC3_DEPEVT_EPCMDCMPLT << 6));
  assert (CommandWrites == Commands && Dev.Endpoints[0].TransferStarted);
  puts ("PASS restart preserves shared TRB and ignores old completions until matching END ack");
  Init ();
  Dev.Endpoints[1].TransferStarted = TRUE;
  Dev.Endpoints[1].ResourceIndex = 1;
  Active[1] = TRUE;
  assert (Dwc3Ep0OutStart (&Dev) == EFI_SUCCESS);
  CompleteEnd (0);
  assert (!Active[0] && Dev.Ep0SetupPending && Dev.Endpoints[1].EndTransferPending);
  Commands = CommandWrites;
  Dwc3HandleDeviceEvent (&Dev, DWC3_DEVICE_EVENT_CONNECT_DONE << 8);
  assert (Configs == 0 && !Active[0] && Dev.Endpoints[1].EndTransferPending);
  assert (Dev.Ep0ConnectDonePending && CommandWrites == Commands);
  CompleteEnd (1);
  assert (Active[0] && !Active[1] && !Dev.Ep0SetupPending && RejectedStarts == 0);
  assert (!Dev.Ep0ConnectDonePending && Configs == 0);
  puts ("PASS both EP0 END acks are required and CONNECT_DONE cannot reset resources mid-cancel");
  Init ();
  RejectEnd = TRUE;
  Before = Dev.Endpoints[0].TrbPool[0];
  assert (Dwc3Ep0OutStart (&Dev) == EFI_DEVICE_ERROR);
  Commands = CommandWrites;
  Dwc3HandleDeviceEvent (&Dev, DWC3_DEVICE_EVENT_RESET << 8);
  Dwc3HandleDeviceEvent (&Dev, DWC3_DEVICE_EVENT_CONNECT_DONE << 8);
  Dwc3Ep0StallAndRestart (&Dev);
  assert (Dwc3SetHalt (&Dev, 0, TRUE) == EFI_DEVICE_ERROR);
  assert (Dwc3Ep0OutStart (&Dev) == EFI_DEVICE_ERROR);
  assert (Dev.Ep0RestartFailed && Dev.Endpoints[0].EndTransferPending);
  assert (memcmp (&Before, &Dev.Endpoints[0].TrbPool[0], sizeof (Before)) == 0);
  assert (CommandWrites == Commands);
  puts ("PASS rejected END retains ownership and blocks subsequent endpoint commands");
  Init ();
  TimeoutEnd = TRUE;
  Before = Dev.Endpoints[0].TrbPool[0];
  assert (Dwc3Ep0OutStart (&Dev) == EFI_DEVICE_ERROR);
  Commands = CommandWrites;
  assert (Dwc3StartTransfer (&Dev, 0, (UINTN)SetupBuffer, 8,
                             DWC3_TRBCTL_CONTROL_SETUP) == EFI_DEVICE_ERROR);
  assert (Dev.Ep0RestartFailed && CommandWrites == Commands);
  assert (memcmp (&Before, &Dev.Endpoints[0].TrbPool[0], sizeof (Before)) == 0);
  puts ("PASS timed-out END blocks STARTTRANSFER without overwriting the hardware-owned TRB");
  Init ();
  assert (Dwc3Ep0OutStart (&Dev) == EFI_SUCCESS);
  Commands = CommandWrites;
  Dwc3HandleEpEvent (&Dev, (DWC3_DEPCMD_ENDTRANSFER << 24) | (1U << 12) |
                          (DWC3_DEPEVT_EPCMDCMPLT << 6));
  assert (Dev.Ep0RestartFailed && Dev.Endpoints[0].EndTransferPending);
  assert (CommandWrites == Commands);
  puts ("PASS failed END completion event cannot authorize a new SETUP");
  Init ();
  assert (Dwc3Ep0OutStart (&Dev) == EFI_SUCCESS);
  Dev.Started = FALSE;
  Commands = CommandWrites;
  CompleteEnd (0);
  assert (!Active[0] && CommandWrites == Commands && Dev.Ep0SetupPending);
  puts ("PASS late END ack after controller stop cannot restart DMA");
  Init ();
  Dev.Stopping = TRUE;
  Commands = CommandWrites;
  Before = Dev.Endpoints[0].TrbPool[0];
  assert (Dwc3StartTransfer (&Dev, 0, (UINTN)SetupBuffer, 8,
                             DWC3_TRBCTL_CONTROL_SETUP) == EFI_NOT_READY);
  assert (CommandWrites == Commands);
  assert (memcmp (&Before, &Dev.Endpoints[0].TrbPool[0], sizeof (Before)) == 0);
  puts ("PASS stop ownership blocks new DMA without modifying shared TRB");
  Init ();
  Registers[(DWC3_DEP_BASE (0)+DWC3_DEPCMD)/4]=DWC3_DEPCMD_ENDTRANSFER|DWC3_DEPCMD_CMDACT;
  Commands=CommandWrites;
  assert (Dwc3SendEpCommand (&Dev,0,DWC3_DEPCMD_CLEARSTALL,0,0,0,NULL)==EFI_NOT_READY);
  assert (CommandWrites==Commands);
  puts ("PASS busy DEP command refuses CLEARSTALL without touching command parameters");
  Init ();
  Dev.EventBuffer=TestRing;
  Dev.Endpoints[0].Stalled=TRUE;
  Dev.Endpoints[0].EndTransferPending=TRUE;
  Registers[(DWC3_DEP_BASE (0)+DWC3_DEPCMD)/4]=DWC3_DEPCMD_ENDTRANSFER|DWC3_DEPCMD_CMDACT;
  UINT32 Reset=(DWC3_DEVICE_EVENT_RESET<<8)|1U;
  memcpy (TestRing,&Reset,4);
  Registers[DWC3_GEVNTCOUNT (0)/4]=4;
  Commands=CommandWrites;
  Dwc3ProcessEvents (&Dev);
  assert (CommandWrites==Commands && Dev.Endpoints[0].EndTransferPending);
  puts ("PASS RESET event cannot overwrite an active END with CLEARSTALL");
  Init ();
  Dev.Signature=DWC3_DEV_SIGNATURE;
  Dev.EventBuffer=TestRing;
  Dev.Endpoints[0].Stalled=TRUE;
  memcpy (TestRing,&Reset,4);
  Registers[DWC3_GEVNTCOUNT (0)/4]=4;
  TimeoutEnd=TRUE;
  Commands=CommandWrites;
  assert (Dwc3StopController (&Dev.UsbfnIo)==EFI_TIMEOUT);
  assert (Dev.Stopping && CommandWrites==Commands+1);
  assert (Registers[DWC3_GEVNTCOUNT (0)/4]==4);
  puts ("PASS production stop END wait does not dispatch RESET or issue CLEARSTALL");
  return 0;
}

VOID Dwc3CoreExit (DWC3_DEV *Device) { (void)Device; assert (0); }
EFI_STATUS UsbfnPlatformPhyExit (VOID) { assert (0); return EFI_DEVICE_ERROR; }
#ifndef MDEPKG_NDEBUG
VOID EFIAPI DebugPrint (UINTN Level, CONST CHAR8 *Format, ...) { (void)Level; (void)Format; }
VOID EFIAPI DebugAssert (CONST CHAR8 *File, UINTN Line, CONST CHAR8 *Description) { (void)File; (void)Line; (void)Description; assert (0); }
BOOLEAN EFIAPI DebugAssertEnabled (VOID) { return TRUE; }
BOOLEAN EFIAPI DebugPrintEnabled (VOID) { return TRUE; }
BOOLEAN EFIAPI DebugCodeEnabled (VOID) { return TRUE; }
BOOLEAN EFIAPI DebugPrintLevelEnabled (CONST UINTN Level) { (void)Level; return TRUE; }
#endif
