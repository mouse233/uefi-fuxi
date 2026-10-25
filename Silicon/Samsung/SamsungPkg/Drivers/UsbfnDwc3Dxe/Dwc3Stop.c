// SPDX-License-Identifier: BSD-2-Clause-Patent
// Quiesce a running gadget before removing its platform DMA route.
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "UsbfnDwc3Dxe.h"

STATIC EFI_STATUS
DrainStopEvents (DWC3_DEV *Dev)
{
  UINT32 Count;

  Count = MmioRead32 (Dev->Base + DWC3_GEVNTCOUNT (0)) & DWC3_GEVNTCOUNT_MASK;
  if (Count > DWC3_EVENT_BUFFER_SIZE) {
    return EFI_DEVICE_ERROR;
  }

  if (Count != 0) {
    // The session has ended. Acknowledge without dispatch: reset/connect and
    // EP0 completion handlers must not queue fresh work while stopping.
    Dev->EventPos = (Dev->EventPos + Count) % DWC3_EVENT_BUFFER_SIZE;
    MmioWrite32 (Dev->Base + DWC3_GEVNTCOUNT (0), Count);
  }

  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI
Dwc3StopController (IN EFI_USBFN_IO_PROTOCOL *This)
{
  DWC3_DEV *Dev;
  DWC3_ENDPOINT *Endpoint;
  EFI_STATUS Status;
  UINT32 Register, Command, Timeout;
  UINT8 Index;

  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Dev = DWC3_DEV_FROM_PROTOCOL (This);
  if (!Dev->Started) {
    // A previous route-removal failure is not a successful stop. Permit only
    // its checked rollback to be retried; do not restart the gadget.
    if (!Dev->Stopping) {
      return EFI_SUCCESS;
    }
    Status = UsbfnPlatformPhyExit ();
    if (!EFI_ERROR (Status)) {
      Dev->Stopping = FALSE;
    }
    return Status;
  }

  if (Dev->Stopping) {
    return EFI_NOT_READY;
  }
  Dev->Stopping = TRUE;
  DEBUG ((DEBUG_ERROR, "DWC3 STOP: ending active transfers; retaining DMA memory\n"));
  for (Index = 0; Index < Dev->NumPhysicalEps; Index++) {
    Endpoint = &Dev->Endpoints[Index];
    if (!Endpoint->TransferStarted || Endpoint->EndTransferPending) {
      continue;
    }
    Command = DWC3_DEPCMD_ENDTRANSFER | DWC3_DEPCMD_HIPRI_FORCERM |
              DWC3_DEPCMD_CMDIOC | DWC3_DEPCMD_PARAM (Endpoint->ResourceIndex);
    Status = Dwc3SendEpCommand (Dev, Index, Command, 0, 0, 0, NULL);
    if (EFI_ERROR (Status)) {
      // No halt proof: retain TRBs, endpoint ownership and the SMMU route.
      DEBUG ((DEBUG_ERROR, "DWC3 STOP: END failed ep=%u status=%r; route retained\n", Index, Status));
      return Status;
    }
    Endpoint->EndTransferPending = TRUE;
  }

  Register = MmioRead32 (Dev->Base + DWC3_DCTL);
  Register &= ~(DWC3_DCTL_RUN_STOP | DWC3_DCTL_TSTCTRL_MASK);
  MmioWrite32 (Dev->Base + DWC3_DCTL, Register);
  // A command acknowledgment alone is not proof that DMA has stopped.
  // DEVCTRLHLT is the final hardware gate. Pending events must be consumed
  // while polling it (Linux dwc3_gadget_soft_disconnect documents this).
  for (Timeout = 0; Timeout < DWC3_RUNSTOP_TIMEOUT_US; Timeout++) {
    Status = DrainStopEvents (Dev);
    if (EFI_ERROR (Status)) {
      return Status;
    }
    Register = MmioRead32 (Dev->Base + DWC3_DSTS);
    if ((Register & DWC3_DSTS_DEVCTRLHLT) != 0) {
      break;
    }
    gBS->Stall (1);
  }
  if (Timeout == DWC3_RUNSTOP_TIMEOUT_US) {
    DEBUG ((DEBUG_ERROR, "DWC3 STOP: halt timeout DSTS=%08x; route retained\n", Register));
    return EFI_TIMEOUT;
  }

  Status = DrainStopEvents (Dev);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  DEBUG ((DEBUG_ERROR, "DWC3 STOP: HALTED DSTS=%08x events=%u\n", Register,
          MmioRead32 (Dev->Base + DWC3_GEVNTCOUNT (0)) & DWC3_GEVNTCOUNT_MASK));
  // Hardware is halted: retire bookkeeping without issuing another END on
  // endpoints whose asynchronous completion events we deliberately discarded.
  for (Index = 0; Index < Dev->NumPhysicalEps; Index++) {
    Endpoint = &Dev->Endpoints[Index];
    Endpoint->Enabled = FALSE;
    Endpoint->TransferStarted = FALSE;
    Endpoint->EndTransferPending = FALSE;
    Endpoint->ResourceIndex = 0;
    Endpoint->TransferBuffer = NULL;
  }
  Dwc3CoreExit (Dev);
  Dev->Started = FALSE;
  Dev->Speed = UsbBusSpeedUnknown;
  Dev->MessageHead = Dev->MessageTail = 0;
  Status = UsbfnPlatformPhyExit ();
  if (!EFI_ERROR (Status)) {
    Dev->Stopping = FALSE;
  }
  DEBUG ((DEBUG_ERROR, "DWC3 STOP: route release status=%r\n", Status));
  return Status;
}
