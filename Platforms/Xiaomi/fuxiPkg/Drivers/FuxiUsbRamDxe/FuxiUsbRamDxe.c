// SPDX-License-Identifier: BSD-2-Clause-Patent
// Opt-in receiver diagnostic. Always stays in UEFI: no filesystem/BlockIo,
// flash, reboot, or kernel handoff interface is exposed by the wire protocol.
#include <Uefi.h>
#include <IndustryStandard/Usb.h>
#include <Protocol/UsbFunctionIo.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "RamBulk.h"
#if defined(FUXI_DATA_PORT_UFS) && FUXI_DATA_PORT_UFS
#include "../../Include/Protocol/FuxiUfsReport.h"
STATIC VOID ReplayUfsReport(VOID) {
  EFI_GUID Guid = FUXI_UFS_REPORT_PROTOCOL_GUID;
  FUXI_UFS_REPORT_PROTOCOL *Report = NULL;
  EFI_STATUS Status = gBS->LocateProtocol(&Guid, NULL, (VOID **)&Report);
  if (!EFI_ERROR(Status) && Report != NULL && Report->Revision == FUXI_UFS_REPORT_REVISION && Report->Replay != NULL) {
    Report->Replay(); // Sealed pre-USB text, never re-runs the UFS diagnostic.
  } else {
    DEBUG((DEBUG_ERROR, "USBRAM: cached UFS report unavailable %r\n", Status));
  }
}
#endif
// Per-setup-packet traces flood the boot log during host enumeration; a
// diagnostic-first candidate silences them with FUXI_USB_EP0_TRACE=0.
#ifndef FUXI_USB_EP0_TRACE
#define FUXI_USB_EP0_TRACE 1
#endif
#if FUXI_USB_EP0_TRACE
#define FUXI_TRACE(Arg) DEBUG Arg
#else
#define FUXI_TRACE(Arg)
#endif
#if defined(FUXI_USB_RAM_SYSTEM_HANDOFF)
#include <Protocol/UniXNURamObjects.h>
#include <Library/CacheMaintenanceLib.h>
STATIC UR_HANDOFF Handoff;
STATIC BOOLEAN ObjectAllocated[2];
STATIC UINT32 AllocatingObject;
STATIC EFI_GUID RamObjectsGuid=UNIXNU_RAM_OBJECTS_GUID;
STATIC EFI_STATUS ReserveSystemWindow(VOID) {
  EFI_PHYSICAL_ADDRESS Raw=0;
  EFI_STATUS Status=gBS->AllocatePages(AllocateAnyPages,EfiLoaderData,
    EFI_SIZE_TO_PAGES(UR_WINDOW+SIZE_4MB),&Raw);
  if(EFI_ERROR(Status)) return Status;
  Handoff.Version=1;Handoff.Bytes=sizeof(Handoff);
  // The skew is not 2 MiB alignment padding: DarwinBoot adopts this window only
  // when its low 21 bits equal the kernel link base's, so that the 2 MiB bootstrap
  // blocks line up. UR_WINDOW_SKEW carries that value.
  Handoff.Window=ALIGN_VALUE(Raw,SIZE_2MB)+UR_WINDOW_SKEW;Handoff.WindowBytes=UR_WINDOW;
  DEBUG((DEBUG_ERROR,"USBRAM SYSTEM: window=%lx size=%lx skew=%lx; sparse preflight\n",
    Handoff.Window,Handoff.WindowBytes,UR_WINDOW_SKEW));
  // All pages belong to this allocation, before any OS data is received.
  for(UINT32 Pass=0;Pass<2;Pass++) {
    for(UINT64 At=0;At<=UR_WINDOW;At+=SIZE_2MB) {
      UINT64 Address=Handoff.Window+(At==UR_WINDOW?UR_WINDOW-sizeof(UINT64):At);
      *(volatile UINT64 *)(UINTN)Address=Address^(Pass?MAX_UINT64:0);
      WriteBackInvalidateDataCacheRange((VOID *)(UINTN)Address,sizeof(UINT64));
    }
    for(UINT64 At=0;At<=UR_WINDOW;At+=SIZE_2MB) {
      UINT64 Address=Handoff.Window+(At==UR_WINDOW?UR_WINDOW-sizeof(UINT64):At);
      WriteBackInvalidateDataCacheRange((VOID *)(UINTN)Address,sizeof(UINT64));
      if(*(volatile UINT64 *)(UINTN)Address!=(Address^(Pass?MAX_UINT64:0))) return EFI_DEVICE_ERROR;
    }
  }
  DEBUG((DEBUG_ERROR,"USBRAM SYSTEM: 12 GiB sparse preflight PASS; samples are not full RAM coverage\n"));
  return EFI_SUCCESS;
}
#endif

#pragma pack(1)
typedef struct {
  EFI_USB_CONFIG_DESCRIPTOR Config;
  EFI_USB_INTERFACE_DESCRIPTOR Interface;
  EFI_USB_ENDPOINT_DESCRIPTOR Out, In;
} USB_CONFIG;
#pragma pack()
STATIC EFI_USB_DEVICE_DESCRIPTOR Device={18,1,0x200,0,0,0,64,0x1209,1,0x100,1,2,3,1};
STATIC USB_CONFIG Config={{9,2,sizeof(USB_CONFIG),1,1,0,0x80,250},
  {9,4,0,0,2,0xff,0x58,1,0},{7,5,1,2,512,0},{7,5,0x81,2,512,0}};
STATIC EFI_USB_ENDPOINT_DESCRIPTOR *Endpoints[]={&Config.Out,&Config.In};
STATIC EFI_USB_INTERFACE_INFO InterfaceInfo={&Config.Interface,Endpoints};
STATIC EFI_USB_INTERFACE_INFO *Interfaces[]={&InterfaceInfo};
STATIC EFI_USB_CONFIG_INFO ConfigInfo={&Config.Config,Interfaces};
STATIC EFI_USB_CONFIG_INFO *Configs[]={&ConfigInfo};
STATIC EFI_USB_DEVICE_INFO DeviceInfo={&Device,Configs};
STATIC EFI_USBFN_IO_PROTOCOL *Usb;
STATIC RB_SESSION Session;
STATIC RB8 *Rx,*Tx,*Control;
STATIC RB8 Header[RB_HEADER];
STATIC RB32 Body;
STATIC BOOLEAN Configured,Pending;
STATIC unsigned Phase; // 0 header RX, 1 payload RX, 2 ACK TX
STATIC EFI_STATUS Stall(UINT8 Endpoint,EFI_USBFN_ENDPOINT_DIRECTION Direction,BOOLEAN Value) {
  return Usb->SetEndpointStallState(Usb,Endpoint,Direction,&Value);
}

STATIC VOID *RamAllocate(VOID *Context,RB64 Bytes) {
#if defined(FUXI_USB_RAM_SYSTEM_HANDOFF)
  (VOID)Context;
  if(AllocatingObject<1 || AllocatingObject>2 || Bytes!=UrBytes(AllocatingObject) ||
     ObjectAllocated[AllocatingObject-1]) return NULL;
  ObjectAllocated[AllocatingObject-1]=TRUE;
  return (VOID *)(UINTN)(Handoff.Window+UrOffset(AllocatingObject));
#else
  EFI_PHYSICAL_ADDRESS Address=0;
  (VOID)Context;
  if(Bytes>MAX_UINTN-4095 || EFI_ERROR(gBS->AllocatePages(AllocateAnyPages,
       EfiLoaderData,EFI_SIZE_TO_PAGES((UINTN)Bytes),&Address))) return NULL;
  return (VOID *)(UINTN)Address;
#endif
}
STATIC VOID RamRelease(VOID *Context,VOID *Data,RB64 Bytes) {
#if defined(FUXI_USB_RAM_SYSTEM_HANDOFF)
  (VOID)Context;
  for(UINT32 Id=1;Id<=2;Id++)
    if(Data==(VOID *)(UINTN)(Handoff.Window+UrOffset(Id)) && Bytes==UrBytes(Id)) ObjectAllocated[Id-1]=FALSE;
  // Keep the entire reserved window. Never free a slice independently.
#else
  (VOID)Context;gBS->FreePages((EFI_PHYSICAL_ADDRESS)(UINTN)Data,EFI_SIZE_TO_PAGES((UINTN)Bytes));
#endif
}
STATIC int RamHash(CONST VOID *Data,RB64 Bytes,RB8 Digest[32]) {
  VOID *Hash=AllocatePool(Sha256GetContextSize());
  CONST UINT8 *Cursor=Data;
  BOOLEAN Ok;
  if(Hash==NULL) return 0;
  Ok=Sha256Init(Hash);
  while(Ok && Bytes) {
    UINTN Count=(UINTN)MIN(Bytes,(RB64)RB_CHUNK);
    Ok=Sha256Update(Hash,Cursor,Count);Cursor+=Count;Bytes-=Count;
  }
  if(Ok) Ok=Sha256Final(Hash,Digest);
  FreePool(Hash);return Ok;
}
STATIC EFI_STATUS Ep0Reply(CONST VOID *Data,UINTN Bytes,UINT16 Requested) {
  UINTN Size=MIN(Bytes,(UINTN)Requested);
  if(Size) CopyMem(Control,Data,Size);
  return Usb->Transfer(Usb,0,EfiUsbEndpointDirectionDeviceTx,&Size,Control);
}
STATIC EFI_STATUS Setup(EFI_USB_DEVICE_REQUEST *Request) {
  UINT8 Type=(UINT8)(Request->Value>>8),Index=(UINT8)Request->Value;
  UINT8 Zero[2]={0,0};
  if(Request->RequestType==0x80 && Request->Request==USB_REQ_GET_DESCRIPTOR) {
    if(Type==USB_DESC_TYPE_DEVICE && Index==0)
      return Ep0Reply(&Device,sizeof(Device),Request->Length);
    if(Type==USB_DESC_TYPE_CONFIG && Index==0)
      return Ep0Reply(&Config,sizeof(Config),Request->Length);
    if(Type==6 && Index==0) {
      UINT8 Qualifier[]={10,6,0,2,0,0,0,64,1,0};
      return Ep0Reply(Qualifier,sizeof(Qualifier),Request->Length);
    }
    if(Type==7 && Index==0) {
      USB_CONFIG Other=Config;
      Other.Config.DescriptorType=7;
      Other.Out.MaxPacketSize=Other.In.MaxPacketSize=(UINT16)(Config.Out.MaxPacketSize==512?64:512);
      return Ep0Reply(&Other,sizeof(Other),Request->Length);
    }
    if(Type==USB_DESC_TYPE_STRING) {
      CONST CHAR16 *String;
      UINTN Count;
      if(Index==0) {UINT8 Language[]={4,3,9,4};return Ep0Reply(Language,4,Request->Length);}
      String=Index==1?L"UniXNU":Index==2?L"fuxi RAM Bulk":Index==3?L"fcde91e-ram":NULL;
      if(String!=NULL) {
        Count=StrLen(String)*2;Control[0]=(UINT8)(Count+2);Control[1]=3;
        CopyMem(Control+2,String,Count);
        return Ep0Reply(Control,Count+2,Request->Length);
      }
    }
  }
  if(Request->RequestType==0 && Request->Request==USB_REQ_SET_CONFIG &&
     Request->Index==0 && Request->Length==0 && Request->Value<=1) {
    Usb->AbortTransfer(Usb,1,EfiUsbEndpointDirectionDeviceRx);
    Usb->AbortTransfer(Usb,1,EfiUsbEndpointDirectionDeviceTx);
    RbClear(&Session);Configured=(BOOLEAN)(Request->Value==1);Pending=FALSE;Phase=0;
    DEBUG((DEBUG_ERROR,"USBRAM: configuration %u\n",Request->Value));
    return EFI_SUCCESS; // DWC3 performs the EP0 status stage.
  }
  if(Request->RequestType==0x80 && Request->Request==USB_REQ_GET_CONFIG) {
    Zero[0]=(UINT8)Configured;return Ep0Reply(Zero,1,Request->Length);
  }
  if(Request->RequestType==0x81 && Request->Request==USB_REQ_GET_INTERFACE && Request->Index==0)
    return Ep0Reply(Zero,1,Request->Length);
  if(Request->RequestType==1 && Request->Request==USB_REQ_SET_INTERFACE &&
     Request->Value==0 && Request->Index==0 && Request->Length==0) {
    Usb->AbortTransfer(Usb,1,EfiUsbEndpointDirectionDeviceRx);
    Usb->AbortTransfer(Usb,1,EfiUsbEndpointDirectionDeviceTx);
    RbClear(&Session);Pending=FALSE;Phase=0;return EFI_SUCCESS;
  }
  if((Request->RequestType==0x80 || Request->RequestType==0x81 || Request->RequestType==0x82) &&
     Request->Request==USB_REQ_GET_STATUS) return Ep0Reply(Zero,2,Request->Length);
  if(Request->RequestType==2 && Request->Request==USB_REQ_CLEAR_FEATURE &&
     Request->Value==0 && Request->Length==0 && (Request->Index==1 || Request->Index==0x81))
    return Stall(1,(Request->Index&0x80)?
      EfiUsbEndpointDirectionDeviceTx:EfiUsbEndpointDirectionDeviceRx,FALSE);
  return EFI_UNSUPPORTED;
}
STATIC VOID Process(RB32 Bytes) {
#if defined(FUXI_USB_RAM_SYSTEM_HANDOFF)
  AllocatingObject=(UINT32)RbRead(Header+12,4);
#endif
  RbHandle(&Session,Header,Bytes?Rx:NULL,Bytes,Tx);
  if(RbRead(Header+10,2)==RbEnd && RbRead(Tx+28,4)==RbOk) {
    UINT32 Id=(UINT32)RbRead(Header+12,4);
    DEBUG((DEBUG_ERROR,"USBRAM VERIFIED id=%u PA=%lx bytes=%lu (RAM only)\n",Id,
      (UINT64)(UINTN)Session.Object[Id].Data,Session.Object[Id].Bytes));
  }
  Phase=2;
}
STATIC EFI_STATUS Completion(EFI_USBFN_TRANSFER_RESULT *Result) {
  if(Result->EndpointIndex!=1) return EFI_SUCCESS;
  if(!Configured) return EFI_SUCCESS;
  // The generic controller may queue abort notifications during SET_CONFIG.
  if(Result->TransferStatus==UsbTransferStatusAborted) return EFI_SUCCESS;
  if(Result->TransferStatus!=UsbTransferStatusComplete) return EFI_SUCCESS;
  if(!Pending) return EFI_DEVICE_ERROR;
  if(Phase==2) {
    if(Result->Direction!=EfiUsbEndpointDirectionDeviceTx || Result->Buffer!=Tx ||
       Result->BytesTransferred!=RB_HEADER) return EFI_DEVICE_ERROR;
    Phase=0;
  } else {
    if(Result->Direction!=EfiUsbEndpointDirectionDeviceRx || Result->Buffer!=Rx ||
       Result->BytesTransferred!=(Phase==0?RB_HEADER:Body)) return EFI_DEVICE_ERROR;
    if(Phase==0) {
      CopyMem(Header,Rx,RB_HEADER);
      if(!RbHeaderLength(Header,&Body)) return EFI_COMPROMISED_DATA;
      if(Body) Phase=1; else Process(0);
    } else Process(Body);
  }
  Pending=FALSE;return EFI_SUCCESS;
}
EFI_STATUS EFIAPI FuxiUsbRamEntry(EFI_HANDLE Image,EFI_SYSTEM_TABLE *SystemTable) {
  EFI_STATUS Status;
  EFI_USBFN_MESSAGE Message;
  EFI_USBFN_MESSAGE_PAYLOAD Payload;
  UINTN Size;
  UINT64 Last;
  (VOID)Image;(VOID)SystemTable;
  DEBUG((DEBUG_ERROR,"\fUSBRAM: entering USB2 Bulk receiver diagnostic\n"));
  gBS->SetWatchdogTimer(0,0,0,NULL);
#if defined(FUXI_USB_RAM_SYSTEM_HANDOFF)
  Status=ReserveSystemWindow();if(EFI_ERROR(Status)) goto Park;
#endif
  Status=gBS->LocateProtocol(&gEfiUsbFunctionIoProtocolGuid,NULL,(VOID **)&Usb);
  if(EFI_ERROR(Status)) goto Park;
  Status=Usb->AllocateTransferBuffer(Usb,RB_CHUNK,(VOID **)&Rx);if(EFI_ERROR(Status)) goto Park;
  Status=Usb->AllocateTransferBuffer(Usb,RB_CHUNK,(VOID **)&Tx);if(EFI_ERROR(Status)) goto Park;
  Status=Usb->AllocateTransferBuffer(Usb,4096,(VOID **)&Control);if(EFI_ERROR(Status)) goto Park;
  Session.Allocate=RamAllocate;Session.Release=RamRelease;Session.Hash=RamHash;
  Status=Usb->StartController(Usb);
  DEBUG((DEBUG_ERROR,"USBRAM S13 StartController returned %r\n",Status));
  if(EFI_ERROR(Status)) goto Park;
  Status=Usb->ConfigureEnableEndpoints(Usb,&DeviceInfo);
  DEBUG((DEBUG_ERROR,"USBRAM S19 ConfigureEnableEndpoints returned %r\n",Status));
  if(Status==EFI_NOT_READY) goto Park; // Audit intentionally parks before DMA.
  if(EFI_ERROR(Status)) goto Stop;
  DEBUG((DEBUG_ERROR,"USBRAM WAIT 1209:0001; Bulk OUT=01 IN=81; idle timeout 180s\n"));
  Last=GetPerformanceCounter();
  for(;;) {
    Size=sizeof(Payload);
    Status=Usb->EventHandler(Usb,&Message,&Size,&Payload);
    if(EFI_ERROR(Status)) break;
    if(Message==EfiUsbMsgSetupPacket) {
      FUXI_TRACE((DEBUG_ERROR,"USBRAM: setup rt=%02x req=%02x val=%04x idx=%04x len=%u\n",
        Payload.udr.RequestType,Payload.udr.Request,Payload.udr.Value,
        Payload.udr.Index,Payload.udr.Length));
      Status=Setup(&Payload.udr);
      if(EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR,"USBRAM: setup reply failed %r\n",Status));
        Stall(0,EfiUsbEndpointDirectionDeviceRx,TRUE);
        Status=EFI_SUCCESS;
      }
      Last=GetPerformanceCounter();
    } else if(Message==EfiUsbMsgBusEventReset || Message==EfiUsbMsgBusEventDetach) {
      Configured=FALSE;Pending=FALSE;Phase=0;
      RbClear(&Session);
      FUXI_TRACE((DEBUG_ERROR,"USBRAM: bus %a; session cleared\n",
        Message==EfiUsbMsgBusEventReset?"reset":"detach"));
    } else if(Message==EfiUsbMsgBusEventSpeed) {
      Config.Out.MaxPacketSize=Config.In.MaxPacketSize=(UINT16)(Payload.ubs>=UsbBusSpeedHigh?512:64);
      DEBUG((DEBUG_ERROR,"USBRAM: speed=%u\n",Payload.ubs));
    } else if(Message==EfiUsbMsgEndpointStatusChangedRx || Message==EfiUsbMsgEndpointStatusChangedTx) {
      Status=Completion(&Payload.utr);if(EFI_ERROR(Status)) break;
      if(Payload.utr.EndpointIndex==1) Last=GetPerformanceCounter();
    }
#if defined(FUXI_USB_RAM_SYSTEM_HANDOFF)
    // Wait for the final END ACK's IN completion before stopping the controller.
    if(!Pending && Phase==0 && Session.Object[1].State==2 && Session.Object[2].State==2) {
      Status=EFI_SUCCESS;break;
    }
#endif
    if(Configured && !Pending) {
      Size=Phase==0?RB_HEADER:Phase==1?Body:RB_HEADER;
      Status=Usb->Transfer(Usb,1,Phase==2?EfiUsbEndpointDirectionDeviceTx:
        EfiUsbEndpointDirectionDeviceRx,&Size,Phase==2?Tx:Rx);
      if(EFI_ERROR(Status)) break;
      Pending=TRUE;
    }
    if(GetTimeInNanoSecond(GetPerformanceCounter()-Last)>180000000000ULL) {Status=EFI_TIMEOUT;break;}
    gBS->Stall(100);
  }
Stop:
  {
    EFI_STATUS StopStatus=Usb->StopController(Usb);
    DEBUG((DEBUG_ERROR,"USBRAM QUIESCE: %r; receive status=%r; buffers retained\n",StopStatus,Status));
    if(EFI_ERROR(StopStatus)) Status=StopStatus;
  }
#if defined(FUXI_USB_RAM_SYSTEM_HANDOFF)
  if(!EFI_ERROR(Status) && Session.Object[1].State==2 && Session.Object[2].State==2) {
    EFI_HANDLE Handle=NULL;
    for(UINT32 Id=1;Id<=2;Id++) {
      Handoff.Object[Id-1].Address=(UINT64)(UINTN)Session.Object[Id].Data;
      Handoff.Object[Id-1].Bytes=Session.Object[Id].Bytes;
      CopyMem(Handoff.Object[Id-1].Sha256,Session.Object[Id].Digest,32);
    }
    Handoff.Flags=3; // both END digests passed and StopController restored routing.
    if(!UrValid(&Handoff)) {Status=EFI_COMPROMISED_DATA;goto Park;}
    Status=gBS->InstallProtocolInterface(&Handle,&RamObjectsGuid,EFI_NATIVE_INTERFACE,&Handoff);
    if(EFI_ERROR(Status)) goto Park;
    DEBUG((DEBUG_ERROR,"USBRAM SYSTEM: immutable objects published; return to boot manager\n"));
    return EFI_SUCCESS;
  }
#endif
Park:
#if defined(FUXI_DATA_PORT_UFS) && FUXI_DATA_PORT_UFS
  ReplayUfsReport();
#endif
  // Retain RAM and all DMA allocations for inspection until reboot. Never
  // return to BDS and accidentally start XNU with unreserved receive buffers.
  DEBUG((DEBUG_ERROR,"USBRAM STOP status=%r; buffers retained; hardware result needs review\n",Status));
  CpuDeadLoop();
  return Status;
}
