## fuxiPkg/Include/APRIORI.inc
## Xiaomi 13 (SM8550) — derived from uefi-sheng shengPkg (branch: sheng).
##
## Minimal PEI/DXE dispatch order for FUXI_VENDOR_HW = 0:
## only Project Mu / Silicium drivers plus UniXNU. Every `Binaries/sheng/*`
## entry of the original is dropped because fuxi has no vendor blob import yet.
##
## TODO(阶段 2): FuxiBootMemoryDxe must declare 0xb8000000/0x02b00000 as boot
## services memory before SimpleFbDxe runs, otherwise the GOP has no backing.
## sheng does this in ShengBootMemoryDxe; fuxi has no equivalent yet.

APRIORI DXE {
  INF MdeModulePkg/Core/Dxe/DxeMain.inf
  INF MdeModulePkg/Universal/PCD/Dxe/Pcd.inf

  INF MdeModulePkg/Universal/ReportStatusCodeRouter/RuntimeDxe/ReportStatusCodeRouterRuntimeDxe.inf
  INF MdeModulePkg/Universal/StatusCodeHandler/RuntimeDxe/StatusCodeHandlerRuntimeDxe.inf
  INF MdeModulePkg/Core/RuntimeDxe/RuntimeDxe.inf
  INF ArmPkg/Drivers/CpuDxe/CpuDxe.inf
  INF ArmPkg/Drivers/ArmGicDxe/ArmGicDxe.inf
  INF EmbeddedPkg/MetronomeDxe/MetronomeDxe.inf
  INF ArmPkg/Drivers/TimerDxe/TimerDxe.inf

  INF MdeModulePkg/Universal/ResetSystemRuntimeDxe/ResetSystemRuntimeDxe.inf

!if $(FUXI_PAYLOAD_DIAGNOSTIC) == 1
  INF fuxiPkg/Drivers/FuxiPayloadDxe/FuxiPayloadDxe.inf
!endif
  INF MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIoDxe.inf
  INF MdeModulePkg/Universal/Disk/PartitionDxe/PartitionDxe.inf
  INF MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/EnglishDxe.inf
  INF FatPkg/EnhancedFatDxe/Fat.inf

  INF MdeModulePkg/Universal/Variable/RuntimeDxe/VariableRuntimeDxe.inf

  # 亮屏路径：上一级（ABL）留在 splash_region 的 framebuffer 继续扫描输出，
  # SimpleFbDxe 在其上发布 GOP。USE_CUSTOM_DISPLAY_DRIVER = 0。
  INF SiliciumPkg/Drivers/SimpleFbDxe/SimpleFbDxe.inf

  INF MdeModulePkg/Universal/WatchdogTimerDxe/WatchdogTimer.inf
  INF MdeModulePkg/Universal/SecurityStubDxe/SecurityStubDxe.inf
  INF EmbeddedPkg/EmbeddedMonotonicCounter/EmbeddedMonotonicCounter.inf
  INF EmbeddedPkg/RealTimeClockRuntimeDxe/RealTimeClockRuntimeDxe.inf
  INF MdeModulePkg/Universal/PrintDxe/PrintDxe.inf
  INF MdeModulePkg/Universal/DevicePathDxe/DevicePathDxe.inf
  INF MdeModulePkg/Universal/CapsuleRuntimeDxe/CapsuleRuntimeDxe.inf
  INF MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf
  INF MdeModulePkg/Universal/BdsDxe/BdsDxe.inf

  INF MdeModulePkg/Bus/Usb/UsbBusDxe/UsbBusDxe.inf
  INF MdeModulePkg/Bus/Usb/UsbKbDxe/UsbKbDxe.inf
  INF MdeModulePkg/Bus/Usb/UsbMassStorageDxe/UsbMassStorageDxe.inf

  INF EmbeddedPkg/SimpleTextInOutSerial/SimpleTextInOutSerial.inf
  INF MdeModulePkg/Universal/Console/ConPlatformDxe/ConPlatformDxe.inf
  INF MdeModulePkg/Universal/Console/ConSplitterDxe/ConSplitterDxe.inf
  INF MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsoleDxe.inf

!if $(FUXI_DATA_PORT_UFS) == 1
  # The native UFS diagnostic must dispatch before the USB receiver: the
  # receiver-only candidate parks inside its entry after the idle window and
  # never reaches BDS. The console stack above is already up at this point.
  INF fuxiPkg/Drivers/FuxiNativeUfsDxe/FuxiNativeUfsDxe.inf
!endif
}
