##
#  fuxiPkg — Xiaomi 13 (SM8550 / kalama)
#
#  Derived from UniXNU/uefi-sheng shengPkg/sheng.dsc (branch: sheng).
#  参考基线：Mu-Silicium 的 Platforms/Xiaomi/nuwaPkg（小米 13 Pro，同 SM8550）。
#
#  STATUS: stage-1 bring-up. DEBUG builds use the captured fuxi memory map,
#  ABL framebuffer and SPMI keys. DarwinBoot and FuxiBootMemoryDxe remain
#  disabled until the handed-over DT is safely mapped/copied and validated.
#  A successful build is not evidence that the hardware boot reached BDS.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
##

################################################################################
#
# Defines Section
#
################################################################################
[Defines]
  PLATFORM_NAME                  = fuxi
  PLATFORM_GUID                  = 6F1C8E42-3D57-4B0A-9C21-8E4D5A7B1F30
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/fuxiPkg
  SUPPORTED_ARCHITECTURES        = AARCH64
  BUILD_TARGETS                  = RELEASE|DEBUG
  SKUID_IDENTIFIER               = DEFAULT
  FLASH_DEFINITION               = fuxiPkg/fuxi.fdf

  #
  # 与 sheng 首启相同的取舍：0 = 只用 Mu 驱动。
  # 此时上一级（ABL）留在 splash_region 的 framebuffer 继续扫描输出，
  # SimpleFbDxe 直接在其上发布 GOP，UniXNU 菜单可见，不加载任何 vendor 驱动。
  #
  # fuxi 的 stock DT 已自带 /reserved-memory/splash_region
  #   reg = <0x0 0xb8000000 0x0 0x2b00000>
  # 因此不像 sheng 那样需要在 board.toml 里补 dtb_node。
  #
  # 1 = 加载 stock vendor 驱动（SMEM/时钟/RPMh/UFS/USB/充电…）。
  # sheng 上的经验是这条链会把面板点黑，fuxi 未知，留作后续阶段。
  #
  USE_CUSTOM_DISPLAY_DRIVER      = 0
  FUXI_VENDOR_HW                 = 0
  # Opt-in only: publish an identified FAT payload without adding DRAM to GCD.
  FUXI_PAYLOAD_DIAGNOSTIC        = 0
  # Explicit receiver-only image: USB2 warm handoff, no BDS/XNU continuation.
  FUXI_USB_RAM_SYSTEM_HANDOFF    = 0
  FUXI_USB_RAM_RECEIVER          = 0
  FUXI_USB_TRY_SID_ROUTE         = 0
  # Opt-in: keep the USB2 PHY state inherited from ABL instead of pulsing
  # GUSB2PHYCFG.PHYSOFTRST, which this firmware cannot re-initialize.
  FUXI_USB_KEEP_PHY              = 0

  # TWRP /data port diagnostics. No decryptor, no native UFS takeover yet.
  FUXI_DATA_PORT_PROBE           = 0
  FUXI_DATA_SCM_QUERY            = 0
  # M1: native read-only UFS takeover diagnostic (FuxiNativeUfsDxe).
  FUXI_DATA_PORT_UFS             = 0
  FUXI_UFS_REPORT_HOLD_SECONDS   = 0
  # 0 = silence the per-packet EP0 traces (diagnostic-first candidates).
  FUXI_USB_EP0_TRACE             = 1

  #
  # 0 = SM8550-AB
  # 1 = SM8550-AC
  # fuxi (2211133C) 为 SM8550-AB
  #
  SOC_TYPE                       = 0

!include KailuaPkg/KailuaPkg.dsc.inc

!if ($(USE_CUSTOM_DISPLAY_DRIVER) == 1) && ($(FUXI_VENDOR_HW) == 0)
  !error The stock DisplayDxe chain needs FUXI_VENDOR_HW = 1
!endif

[PcdsFixedAtBuild]
  #
  # DDR Memory — 实测：fuxi live FDT 的 memory 基址为 0x80000000
  #
  gArmTokenSpaceGuid.PcdSystemMemoryBase|0x80000000

  #
  # UEFI Stack
  # Matches the captured fuxi "UEFI Stack" descriptor; statically checked.
  #
  gArmPlatformTokenSpaceGuid.PcdCPUCoresStackBase|0xA760D000
  gArmPlatformTokenSpaceGuid.PcdCPUCorePrimaryStackSize|0x40000

  #
  # SMBIOS
  #
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemManufacturer|"Xiaomi"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemModel|"13"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemRetailModel|"fuxi"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemRetailSku|"13_fuxi"
  gSiliciumPkgTokenSpaceGuid.PcdSmbiosSystemBoardModel|"13"

  #
  # Simple Frame Buffer
  # 面板 m3_38_0c_0a，1080x2400，DSC command mode。
  # 宽度必须与 ABL 的 scan-out stride 一致，否则画面错位。
  #
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferWidth|1080
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferHeight|2400
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferColorDepth|32
  #
  # 1080/8/2 = 67 列，2400/16/2 = 75 行；sheng 用 3（3048 宽）。
  #
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferFontScale|2
  gSiliciumPkgTokenSpaceGuid.PcdFrameBufferDelay|30000

  #
  # Platform PEI
  #
  gQcomPkgTokenSpaceGuid.PcdPlatformType|"LA"
!if $(FUXI_VENDOR_HW) == 0
  # 沿用 sheng 的规避：PlatformPeim 会去扫 stock UEFI 残留的 FD 窗口并调用其
  # scheduler protocol，在没有 vendor 驱动读这些 HOB 时会随机卡死。
  gQcomPkgTokenSpaceGuid.PcdBuildXblHobs|FALSE
!endif

[LibraryClasses]
!if $(FUXI_USB_RAM_RECEIVER) == 1
!if $(FUXI_USB_TRY_SID_ROUTE) == 1
  PlatformUsbfnLib|fuxiPkg/Library/FuxiUsbfnLib/FuxiUsbfnRouteLib.inf
!else
  PlatformUsbfnLib|fuxiPkg/Library/FuxiUsbfnLib/FuxiUsbfnLib.inf
!endif
!endif
  #
  # Memory Libraries
  #
  MemoryMapLib|fuxiPkg/Library/MemoryMapLib/MemoryMapLib.inf
  ConfigurationMapLib|fuxiPkg/Library/ConfigurationMapLib/ConfigurationMapLib.inf

  UniXNULib|UniXNUPkg/Library/UniXNULib/UniXNULib.inf
  FdtLib|MdePkg/Library/BaseFdtLib/BaseFdtLib.inf

[Components]
!if $(FUXI_DATA_PORT_PROBE) == 1
  fuxiPkg/Drivers/FuxiDataProbeDxe/FuxiDataProbeDxe.inf {
    <BuildOptions>
      *_*_*_CC_FLAGS = -DFUXI_DATA_SCM_QUERY=$(FUXI_DATA_SCM_QUERY)
  }
!endif
!if $(FUXI_DATA_PORT_UFS) == 1
  fuxiPkg/Drivers/FuxiNativeUfsDxe/FuxiNativeUfsDxe.inf {
    <BuildOptions>
      *_*_*_CC_FLAGS = -DFUXI_UFS_REPORT_HOLD_SECONDS=$(FUXI_UFS_REPORT_HOLD_SECONDS)
  }
!endif
!if $(FUXI_USB_RAM_RECEIVER) == 1
  SamsungPkg/Drivers/UsbfnDwc3Dxe/UsbfnDwc3Dxe.inf {
    <BuildOptions>
      *_*_*_CC_FLAGS = -DFUXI_USB_DMA32=1
!if $(FUXI_USB_KEEP_PHY) == 1
      *_*_*_CC_FLAGS = -DFUXI_USB_KEEP_PHY=1
!endif
!if $(FUXI_USB_EP0_TRACE) == 0
      *_*_*_CC_FLAGS = -DFUXI_USB_EP0_TRACE=0
!endif
  }
  fuxiPkg/Drivers/FuxiUsbRamDxe/FuxiUsbRamDxe.inf {
!if $(FUXI_USB_RAM_SYSTEM_HANDOFF) == 1 || $(FUXI_USB_EP0_TRACE) == 0 || $(FUXI_DATA_PORT_UFS) == 1
    <BuildOptions>
!endif
!if $(FUXI_DATA_PORT_UFS) == 1
      *_*_*_CC_FLAGS = -DFUXI_DATA_PORT_UFS=1
!endif
!if $(FUXI_USB_RAM_SYSTEM_HANDOFF) == 1
      *_*_*_CC_FLAGS = -DFUXI_USB_RAM_SYSTEM_HANDOFF=1
!endif
!if $(FUXI_USB_EP0_TRACE) == 0
      *_*_*_CC_FLAGS = -DFUXI_USB_EP0_TRACE=0
!endif
  }
!endif
  #
  # UniXNU 启动管理器
  #
  UniXNUPkg/Application/UniXNU/UniXNU.inf
  UniXNUPkg/Driver/UniXNUDxe/UniXNUDxe.inf

  #
  # DarwinBoot（XNU 加载器；见 Include/DXE.inc）
  #
  # stage 2a: 只加载驱动入口。它的 Boot() 仍拒绝非空设备树，因此不会触碰
  # SEC MMU 未映射的那棵 handed-over tree。
  DarwinBootPkg/Driver/DarwinBoot.inf {
    <LibraryClasses>
      # This loader uses only SHA256; no RNG operation is requested.
      RngLib|MdePkg/Library/BaseRngLibNull/BaseRngLibNull.inf
  }

  #
  # 板级驱动
  #
  #   FuxiBootMemoryDxe：把 DTB 里 /memory 描述的、GCD 还不认识的 DRAM 减去
  #   /reserved-memory 后加入系统内存，并把 /chosen 的 initrd 发布成只读 BlockIo。
  #   没有它，DXE 只有 fuxiPkg MemoryMapLib 那几条固定区可用。
  #
  #   FuxiKeyInputDxe：电源/音量键 → SimpleTextIn，菜单导航必需。
  #
  # disabled for bring-up, see Include/DXE.inc
  #fuxiPkg/Drivers/FuxiBootMemoryDxe/FuxiBootMemoryDxe.inf
!if $(FUXI_PAYLOAD_DIAGNOSTIC) == 1
  fuxiPkg/Drivers/FuxiPayloadDxe/FuxiPayloadDxe.inf
!endif
  fuxiPkg/Drivers/FuxiKeyInputDxe/FuxiKeyInputDxe.inf
