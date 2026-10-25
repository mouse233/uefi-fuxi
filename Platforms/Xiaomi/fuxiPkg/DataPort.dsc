# SPDX-License-Identifier: BSD-2-Clause-Patent
# Standalone compile qualification; this DSC does not produce a bootable FD.
[Defines]
  PLATFORM_NAME = FuxiDataPort
  PLATFORM_GUID = 3C67FB7A-B8DE-49BB-9B96-D5487E130CBC
  PLATFORM_VERSION = 0.1
  DSC_SPECIFICATION = 0x0001001B
  OUTPUT_DIRECTORY = Build/FuxiDataPort
  SUPPORTED_ARCHITECTURES = AARCH64
  BUILD_TARGETS = DEBUG|RELEASE
  SKUID_IDENTIFIER = DEFAULT
  DEFINE FUXI_DATA_SCM_QUERY = 0

[LibraryClasses]
  ArmSmcLib|MdePkg/Library/ArmSmcLib/ArmSmcLib.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  StackCheckLib|MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf

[PcdsFixedAtBuild]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0

[Components]
  fuxiPkg/Drivers/FuxiDataProbeDxe/FuxiDataProbeDxe.inf {
    <BuildOptions>
      *_*_*_CC_FLAGS = -DFUXI_DATA_SCM_QUERY=$(FUXI_DATA_SCM_QUERY)
  }
