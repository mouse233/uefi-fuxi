ARCH              = arm64
TARGET            = aarch64-linux-gnu
CC                = clang
CFLAGS            = --target=$(TARGET)
OBJCOPY           = llvm-objcopy

BOOT_STAGE_MARKERS ?= 0
MARKER_FB_BASE     ?= 0
MARKER_FB_SIZE     ?= 0
MARKER_BAND_SIZE   ?= 0

.PHONY: all FORCE
all: BootShim.elf BootShim.bin

FORCE:

BootShim.bin: BootShim.elf
	$(OBJCOPY) -O binary $< $@

BootShim.elf: BootShim.S StageMarkers.inc FORCE
	$(CC) ${CFLAGS} -c $< -o $@ -DREQUIRES_KERNEL_HEADER=$(REQUIRES_KERNEL_HEADER) -DFD_BASE=$(FD_BASE) -DFD_SIZE=$(FD_SIZE) -DBOOT_STAGE_MARKERS=$(BOOT_STAGE_MARKERS) -DMARKER_FB_BASE=$(MARKER_FB_BASE) -DMARKER_FB_SIZE=$(MARKER_FB_SIZE) -DMARKER_BAND_SIZE=$(MARKER_BAND_SIZE)

BootShim.S:
