/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Opt-in fuxi DEBUG markers. Only x11-x15 and condition flags are scratch.
 * x0, x1 (payload pointer), x4/x5 (copy state), LR and SP remain intact.
 * Linear bands deliberately avoid assuming a framebuffer pixel stride.
 */
#if BOOT_STAGE_MARKERS
#if MARKER_FB_BASE != 0xB8000000 || MARKER_FB_SIZE != 0x02B00000
#error "Stage markers require the audited fuxi framebuffer reservation"
#endif
#if MARKER_BAND_SIZE != 0x40000
#error "Stage markers require two audited 256 KiB bands"
#endif
#if 2 * MARKER_BAND_SIZE > MARKER_FB_SIZE
#error "Stage marker bands exceed the framebuffer reservation"
#endif

.macro FuxiStageMarker offset, color
  ldr   x11, =(MARKER_FB_BASE + \offset)
  ldr   x12, =(MARKER_FB_BASE + \offset + MARKER_BAND_SIZE)
  ldr   w13, =\color
1:
  str   w13, [x11], #4
  cmp   x11, x12
  b.lo  1b

  /* Publish the band to the display DMA engine, even if a cache was enabled. */
  dsb   sy
  mrs   x14, ctr_el0
  ubfx  x14, x14, #16, #4
  mov   x15, #4
  lsl   x14, x15, x14
  ldr   x11, =(MARKER_FB_BASE + \offset)
2:
  dc    cvac, x11
  add   x11, x11, x14
  cmp   x11, x12
  b.lo  2b
  dsb   sy
.endm
#endif
