// SPDX-License-Identifier: BSD-2-Clause-Patent
// Boot-services-only, immutable diagnostic text. Replay must never issue IO.
#ifndef FUXI_UFS_REPORT_PROTOCOL_H
#define FUXI_UFS_REPORT_PROTOCOL_H
#include <Uefi.h>
#define FUXI_UFS_REPORT_PROTOCOL_GUID \
  {0x6d8c0fc1, 0x6c29, 0x4df2, {0xb7, 0xd1, 0x84, 0x5e, 0x1b, 0x4c, 0xf2, 0x09}}
#define FUXI_UFS_REPORT_REVISION 1U
typedef struct {
  UINT32 Revision;
  VOID (EFIAPI *Replay)(VOID);
} FUXI_UFS_REPORT_PROTOCOL;
#endif
