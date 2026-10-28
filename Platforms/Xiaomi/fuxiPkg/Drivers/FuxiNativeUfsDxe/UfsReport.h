// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef FUXI_UFS_REPORT_H
#define FUXI_UFS_REPORT_H
#include <Uefi.h>
#define FNU_REPORT_LINES 128U
#define FNU_REPORT_CHARS 192U
typedef struct {
  UINTN Count, Dropped, Truncated;
  BOOLEAN Sealed;
  CHAR16 Lines[FNU_REPORT_LINES][FNU_REPORT_CHARS];
} FNU_REPORT;
typedef VOID (*FNU_REPORT_EMIT)(CONST CHAR16 *Line);
VOID FnuReportAppend(FNU_REPORT *Report, CONST CHAR16 *Line);
VOID FnuReportReplay(CONST FNU_REPORT *Report, FNU_REPORT_EMIT Emit);
#endif
