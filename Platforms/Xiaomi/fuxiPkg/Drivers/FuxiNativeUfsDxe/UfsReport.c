// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded text only. No allocation, MMIO, DMA, timer, or storage dependency.
#include "UfsReport.h"
VOID FnuReportAppend(FNU_REPORT *Report, CONST CHAR16 *Line) {
  UINTN I = 0;
  CHAR16 *Destination;
  if (Report == NULL || Line == NULL || Report->Sealed) return;
  if (Report->Count >= FNU_REPORT_LINES) { ++Report->Dropped; return; }
  Destination = Report->Lines[Report->Count++];
  while (I + 1 < FNU_REPORT_CHARS && Line[I] != 0) {
    Destination[I] = Line[I];
    ++I;
  }
  if (Line[I] != 0) ++Report->Truncated;
  while (I > 0 && (Destination[I - 1] == L'\n' || Destination[I - 1] == L'\r')) --I;
  Destination[I] = 0;
}
VOID FnuReportReplay(CONST FNU_REPORT *Report, FNU_REPORT_EMIT Emit) {
  UINTN I;
  if (Report == NULL || Emit == NULL || !Report->Sealed) return;
  for (I = 0; I < Report->Count && I < FNU_REPORT_LINES; ++I) Emit(Report->Lines[I]);
}
