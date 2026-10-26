// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "UfsReport.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned emitted;
static UINT64 checksum;
static VOID Emit(CONST CHAR16 *Line) {
  UINTN i;
  ++emitted;
  for (i = 0; Line[i] != 0; ++i) {
    assert(i < FNU_REPORT_CHARS - 1);
    checksum = checksum * 33 + Line[i];
    assert(Line[i] != L'\r' && Line[i] != L'\n');
  }
}

int main(void) {
  static struct { UINT64 before; FNU_REPORT report; UINT64 after; } guarded;
  static FNU_REPORT saved;
  CHAR16 large[300];
  FNU_REPORT *r = &guarded.report;
  UINTN i;
  UINT64 first;
  guarded.before = 0x123456789abcdef0ULL;
  guarded.after = ~guarded.before;
  FnuReportAppend(NULL, L"ignored");
  FnuReportAppend(r, NULL);
  FnuReportAppend(r, L"FUXIUFS GPT=Success\r\n");
  FnuReportReplay(r, Emit);
  assert(emitted == 0); // In-progress reports are never published/replayed.
  assert(r->Count == 1 && r->Lines[0][19] == 0);
  for (i = 0; i < 299; ++i) large[i] = L'x';
  large[299] = 0;
  FnuReportAppend(r, large);
  assert(r->Count == 2 && r->Truncated == 1);
  assert(r->Lines[1][FNU_REPORT_CHARS - 1] == 0);
  for (i = 2; i < FNU_REPORT_LINES; ++i) FnuReportAppend(r, L"cached line\n");
  FnuReportAppend(r, L"overflow");
  assert(r->Count == FNU_REPORT_LINES && r->Dropped == 1);
  r->Sealed = TRUE;
  memcpy(&saved, r, sizeof(saved));
  FnuReportAppend(r, L"late mutation");
  FnuReportReplay(NULL, Emit);
  FnuReportReplay(r, NULL);
  FnuReportReplay(r, Emit);
  assert(emitted == FNU_REPORT_LINES);
  first = checksum;
  emitted = 0; checksum = 0;
  FnuReportReplay(r, Emit);
  assert(emitted == FNU_REPORT_LINES && checksum == first);
  assert(memcmp(r, &saved, sizeof(saved)) == 0);
  assert(guarded.before == 0x123456789abcdef0ULL && guarded.after == ~guarded.before);
  puts("UFS report: bounds, CRLF, truncation, overflow, seal and repeat replay passed");
  return 0;
}
