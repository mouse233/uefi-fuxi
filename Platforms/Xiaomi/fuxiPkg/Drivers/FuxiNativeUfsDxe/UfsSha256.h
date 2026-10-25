// SPDX-License-Identifier: BSD-2-Clause-Patent
// Independent SHA-256 (FIPS 180-4) for the native UFS diagnostics; the host
// tests check it against an independent implementation. No crypto library is
// linked and no key material passes through here.
#ifndef FUXI_UFS_SHA256_H
#define FUXI_UFS_SHA256_H
#include <Uefi.h>

typedef struct {
  UINT32 State[8];
  UINT64 Bits;
  UINT8 Buffer[64];
  UINTN BufferBytes;
} FNU_SHA256_CTX;

VOID FnuSha256Init(FNU_SHA256_CTX *Ctx);
VOID FnuSha256Update(FNU_SHA256_CTX *Ctx, CONST VOID *Data, UINTN Bytes);
VOID FnuSha256Final(FNU_SHA256_CTX *Ctx, UINT8 Digest[32]);

#endif
