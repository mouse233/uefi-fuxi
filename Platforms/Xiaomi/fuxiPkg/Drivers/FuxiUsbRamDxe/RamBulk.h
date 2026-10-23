// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef FUXI_RAM_BULK_H
#define FUXI_RAM_BULK_H
#ifdef RAMBULK_UEFI
#include <Uefi.h>
typedef UINT8 RB8;
typedef UINT16 RB16;
typedef UINT32 RB32;
typedef UINT64 RB64;
#else
#include <stdint.h>
typedef uint8_t RB8;
typedef uint16_t RB16;
typedef uint32_t RB32;
typedef uint64_t RB64;
#endif
#define RB_HEADER 64
#define RB_CHUNK 65536
#define RB_OBJECTS 3
#define RB_TOTAL_LIMIT (10ULL << 30)
enum { RbHello=1, RbBegin, RbData, RbEnd, RbAbort };
enum { RbOk=0, RbBadHeader, RbBadObject, RbBadState, RbBadLength,
       RbBadOffset, RbBadHash, RbNoMemory };
typedef struct {
  RB8 *Data;
  RB64 Bytes, Received;
  RB8 Digest[32];
  unsigned State; // 0 empty, 1 receiving, 2 verified, 3 poisoned
} RB_OBJECT;
typedef struct {
  void *Context;
  void *(*Allocate)(void *, RB64);
  void (*Release)(void *, void *, RB64);
  int (*Hash)(const void *, RB64, RB8[32]);
  RB_OBJECT Object[RB_OBJECTS];
  RB64 Allocated;
} RB_SESSION;
RB64 RbRead(const RB8 *, unsigned);
void RbWrite(RB8 *, RB64, unsigned);
int RbHeaderLength(const RB8[RB_HEADER], RB32 *);
void RbHandle(RB_SESSION *, const RB8[RB_HEADER], const RB8 *, RB32, RB8[RB_HEADER]);
void RbClear(RB_SESSION *);
#endif
