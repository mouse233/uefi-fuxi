// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "UfsSha256.h"

#define ROTR(X, N) (((X) >> (N)) | ((X) << (32 - (N))))

STATIC CONST UINT32 K[64] = {
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
  0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
  0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
  0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
  0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
  0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
  0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
  0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
  0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
  0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

STATIC UINT32 LoadBe32(CONST UINT8 *P) {
  return ((UINT32)P[0] << 24) | ((UINT32)P[1] << 16) | ((UINT32)P[2] << 8) | (UINT32)P[3];
}

STATIC VOID Compress(UINT32 *State, CONST UINT8 *Block) {
  UINT32 W[64], A, B, C, D, E, F, G, H, T1, T2;
  UINTN I;
  for (I = 0; I < 16; ++I) W[I] = LoadBe32(Block + I * 4);
  for (I = 16; I < 64; ++I) {
    UINT32 S0 = ROTR(W[I - 15], 7) ^ ROTR(W[I - 15], 18) ^ (W[I - 15] >> 3);
    UINT32 S1 = ROTR(W[I - 2], 17) ^ ROTR(W[I - 2], 19) ^ (W[I - 2] >> 10);
    W[I] = W[I - 16] + S0 + W[I - 7] + S1;
  }
  A = State[0]; B = State[1]; C = State[2]; D = State[3];
  E = State[4]; F = State[5]; G = State[6]; H = State[7];
  for (I = 0; I < 64; ++I) {
    UINT32 S1 = ROTR(E, 6) ^ ROTR(E, 11) ^ ROTR(E, 25);
    UINT32 Ch = (E & F) ^ (~E & G);
    UINT32 S0 = ROTR(A, 2) ^ ROTR(A, 13) ^ ROTR(A, 22);
    UINT32 Maj = (A & B) ^ (A & C) ^ (B & C);
    T1 = H + S1 + Ch + K[I] + W[I];
    T2 = S0 + Maj;
    H = G; G = F; F = E; E = D + T1;
    D = C; C = B; B = A; A = T1 + T2;
  }
  State[0] += A; State[1] += B; State[2] += C; State[3] += D;
  State[4] += E; State[5] += F; State[6] += G; State[7] += H;
}

VOID FnuSha256Init(FNU_SHA256_CTX *Ctx) {
  UINTN I;
  static CONST UINT32 Initial[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
  };
  if (Ctx == NULL) return;
  for (I = 0; I < 8; ++I) Ctx->State[I] = Initial[I];
  Ctx->Bits = 0;
  Ctx->BufferBytes = 0;
}

VOID FnuSha256Update(FNU_SHA256_CTX *Ctx, CONST VOID *Data, UINTN Bytes) {
  CONST UINT8 *P = Data;
  if (Ctx == NULL || (Data == NULL && Bytes != 0)) return;
  Ctx->Bits += (UINT64)Bytes * 8;
  while (Bytes != 0) {
    UINTN Chunk = 64 - Ctx->BufferBytes;
    if (Chunk > Bytes) Chunk = Bytes;
    {
      UINTN I;
      for (I = 0; I < Chunk; ++I) Ctx->Buffer[Ctx->BufferBytes + I] = P[I];
    }
    Ctx->BufferBytes += Chunk;
    P += Chunk;
    Bytes -= Chunk;
    if (Ctx->BufferBytes == 64) {
      Compress(Ctx->State, Ctx->Buffer);
      Ctx->BufferBytes = 0;
    }
  }
}

VOID FnuSha256Final(FNU_SHA256_CTX *Ctx, UINT8 Digest[32]) {
  UINT64 Bits;
  UINTN I;
  UINT8 Pad;
  if (Ctx == NULL || Digest == NULL) return;
  Bits = Ctx->Bits;
  Pad = 0x80;
  FnuSha256Update(Ctx, &Pad, 1);
  Pad = 0;
  while (Ctx->BufferBytes != 56) FnuSha256Update(Ctx, &Pad, 1);
  {
    UINT8 Length[8];
    for (I = 0; I < 8; ++I) Length[I] = (UINT8)(Bits >> (56 - 8 * I));
    FnuSha256Update(Ctx, Length, 8);
  }
  for (I = 0; I < 8; ++I) {
    Digest[I * 4] = (UINT8)(Ctx->State[I] >> 24);
    Digest[I * 4 + 1] = (UINT8)(Ctx->State[I] >> 16);
    Digest[I * 4 + 2] = (UINT8)(Ctx->State[I] >> 8);
    Digest[I * 4 + 3] = (UINT8)Ctx->State[I];
  }
}
