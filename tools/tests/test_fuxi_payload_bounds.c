// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exercise the real scanner with an actual FAT and malformed/ambiguous spans.
#include "../../Platforms/Xiaomi/fuxiPkg/Drivers/FuxiPayloadDxe/PayloadBounds.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main (int argc, char **argv)
{
  FILE *File;
  UINT8 *Fat;
  UINT8 *Combined;
  UINTN Offset;

  assert (argc == 2);
  File = fopen (argv[1], "rb");
  assert (File != NULL);
  Fat = malloc (FUXI_PAYLOAD_SIZE);
  Combined = malloc (2 * FUXI_PAYLOAD_SIZE + 31);
  assert (Fat != NULL && Combined != NULL);
  assert (fread (Fat, 1, FUXI_PAYLOAD_SIZE, File) == FUXI_PAYLOAD_SIZE);
  assert (fgetc (File) == EOF);
  fclose (File);
  assert (FuxiPayloadHeader (Fat, FUXI_PAYLOAD_SIZE));
  assert (!FuxiPayloadHeader (Fat, FUXI_PAYLOAD_SIZE - 1));
  assert (FuxiFindPayload (Fat, FUXI_PAYLOAD_SIZE, &Offset) && Offset == 0);
  memset (Combined, 0xA5, 31);
  memcpy (Combined + 31, Fat, FUXI_PAYLOAD_SIZE);
  assert (FuxiFindPayload (Combined, FUXI_PAYLOAD_SIZE + 31, &Offset) && Offset == 31);
  assert (!FuxiFindPayload (Combined, FUXI_PAYLOAD_SIZE + 30, &Offset));
  memcpy (Combined + 31 + FUXI_PAYLOAD_SIZE, Fat, FUXI_PAYLOAD_SIZE);
  assert (!FuxiFindPayload (Combined, 2 * FUXI_PAYLOAD_SIZE + 31, &Offset));
  Fat[39] ^= 1;
  assert (!FuxiFindPayload (Fat, FUXI_PAYLOAD_SIZE, &Offset));
  Fat[39] ^= 1;
  Fat[22] = 0;
  assert (!FuxiPayloadHeader (Fat, FUXI_PAYLOAD_SIZE));
  assert (!FuxiFindPayload (Fat, FUXI_INITRD_LIMIT + 1, &Offset));
  assert (!FuxiFindPayload (Fat, 0, &Offset));
  assert (FuxiContainsRange (0xA8000000, 0x10000000, 0xB7000000, 0x1000000));
  assert (!FuxiContainsRange (0xA8000000, 0x10000000, 0xB7000000, 0x1000001));
  assert (!FuxiContainsRange (0xA8000000, 0x10000000, 0xC5B1D0, 40));
  assert (!FuxiContainsRange (0xA8000000, 0x10000000, 0x0C400000, 40));
  assert (!FuxiContainsRange (0xA8000000, 0x10000000, MAX_UINT64 - 7, 40));
  assert (!FuxiContainsRange (MAX_UINT64 - 7, 16, MAX_UINT64 - 3, 1));
  assert (!FuxiContainsRange (0xA8000000, 0x10000000, 0xA8000000, 0));
  assert (!FuxiContainsRange (0xA8000000, 0x10000000, 0xB8000000, 1));
  free (Combined);
  free (Fat);
  puts ("fuxi payload scanner and range checks passed");
  return 0;
}
