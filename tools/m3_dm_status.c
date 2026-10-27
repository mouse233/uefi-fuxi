// SPDX-License-Identifier: BSD-2-Clause-Patent
// Read-only DM_TABLE_STATUS for this device. Only validated nonsecret fields
// are printed; a non-redacted key field or unknown layout fails closed.
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/dm-ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <unistd.h>

typedef struct {
  uint64_t iv, start;
  unsigned major, minor, sector_size;
  int iv_large, wrapped, discards;
} MAPPING;

static int number(const char *s, uint64_t *out) {
  char *end;
  unsigned long long value;
  const char *p;
  if (!s || !*s) return 0;
  for (p=s; *p; ++p) if (*p<'0' || *p>'9') return 0;
  errno=0; value=strtoull(s,&end,10);
  if (errno || *end) return 0;
  *out=(uint64_t)value;
  return 1;
}

// Parameters are modified in place and never printed. Only '-' is accepted
// for the key field; any other value causes rejection without echoing it.
static int parse(char *parameters, MAPPING *m) {
  char *parts[16], *save=NULL, *token, *colon;
  uint64_t iv, start, major, minor, count=0, sector;
  size_t n=0, i;
  int seen_sector=0;
  memset(m,0,sizeof(*m)); m->sector_size=512;
  for (token=strtok_r(parameters," \t\r\n",&save); token;
       token=strtok_r(NULL," \t\r\n",&save)) {
    if (n==16) return 0;
    parts[n++]=token;
  }
  if (n<5 || strcmp(parts[0],"aes-xts-plain64") || strcmp(parts[1],"-")) return 0;
  if (!number(parts[2],&iv) || !number(parts[4],&start)) return 0;
  colon=strchr(parts[3],':');
  if (!colon || strchr(colon+1,':')) return 0;
  *colon=0;
  if (!number(parts[3],&major) || !number(colon+1,&minor) || major>UINT32_MAX || minor>UINT32_MAX) return 0;
  if (n>5 && (!number(parts[5],&count) || count!=n-6 || count>8)) return 0;
  for (i=6; i<n; ++i) {
    if (!strcmp(parts[i],"iv_large_sectors") && !m->iv_large) m->iv_large=1;
    else if (!strcmp(parts[i],"wrappedkey_v0") && !m->wrapped) m->wrapped=1;
    else if (!strcmp(parts[i],"allow_discards") && !m->discards) m->discards=1;
    else if (!strncmp(parts[i],"sector_size:",12) && !seen_sector &&
             number(parts[i]+12,&sector) && (sector==512 || sector==1024 || sector==2048 || sector==4096)) {
      m->sector_size=(unsigned)sector; seen_sector=1;
    }
    else return 0;
  }
  m->iv=iv; m->start=start; m->major=(unsigned)major; m->minor=(unsigned)minor;
  return 1;
}

static void wipe(void *buffer, size_t length) {
  volatile unsigned char *p=buffer;
  while (length--) *p++=0;
}

// Kernel status may report an aligned next offset beyond the returned data
// size; clamp to returned bytes before searching for the terminating NUL.
static int status_end(size_t start, size_t size, size_t next, size_t capacity, size_t *end) {
  if (size>capacity || start>size || next<sizeof(struct dm_target_spec) || next>capacity-start)
    return 0;
  *end=start+next;
  if (*end>size) *end=size;
  return *end>=start+sizeof(struct dm_target_spec)+1;
}

static int selftest(void) {
  MAPPING m;
  size_t end;
  char good[]="aes-xts-plain64 - 0 8:32 0 4 allow_discards sector_size:4096 iv_large_sectors wrappedkey_v0";
  char secret[]="aes-xts-plain64 should-never-be-emitted 0 8:32 0";
  char malformed[]="aes-xts-plain64 - 0 8:32 0 2 sector_size:4096";
  char unknown[]="aes-xts-plain64 - 0 8:32 0 1 unknown";
  char duplicate[]="aes-xts-plain64 - 0 8:32 0 2 sector_size:512 sector_size:4096";
  char offset[]="aes-xts-plain64 - 40 8:32 24 2 sector_size:4096 iv_large_sectors";
  assert(parse(good,&m) && m.sector_size==4096 && m.iv_large && m.wrapped && m.discards && m.major==8 && m.minor==32);
  assert(!parse(secret,&m)); assert(!parse(malformed,&m)); assert(!parse(unknown,&m)); assert(!parse(duplicate,&m));
  assert(parse(offset,&m) && m.iv==40 && m.start==24 && !m.wrapped);
  assert(status_end(312,446,136,16384,&end) && end==446);
  assert(!status_end(312,320,136,16384,&end));
  puts("DM status sanitizer selftest passed");
  return 0;
}

static int probe(void) {
  enum { BUFFER_BYTES=16384 };
  struct rlimit core={0,0};
  struct dm_ioctl *io;
  struct dm_target_spec *spec;
  MAPPING mapping;
  char *buffer, *parameters;
  size_t end, available;
  uint64_t begin, length;
  int fd, ok=0, error_number=0;
  uint32_t trace_start=0, trace_size=0, trace_next=0;
  const char *stage="open";
  if (setrlimit(RLIMIT_CORE,&core)) return 1;
  buffer=calloc(1,BUFFER_BYTES);
  if (!buffer) return 1;
  io=(struct dm_ioctl *)buffer;
  io->version[0]=4; io->data_size=BUFFER_BYTES; io->data_start=sizeof(*io);
  io->flags=DM_STATUS_TABLE_FLAG;
  memcpy(io->name,"userdata",sizeof("userdata"));
  fd=open("/dev/device-mapper",O_RDONLY|O_CLOEXEC);
  if (fd<0) { error_number=errno; goto done; }
  stage="ioctl";
  if (ioctl(fd,DM_TABLE_STATUS,io)<0) { error_number=errno; close(fd); goto done; }
  close(fd);
  trace_start=io->data_start; trace_size=io->data_size;
  stage="header";
  if ((io->flags&DM_BUFFER_FULL_FLAG) || !(io->flags&DM_ACTIVE_PRESENT_FLAG) ||
      io->target_count!=1 || io->data_size>BUFFER_BYTES ||
      io->data_start>io->data_size || io->data_start%_Alignof(struct dm_target_spec) ||
      io->data_size-io->data_start<sizeof(*spec)) goto done;
  stage="target";
  spec=(struct dm_target_spec *)(buffer+io->data_start);
  trace_next=spec->next;
  if (!memchr(spec->target_type,0,sizeof(spec->target_type)) || strcmp(spec->target_type,"default-key")) goto done;
  stage="bounds";
  if (!status_end(io->data_start,io->data_size,spec->next,BUFFER_BYTES,&end)) goto done;
  parameters=(char *)(spec+1); available=end-(size_t)(parameters-buffer);
  if (!memchr(parameters,0,available)) goto done;
  begin=spec->sector_start; length=spec->length;
  stage="format-or-redaction";
  if (!length || !parse(parameters,&mapping)) goto done;
  // No raw parameters or key-like fields are ever printed.
  printf("{\"target\":\"default-key\",\"cipher\":\"aes-xts-plain64\","
         "\"key_field_redacted\":true,\"target_begin_512\":%" PRIu64 ","
         "\"target_length_512\":%" PRIu64 ",\"iv_offset_512\":%" PRIu64 ","
         "\"device_start_512\":%" PRIu64 ",\"backing_major\":%u,\"backing_minor\":%u,"
         "\"sector_size\":%u,\"iv_large_sectors\":%s,\"wrappedkey_v0\":%s,\"allow_discards\":%s}\n",
         begin,length,mapping.iv,mapping.start,mapping.major,mapping.minor,mapping.sector_size,
         mapping.iv_large?"true":"false",mapping.wrapped?"true":"false",mapping.discards?"true":"false");
  ok=1;
done:
  wipe(buffer,BUFFER_BYTES); free(buffer);
  if (!ok) fprintf(stderr,"DM status unavailable: stage=%s errno=%d start=%u size=%u next=%u\n",
                   stage,error_number,trace_start,trace_size,trace_next);
  return ok?0:1;
}

int main(int argc, char **argv) {
  if (argc==2 && !strcmp(argv[1],"--selftest")) return selftest();
  if (argc==2 && !strcmp(argv[1],"--probe")) return probe();
  fputs("usage: m3_dm_status --selftest|--probe\n",stderr);
  return 2;
}
