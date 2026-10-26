#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s FILE\n", argv[0]); return 2; }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    struct stat st;
    if (fstat(fd, &st) != 0) { perror("fstat"); return 1; }
    long long size = st.st_size;
    size_t n = 4096;
    struct fiemap *fm = malloc(sizeof(struct fiemap) + n * sizeof(struct fiemap_extent));
    unsigned long long min_pa = ~0ULL, max_pa = 0;
    int count = 0;
    printf("{\"size\":%lld,\"extents\":[", size);
    unsigned long long last_end = 0;
    int first = 1;
    while (last_end < (unsigned long long)size) {
        memset(fm, 0, sizeof(struct fiemap) + n * sizeof(struct fiemap_extent));
        fm->fm_start = last_end;
        fm->fm_length = (unsigned long long)size - last_end;
        fm->fm_extent_count = n;
        if (ioctl(fd, FS_IOC_FIEMAP, fm) < 0) { perror("ioctl"); return 1; }
        if (fm->fm_mapped_extents == 0) break;
        for (unsigned i = 0; i < fm->fm_mapped_extents; i++) {
            struct fiemap_extent *e = &fm->fm_extents[i];
            unsigned long long lo = e->fe_logical;
            unsigned long long po = e->fe_physical;
            unsigned long long ln = e->fe_length;
            printf("%s[%llu,%llu,%llu]", first ? "" : ",", lo, po, ln);
            first = 0;
            count++;
            if (po < min_pa) min_pa = po;
            if (po + ln > max_pa) max_pa = po + ln;
            last_end = lo + ln;
        }
        if (fm->fm_mapped_extents < n) break;
    }
    printf("],\"count\":%d,\"min_pa\":%llu,\"max_pa\":%llu}\n", count, min_pa == ~0ULL ? 0 : min_pa, max_pa);
    return 0;
}
