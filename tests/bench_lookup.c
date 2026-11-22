#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define AZK_HDR_SIZE   32
#define AZK_SLOT_SIZE  88
#define AZK_NAME_LEN   64
#define AZK_VERSION    1

static inline uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static inline uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static inline uint64_t fnv1a64(const char *s, size_t n) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001B3ULL; }
    return h ? h : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <risk_table.bin>\n", argv[0]);
        return 1;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    struct stat st;
    fstat(fd, &st);
    uint8_t *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    uint32_t nslots = rd32(map + 8);
    const char *test_names[] = {
        "alice@LAB.TEST", "user01@LAB.TEST", "user25@LAB.TEST",
        "user50@LAB.TEST", "nonexistent@LAB.TEST", "dummy_0010@LAB.TEST",
        "dummy_2500@LAB.TEST", "dummy_4999@LAB.TEST"
    };
    int n_names = sizeof(test_names)/sizeof(test_names[0]);

    const int ITERS = 1000000;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    volatile uint32_t hits = 0;
    for (int k = 0; k < ITERS; k++) {
        const char *name = test_names[k % n_names];
        size_t nl = strlen(name);
        uint64_t h = fnv1a64(name, nl);
        uint32_t i = (uint32_t)(h & (nslots - 1));
        for (uint32_t probes = 0; probes < nslots; probes++) {
            const uint8_t *s = map + AZK_HDR_SIZE + (size_t)i * AZK_SLOT_SIZE;
            uint64_t key = rd64(s);
            if (key == 0) break;
            if (key == h && memcmp(s + 8, name, nl) == 0 && s[8 + nl] == 0) {
                hits++;
                break;
            }
            i = (i + 1) & (nslots - 1);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed_ns = (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
    double ns_per_lookup = elapsed_ns / ITERS;
    printf("Slots: %u | Lookups: %d | Total: %.3f ms | Per-lookup: %.1f ns | Hits: %u\n",
           nslots, ITERS, elapsed_ns / 1e6, ns_per_lookup, hits);

    munmap(map, st.st_size);
    return 0;
}
