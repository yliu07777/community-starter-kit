#ifndef __CUCKOO_FILTER_H___
#define __CUCKOO_FILTER_H___

#define BITS_PER_TAG 32
#define TAG_PER_BUCKET 4
#define TAG_MASK ((1ULL << BITS_PER_TAG) - 1)
#define BYTES_PER_BUCKET (BITS_PER_TAG * TAG_PER_BUCKET + 7) >> 3
#define ASSOC 4

typedef struct {
    size_t index;
    uint32_t tag;
    uint32_t used;
} victim_cache_t;

struct bucket_ {
    char bits[BYTES_PER_BUCKET];
}__attribute__((__packed__));

typedef struct cuckoo_filter_ {
    uint32_t num_buckets;
    uint32_t total_items;
    uint32_t chunk_count;
    victim_cache_t  victim;
    struct bucket_ *buckets;
} cuckoo_filter_t;

// inspired from http://www-graphics.stanford.edu/~seander/bithacks.html#ZeroInWord
#define haszero4(x) (((x) - 0x1111ULL) & (~(x)) & 0x8888ULL)
#define hasvalue4(x,n) (haszero4((x) ^ (0x1111ULL * (n))))

#define haszero8(x) (((x) - 0x01010101ULL) & (~(x)) & 0x80808080ULL)
#define hasvalue8(x,n) (haszero8((x) ^ (0x01010101ULL * (n))))

#define haszero12(x) (((x) - 0x001001001001ULL) & (~(x)) & 0x800800800800ULL)
#define hasvalue12(x,n) (haszero12((x) ^ (0x001001001001ULL * (n))))

#define haszero16(x) (((x) - 0x0001000100010001ULL) & (~(x)) & 0x8000800080008000ULL)
#define hasvalue16(x,n) (haszero16((x) ^ (0x0001000100010001ULL * (n))))

int
cuckoo_filter_add(uint64_t hv, cuckoo_filter_t *filter);
cuckoo_filter_t *
cuckoo_filter_create(uint64_t hv, uint32_t total_items);
void
cuckoo_filter_destroy(cuckoo_filter_t *filter);
int
cuckoo_filter_match(cuckoo_filter_t *orig, cuckoo_filter_t *new);
void
cuckoo_filter_delete(cuckoo_filter_t *base, cuckoo_filter_t *source);
void
cuckoo_filter_dump(cuckoo_filter_t *filter, const char * prefix);

#endif
