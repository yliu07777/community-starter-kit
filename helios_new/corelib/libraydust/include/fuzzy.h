#ifndef FUZZY_H
#define FUZZY_H
#include <openssl/evp.h>
#include "cuckoofilter.h"

#define MAX_IN_MEMORY_HASH_ENTRIES 65535
#define MAX_IN_MEMORY_GROUP_HASH_ENTRIES MAX_IN_MEMORY_HASH_ENTRIES

typedef struct fuzzy_hash_entry_ {
    STAILQ_ENTRY(fuzzy_hash_entry_) entry;
    char *filename;
    uint64_t md5[2];
    cuckoo_filter_t *filter;
} fuzzy_hash_entry_t;

typedef struct fuzzy_hash_group_ {
    STAILQ_ENTRY(fuzzy_hash_group_) entry;
    cuckoo_filter_t *filter;
    uint64_t md5[2];
    char *path;
    char *name;
    size_t total_size;
    struct filters {
	pthread_mutex_t lock;
	STAILQ_HEAD(fuzzy_hash_bucket, fuzzy_hash_entry_) head;
    } buckets[MAX_IN_MEMORY_GROUP_HASH_ENTRIES];
} fuzzy_hash_group_t;

int fuzzy_hash_filename(const char *filename);
int fuzzy_hash_stream(char *handle, size_t size, cuckoo_filter_t **result);
int fuzzy_hash_insert(const char *group, const char *path, const char *id, const char *md5_string, const char *filename);
int fuzzy_hash_delete(const char *group, const char *path, const char *id, const char *md5_string, const char *filename);
#endif
