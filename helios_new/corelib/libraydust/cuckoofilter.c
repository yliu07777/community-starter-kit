#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/queue.h>
#include <pthread.h>
#include <cuckoofilter.h>
#include <libraydust.h>

#define MAX_RETRY_COUNT 500

static inline size_t
index_hash(uint32_t hv, cuckoo_filter_t *filter) {
    return hv % filter->num_buckets;
}

static inline size_t
alt_index(size_t index, uint32_t tag, cuckoo_filter_t *filter) {
    return index_hash((uint32_t)(index ^ (tag * 0x5bd1e995)), filter);
}

static inline uint32_t
tag_hash(uint32_t hv) {
    uint32_t tag;
    tag = hv & TAG_MASK;
    tag += (tag == 0);
    return tag;
}

inline uint64_t
upperpower2(uint64_t x) {
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    x++;
    return x;
}

static inline cuckoo_filter_t *
cuckoo_filter_init(uint32_t total_items)
{
    cuckoo_filter_t *filter = calloc(sizeof(cuckoo_filter_t), 1);
    if (filter) {
        uint32_t num_buckets;
	num_buckets = upperpower2(ceilf((float)total_items / (float)ASSOC));
	float frac = (float)total_items /(float)num_buckets/(float)ASSOC;
	if (frac > 0.96) {
	    num_buckets <<= 1;
	}
	debug_print("Init filter for total %d items, num buckets %d\n",
		    total_items, num_buckets);
	filter->total_items = total_items;
	filter->num_buckets = num_buckets;
	filter->victim.used = FALSE;
	filter->buckets = calloc(sizeof(struct bucket_), num_buckets);
	if (filter->buckets)
	    return filter;
	free(filter);
	oom_errors ++;
	error_print("Failed to allocate buckets for filter\n");
    } else {
	error_print("Failed to allcate filter memroy\n");
	oom_errors ++;
    }
    return NULL;
}

static inline
void write_tag(size_t index, size_t pos, uint32_t t, cuckoo_filter_t *filter)
{
    char *p = filter->buckets[index].bits;
    uint32_t tag = t & TAG_MASK;

    switch(BITS_PER_TAG) {
    case 2:
	*((uint8_t*) p) |= tag << (2 * pos);
	break;
    case 4:
	p += (pos >> 1);
	if ( (pos & 1) == 0) {
	    *((uint8_t*) p)  &= 0xf0;
	    *((uint8_t*) p)  |= tag;
	}
	else {
	    *((uint8_t*) p)  &= 0x0f;
	    *((uint8_t*) p)  |= (tag << 4);
	}
	break;
    case 8:
	((uint8_t*) p)[pos] =  tag;
	break;
    case 12:
	p += (pos + (pos >> 1));
	if ( (pos & 1) == 0) {
	    ((uint16_t*) p)[0] &= 0xf000;
	    ((uint16_t*) p)[0] |= tag;
	}
	else {
	    ((uint16_t*) p)[0] &= 0x000f;
	    ((uint16_t*) p)[0] |= (tag << 4);
	}
	break;
    case 16:
	((uint16_t*) p)[pos] = tag;
	break;
    case 32:
	((uint32_t*) p)[pos] = tag;
	break;
    }
    return ;
}

static inline uint32_t
read_tag_and_check(size_t index, size_t pos, uint32_t tag_to_check, cuckoo_filter_t *filter)
{
    const char *p = filter->buckets[index].bits;
    uint32_t tag;

    switch (BITS_PER_TAG) {
    case 2:
	tag = *((uint8_t *)p) >> (pos *2);
	break;
    case 4:
	p += (pos >> 1);
	tag = *((uint8_t *)p) >> ((pos & 1) << 2);
	break;
    case 8:
	p += pos;
	tag = *((uint8_t*) p);
	break;
    case 12:
	p += pos + (pos >> 1);
	tag = *((uint16_t*) p) >> ((pos & 1) << 2);
	break;
    case 16:
	p += (pos << 1);
	tag = *((uint16_t*) p);
	break;
    case 32:
	tag = ((uint32_t *)p)[pos];
    }

    if (tag_to_check) {
	if (tag ^ tag_to_check)
	    return tag & TAG_MASK;
	error_print("Tag 0x%X is already exist in index %ld\n", tag, index);
	return ERROR;
    }
    return tag;
}

static inline int
match_tag_at_alt_index(cuckoo_filter_t *filter, size_t index, uint32_t tag)
{
    size_t j;
    for (j = 0; j < TAG_PER_BUCKET; j++) {
	if (!read_tag_and_check(index, j, tag,filter)) return 1;
    }
    return 0;
}

static inline size_t
match_buckets(cuckoo_filter_t *orig, cuckoo_filter_t *new, size_t index, int num_buckets)
{
    size_t j, k;
    size_t fp_count = 0;
    uint32_t tags1[TAG_PER_BUCKET];
    uint32_t tags2[TAG_PER_BUCKET];
    size_t alt_index;

    for (j = 0 ; j < TAG_PER_BUCKET; j ++) {
	tags1[j] = read_tag_and_check(index, j, 0, orig);
	tags2[j] = read_tag_and_check(index, j, 0, new);
    }

    for (j = 0; j < TAG_PER_BUCKET; j ++) {
	for (k = 0; k < TAG_PER_BUCKET; k ++) {
	    if (tags2[k] == 0) continue;
	    if (tags1[j] != 0){
		if (!(tags1[j] ^ tags2[k])) {
		    fp_count ++;
		    continue;
		}
	    } else {
		break;
	    }
	}
	alt_index = index;
	alt_index = (alt_index ^ (tags2[j] * 0x5bd1e995)) % num_buckets;
	if (match_tag_at_alt_index(orig, alt_index, tags2[j]) == 1) {fp_count ++;}
    }
    return fp_count;
}


void
cuckoo_filter_destroy(cuckoo_filter_t *filter)
{
    if (filter) {
	if (filter->buckets)
	    free(filter->buckets);
	free(filter);
    }
}

cuckoo_filter_t *
cuckoo_filter_create(uint64_t hv, uint32_t total_items) {
    cuckoo_filter_t *filter;
    filter = cuckoo_filter_init(total_items);
    if(filter) {
	if (cuckoo_filter_add(hv, filter) == OK) {
	    error_print("New filter is created\n");
	    return filter;
	}
	cuckoo_filter_destroy(filter);
    }
    error_print("Failed to create filter\n");
    return NULL;
}

void
cuckoo_filter_delete(cuckoo_filter_t *base, cuckoo_filter_t *source)
{
    if (!base || !source) return;
    return;
}

int
cuckoo_filter_insert_tag_bucket(size_t index, uint32_t tag, int kickout,
				uint32_t *oldtag, cuckoo_filter_t *filter)
{
    int j;
    debug_print("%s -- %d, tag per bucket %d\n", __FUNCTION__, __LINE__,
		TAG_PER_BUCKET);
    for (j = 0; j < TAG_PER_BUCKET; j ++) {
	int32_t res;
	res = read_tag_and_check(index, j, tag, filter);
	if (res == 0) {
	    debug_print("Insert tag %x to post: %d at index %ld\n", tag, j, index);
	    write_tag(index, j, tag, filter);
	    return OK;
	}
	/*
	 * Tag is already exist
	 */
	if (res == ERROR) {
	    return OK;
	}
    }
    if (kickout) {
	size_t r = rand() % TAG_PER_BUCKET;
	*oldtag = read_tag_and_check(index, r, 0, filter);
	write_tag(index, r, tag, filter);
    }
    return ERROR;
}


static int
cuckoo_filter_add_internal(size_t index, uint32_t tag, cuckoo_filter_t *filter) {
    size_t curindex = index;
    uint32_t curtag = tag;
    uint32_t oldtag;
    uint32_t count = 0;

    for (count = 0; count < MAX_RETRY_COUNT; count ++) {
	int kickout = count > 0;
	oldtag = 9;
	if (cuckoo_filter_insert_tag_bucket(curindex, curtag, kickout, &oldtag, filter) == OK) {
	    return OK;
	}
	if (kickout) {
	    curtag = oldtag;
	}
	curindex = alt_index(curindex, curtag, filter);
    }
    debug_print("%s - %d filter is full\n",__FUNCTION__, __LINE__);
    filter->victim.index = curindex;
    filter->victim.tag = curtag;
    filter->victim.used = TRUE;
    return OK;
}

int
cuckoo_filter_add(uint64_t hv, cuckoo_filter_t *filter)
{
    size_t index = index_hash((uint32_t)(hv >> 32), filter);
    uint32_t tag = tag_hash((uint32_t)(hv & 0xffffffff));

    if (filter->victim.used == TRUE) {
	error_print("Filter is full\n");
	return NO_ENOUGH_SPACE;
    }
    return cuckoo_filter_add_internal(index, tag, filter);
}


int
cuckoo_filter_match(cuckoo_filter_t *orig, cuckoo_filter_t *new)
{
    /* for the given index in one table, check for the tags at the same index in the other table
     * match the tags, if one tag found, implies one chunk found
     *
     * ASSUMPTION: comparing similar sized buckets only at present
     */

    size_t chunk_count = 0;
    int i;
    int num_buckets = orig->num_buckets > new->num_buckets ?\
	new->num_buckets : orig->num_buckets;
    for (i = 0 ; i < num_buckets; i++) {
	chunk_count += match_buckets(orig, new, i, num_buckets);
    }
    return 100 * chunk_count / new->chunk_count;
}

void cuckoo_filter_dump(cuckoo_filter_t *filter, const char * prefix)
{
    unsigned int i;
    if (!filter) return;
    printf("%snumber buckets %d, total_items %d, chunk counts %d\n",
	   prefix, filter->num_buckets, filter->total_items, filter->chunk_count);
    printf("%svictim, index:%ld, tag:%d, used:%d\n",
	   prefix,filter->victim.index,
	   filter->victim.tag, filter->victim.used);
    for (i = 0; i < filter->num_buckets; i++)
    {
	int j;
	printf ("%s index: %d, tags: ", prefix, i);
	for (j = 0; j < TAG_PER_BUCKET; j ++)
	{
	    printf("0x%x", ((uint32_t *)filter->buckets[i].bits)[j]);
	    if ((j + 1) < TAG_PER_BUCKET) {
		printf(", ");
	    } else {
		printf("\n");
	    }
	}
    }
}
