#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <alloca.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <pthread.h>
#include <libraydust.h>
#include <queue_priv.h>
#include <math.h>
#include <ftw.h>
#include "fuzzy.h"
#include "hashutil.h"

#define ROLLING_WINDOW 7
#define BLOCK_SIZE              64
#define SKIPPED_BYTES           BLOCK_SIZE/4

int oom_errors = 0;
int insert_errors = 0;
typedef struct fuzzy_hash_table_ {
    pthread_mutex_t lock;
    STAILQ_HEAD(fuzzy_hash_group_bucket, fuzzy_hash_group_) bucket;
} fuzzy_hash_table_t;
fuzzy_hash_table_t fuzzy_hash_table[MAX_IN_MEMORY_HASH_ENTRIES];

static inline void
convert_md5(const char *md5_string, uint64_t *md50, uint64_t *md51)
{
    char tmp[17];

    memcpy(tmp, md5_string, 16);
    tmp[16]='\0';
    sscanf(tmp, "%lx", md50);
    sscanf(&md5_string[16], "%lx", md51);

}

__thread size_t total_dir_size = 0;
int sum(const char *fpath, const struct stat *sb, int typeflag) {
    if (typeflag == FTW_F || typeflag ==  FTW_D) {
	total_dir_size += sb->st_size;
    } else {
	debug_print("Skip counting for flag 0x%x\n", typeflag);
    }

    return 0;
}

static uint64_t
get_path_size(const char *path)
{
    if (!path || access(path, R_OK)) {
	error_print("%s-- wrong input %s \n", __FUNCTION__, path ? path:NULL);
        return ERROR;
    }
    if (ftw(path, &sum, 1)) {
	error_print("%s- cannot get size of %s, reason: %s\n", __FUNCTION__, path, strerror(errno));
        return ERROR;
    }
    return OK;
}

static inline char *
fuzzy_hash_map_file(const char *filename, size_t *size)
{
    struct stat st;
    size_t sz;
    void *fbuffer;
    int fd = open(filename, O_RDWR);
    if (fd < 0) {
	error_print("Cannot open file %s\n", filename);
	return NULL;
    }
    stat(filename, &st);
    sz = st.st_size;
    debug_print("Map file %s, size %ld\n", filename, sz);
    fbuffer = (char *)mmap(0, sz, PROT_READ, MAP_SHARED, fd, 0);
    if (fbuffer == (char *)-1) {
	error_print("Can not map file %s -- %s\n", filename, strerror(errno));
	return NULL;
    }
    close(fd);
    *size = sz;
    return fbuffer;
}

static inline void
fuzzy_hash_unmap_file(char *fbuffer, size_t size)
{
    munmap(fbuffer, size);
}

uint64_t
rolling_hash(char c, uint8_t *window, uint32_t* rhData) {
    rhData[2] -= rhData[1];
    rhData[2] += (ROLLING_WINDOW * c);

    rhData[1] += c;
    rhData[1] -= window[rhData[0] % ROLLING_WINDOW];

    window[rhData[0] % ROLLING_WINDOW] = c;
    rhData[0]++;

    /* The original spamsum AND'ed this value with 0xFFFFFFFF which
       in theory should have no effect. This AND has been removed
       for performance (jk) */
    rhData[3] = (rhData[3] << 5); //& 0xFFFFFFFF;
    rhData[3] ^= c;

    return rhData[1] + rhData[2] + rhData[3];
}

uint64_t
generate_index_tag_hash(const char *buff, uint32_t size){
    char hash_key[EVP_MAX_MD_SIZE];
    unsigned int hash_size = 0;
    if (sha1hash(buff, size, hash_key, &hash_size) == OK) {
	uint64_t hv;
        memcpy(&hv, hash_key, 8);
	return hv;
    }
    return ERROR;
}

static void
copy_block_to_buffer(char *byte_buffer, char *buff, uint32_t start, uint32_t stop)
{
    uint32_t i;
    for (i = start; i <= stop; i++){
	buff[i-start] = byte_buffer[i];
    }
}

cuckoo_filter_t *
fuzzy_cuckoo_filter_add(uint64_t hv, cuckoo_filter_t *filter, size_t total_size, int clean_up)
{
    cuckoo_filter_t *_filter = filter;

    if (_filter) {
	if (cuckoo_filter_add(hv, _filter) != OK) {
	    insert_errors ++;
	    if (clean_up) {
		cuckoo_filter_destroy(_filter);
	    }
	    _filter = NULL;
	}
    } else {
	debug_print("%s -- %d total_size %ld, block_size %d, ceil %d\n", __FUNCTION__, __LINE__,
		    total_size, BLOCK_SIZE, (uint32_t)ceilf((float)total_size/(float)BLOCK_SIZE/(float)2));
	_filter = cuckoo_filter_create(hv, (uint32_t)ceilf((float)total_size/(float)BLOCK_SIZE/(float)2));
	if (!_filter) {
	    insert_errors ++;
	}
    }
    return _filter;
}

int fuzzy_hash_stream(char *buffer, size_t size, cuckoo_filter_t **result){

    uint32_t i, total_chunks = 0, last_block_index = 0;
    int32_t block_size;
    uint32_t rhData[4] = {0};
    uint64_t rvalue;
    uint64_t hv;
    uint8_t window[ROLLING_WINDOW] = {0};
    cuckoo_filter_t *filter = NULL;
    //
    //  (Yi):
    //  I think the calculation of the max size for the cuckoo hash is
    //  still wrong. But let's fix the coding first before we get into
    //  the detail.
    //
    debug_print("%s -- %d, size %ld\n",__FUNCTION__, __LINE__, size);
    for (i = 0; i < size; i ++) {
	rvalue = rolling_hash(buffer[i], window, rhData);
	if ((rvalue % BLOCK_SIZE) == (BLOCK_SIZE -1)) {
	    char *buf;
	    total_chunks ++;
	    block_size = i - last_block_index;
	    buf = malloc(block_size);
	    if (!buf) {
		oom_errors ++;
		cuckoo_filter_destroy(filter);
		return ERROR;
	    }
	    copy_block_to_buffer(buffer, buf, last_block_index, i);
	    hv = generate_index_tag_hash(buf, block_size);
	    if(fuzzy_cuckoo_filter_add(hv, filter, size, 1) == NULL)
	    {
		free(buf);
		return ERROR;
	    }
	    filter->chunk_count++;
	    last_block_index = i + 1;
	    if((i + SKIPPED_BYTES)  < size)
		i += SKIPPED_BYTES;
	    free(buf);
	}
	hv = 0;
	block_size = 0;
    }
    block_size = i - last_block_index;
    if (block_size > 0 ){
	char *buff = malloc(block_size + 1);
	if (!buff) {
	    oom_errors ++;
	    cuckoo_filter_destroy(filter);
	    return ERROR;
	}
	copy_block_to_buffer(buffer, buff, last_block_index, i);
	hv = generate_index_tag_hash(buff, block_size);
	if (!fuzzy_cuckoo_filter_add(hv, filter, size, 1)) {
	    free(buff);
	    cuckoo_filter_destroy(filter);
	    return ERROR;
	}
    }
    *result = filter;
    return OK;
}


int fuzzy_hash_entry_buffer(char *buffer, size_t size, fuzzy_hash_entry_t *entry, fuzzy_hash_group_t *group)
{
    uint32_t i, total_chunks = 0, last_block_index = 0;
    int32_t block_size;
    uint32_t rhData[4] = {0};
    uint64_t rvalue;
    uint64_t hv;
    uint8_t window[ROLLING_WINDOW] = {0};
    cuckoo_filter_t *filter;

    debug_print("%s --size %ld, total %ld\n", __FUNCTION__, size, group->total_size);
    for (i = 0; i < size; i ++) {
	rvalue = rolling_hash(buffer[i], window, rhData);
	if ((rvalue % BLOCK_SIZE) == (BLOCK_SIZE -1)) {
	    char *buf;
	    total_chunks ++;
	    block_size = i - last_block_index;
	    buf = malloc(block_size + 1);
	    if (!buf) {
		oom_errors ++;
		cuckoo_filter_delete(group->filter, entry->filter);
		cuckoo_filter_destroy(entry->filter);
		error_print("%s - %d, failed to allocate temp buffer \n",__FUNCTION__, __LINE__);
		return ERROR;
	    }
	    copy_block_to_buffer(buffer, buf, last_block_index, i );
	    hv = generate_index_tag_hash(buf, block_size);
	    debug_print("Add tag to private policy\n");
	    filter = fuzzy_cuckoo_filter_add(hv, entry->filter, size, 0);
	    if (filter == NULL)
	    {
		cuckoo_filter_delete(group->filter, entry->filter);
		cuckoo_filter_destroy(entry->filter);
		free(buf);
		error_print("%s--%d, failed to add bucket to filter for file %s\n",
			    __FUNCTION__, __LINE__, entry->filename);
		return ERROR;
	    }
	    if (!entry->filter) {
		entry->filter = filter;
	    }
	    entry->filter->chunk_count ++;
	    debug_print("Add tag to group policy\n");
	    filter= fuzzy_cuckoo_filter_add(hv, group->filter, group->total_size, 0);
	    if (filter == NULL)
	    {
		cuckoo_filter_delete(group->filter, entry->filter);
		cuckoo_filter_destroy(entry->filter);
		entry->filter = NULL;
		free(buf);
		error_print("%s--%d, failed to add bucket to filter for group %s\n",
			    __FUNCTION__, __LINE__, group->name);
		return ERROR;
	    }
	    if (!group->filter)  group->filter = filter;
	    group->filter->chunk_count++;
	    last_block_index = i + 1;
	    if ( ( i + SKIPPED_BYTES) <  size) {
		i += SKIPPED_BYTES;
	    }
	    free(buf);
	}
	hv = 0;
	block_size = 0;
    }

    block_size = i - last_block_index;
    if (block_size > 0) {
	char *buff = malloc(block_size + 1);
	if (!buff) {
	    oom_errors ++;
	    cuckoo_filter_delete(group->filter, entry->filter);
	    cuckoo_filter_destroy(entry->filter);
	    entry->filter = NULL;
	    return ERROR;
	}
	copy_block_to_buffer(buffer, buff, last_block_index, i);
	hv = generate_index_tag_hash(buff, block_size);
	debug_print("Added left over to the private policy\n");
	if ((filter = fuzzy_cuckoo_filter_add(hv, entry->filter, size, 0)) == NULL) {
	    cuckoo_filter_delete(group->filter, entry->filter);
	    cuckoo_filter_destroy(entry->filter);
	    entry->filter = NULL;
	    free(buff);
	    error_print("%s--%d, failed to add bucket to filter for file %s\n",
			__FUNCTION__, __LINE__, entry->filename);
	    return ERROR;
	}
	if (!entry->filter) entry->filter = filter;
	entry->filter->chunk_count ++;
	debug_print("Added left over to the group policy\n");
	if ((filter = fuzzy_cuckoo_filter_add(hv, group->filter, group->total_size, 0)) == NULL)
	{
	    cuckoo_filter_delete(group->filter, entry->filter);
	    cuckoo_filter_destroy(entry->filter);
	    entry->filter = NULL;
	    free(buff);
	    error_print("%s--%d, failed to add bucket to filter for group %s\n",
			__FUNCTION__, __LINE__, group->name);
	    return ERROR;
	}
	if (!group->filter) group->filter = filter;
	group->filter->chunk_count++;
    }
    return OK;
}

int _fuzzy_hash_entry(fuzzy_hash_entry_t *entry, fuzzy_hash_group_t *group)
{
    char *fbuf;
    size_t size = 0;
    if (!entry || !group)
	return ERROR;
    fbuf = fuzzy_hash_map_file(entry->filename, &size);
    if (fbuf) {
	int status;
	status = fuzzy_hash_entry_buffer(fbuf, size, entry, group);
	fuzzy_hash_unmap_file(fbuf, size);
	return status;
    }
    return ERROR;
}

int _fuzzy_hash_filename(const char *filename, cuckoo_filter_t **filter)
{
    char *fbuf;
    size_t size = 0;

    fbuf = fuzzy_hash_map_file(filename, &size);
    if (fbuf) {
	int status;
	status = fuzzy_hash_stream(fbuf, size, filter);
	/* We cannot do anything about an fclose failure. */
	fuzzy_hash_unmap_file(fbuf, size);
	return status;
    }
    return ERROR;
}

int fuzzy_hash_filename(const char *filename){
    cuckoo_filter_t *filter;
    return _fuzzy_hash_filename(filename, &filter);
}


static inline void fuzzy_lock_table(fuzzy_hash_table_t *entry)
{
    pthread_mutex_lock(&entry->lock);
}

static inline void fuzzy_unlock_table(fuzzy_hash_table_t *entry)
{
    pthread_mutex_unlock(&entry->lock);
}

static inline fuzzy_hash_entry_t * alloc_fuzzy_hash_entry(const char *filename)
{

    fuzzy_hash_entry_t *entry;
    debug_print("Alloc hash entry for file %s\n", filename);
    entry = (fuzzy_hash_entry_t *)calloc(sizeof(fuzzy_hash_entry_t), 1);
    if (entry) {
	entry->filename = (char *)malloc(strlen(filename) + 1);
	if (entry->filename) {
	    memcpy(entry->filename, filename, strlen(filename));
	    entry->filename[strlen(filename)] = '\0';
	    return entry;
	}
	error_print("Failed to allocate filename memory\n");
	oom_errors ++;
	free(entry);
    } else {
	oom_errors ++;
	error_print("Failed to allocate hash entry\n");
    }

    return NULL;
}

static inline void fuzzy_hash_entry_destroy(fuzzy_hash_entry_t *entry)
{
    if(entry->filter)
	cuckoo_filter_destroy(entry->filter);
    if (entry->filename)  free(entry->filename);
    free(entry);
}

static inline fuzzy_hash_group_t *
fuzzy_hash_alloc_group(const char *name, const char *path, uint64_t md50, uint64_t md51)
{

    fuzzy_hash_group_t *group;

    group = (fuzzy_hash_group_t *)calloc(sizeof(fuzzy_hash_group_t), 1);
    if (group) {
	group->path = (char *)malloc(strlen(path)+1);
	if (group->path) {
	    memcpy(group->path, path, strlen(path));
	    group->path[strlen(path)] = '\0';
	    group->name = (char *)malloc(strlen(name)+1);
	    if (group->name) {
		int i;
		memcpy(group->name, name, strlen(name));
		group->name[strlen(name)] = '\0';
		group->md5[0] = md50;
		group->md5[1] = md51;
		for (i = 0; i < MAX_IN_MEMORY_GROUP_HASH_ENTRIES; i++) {
		    STAILQ_INIT(&group->buckets[i].head);
		    pthread_mutex_init(&group->buckets[i].lock, NULL);
		}
		get_path_size(group->path);
		group->total_size = total_dir_size;
		return group;
	    }

	    free(group->path);
	}
	error_print("Failed to allocate groupname memory\n");
	free(group);
	group = NULL;
    } else {
	error_print("Failed to allocate fuzzy hash group\n");
    }
    return group;
}

void fuzzy_hash_entry_lock(pthread_mutex_t *lock)
{
    pthread_mutex_lock(lock);
}

void fuzzy_hash_entry_unlock(pthread_mutex_t *lock)
{
    pthread_mutex_unlock(lock);
}

static inline void
fuzzy_hash_destroy_group(fuzzy_hash_group_t *group)
{
    int i;
    fuzzy_hash_entry_t *entry;

    if (!group) return;

    for (i=0; i < MAX_IN_MEMORY_GROUP_HASH_ENTRIES; i++) {
	fuzzy_hash_entry_lock(&group->buckets[i].lock);
	while(!STAILQ_EMPTY(&group->buckets[i].head)) {
	    entry = STAILQ_FIRST(&group->buckets[i].head);
	    STAILQ_REMOVE_HEAD(&group->buckets[i].head, entry);
	    fuzzy_hash_entry_destroy(entry);
	}
	fuzzy_hash_entry_lock(&group->buckets[i].lock);
    }
    if(group->path) free(group->path);
    if(group->name) free(group->name);
    free(group);
}

int
fuzzy_hash_delete(const char *group, const char *path, const char *id,
		  const char *md5_string, const char *filename)
{
    uint64_t md5[2];
    uint16_t hash_index;
    fuzzy_hash_table_t *db_entry;
    fuzzy_hash_group_t *entry, *tmp;

    convert_md5(md5_string, &md5[0], &md5[1]);
    hash_index = (uint16_t)(md5[0] & 0xffff);
    db_entry = &fuzzy_hash_table[hash_index];
    fuzzy_lock_table(db_entry);
    STAILQ_FOREACH_SAFE(entry, &db_entry->bucket, entry, tmp) {
	if ((entry->md5[0] == md5[0]) && (entry->md5[1] == entry->md5[1])) {
	    STAILQ_REMOVE(&db_entry->bucket, entry, fuzzy_hash_entry_, entry);
	    if (entry->filter) {
		fuzzy_hash_destroy_group(entry);
	    }
	    break;
	}
    }
    fuzzy_unlock_table(db_entry);
    return OK;
}

cuckoo_filter_t **
fuzzy_hash_similarity_lookup(const char *md5_string, const char *filename,
			     uint32_t max_return, uint32_t *total_return)
{
    uint16_t hash_index;
    fuzzy_hash_table_t *db_entry = NULL;
    fuzzy_hash_entry_t *entry = NULL;
    cuckoo_filter_t *filter = NULL, **filters;
    uint64_t md5[2];

    filters = (cuckoo_filter_t **)malloc(sizeof(void *) * max_return);
    if (!filters) {
	return NULL;
    }

    convert_md5(md5_string, &md5[0], &md5[1]);
    hash_index = (uint16_t)(md5[0] & 0xffff);
    db_entry = &fuzzy_hash_table[hash_index];
    fuzzy_lock_table(db_entry);
    STAILQ_FOREACH(entry, &db_entry->bucket, entry) {
	if ((entry->md5[0] == md5[0]) && (entry->md5[1] == entry->md5[1])) {
	    fuzzy_unlock_table(db_entry);
	    *total_return = 1;
	    filters[0] = entry->filter;
	    return filters;
	}
    }
    fuzzy_unlock_table(db_entry);
    if ((_fuzzy_hash_filename(filename, &filter) == OK) && filter){
	int i, score;
	uint32_t found = 0;
	for (i = 0; i < MAX_IN_MEMORY_HASH_ENTRIES; i ++) {
	    fuzzy_hash_table_t *db_entry = &fuzzy_hash_table[i];
	    fuzzy_lock_table(db_entry);
	    STAILQ_FOREACH(entry, &db_entry->bucket, entry) {
		score = cuckoo_filter_match(entry->filter, filter);
		if (score > 0 ) {
		    filters[found] = entry->filter;
		    found ++;
		}
		if (found >= max_return - 1) {
		    *total_return = found;
		    fuzzy_unlock_table(db_entry);
		    return filters;
		}
	    }
	    fuzzy_unlock_table(db_entry);
	}
	*total_return = found;
    }

    return filters;
}

int
fuzzy_hash_add_entry_to_group(fuzzy_hash_group_t *group, const char *filename,
			      const char *md5_string)
{
    uint16_t hash_index;
    uint64_t md50, md51;
    fuzzy_hash_entry_t *entry;
    //cuckoo_filter_t *filter = NULL;

    convert_md5(md5_string, &md50, &md51);
    hash_index = ((uint16_t)(md50 & MAX_IN_MEMORY_GROUP_HASH_ENTRIES)) - 1;
    fuzzy_hash_entry_lock(&group->buckets[hash_index].lock);
    STAILQ_FOREACH(entry, &group->buckets[hash_index].head, entry) {
	if ((entry->md5[0] == md50) && (entry->md5[1] == md51)) {
	    debug_print("Found exsiting entry\n");
	    fuzzy_hash_entry_unlock(&group->buckets[hash_index].lock);
	    return OK;
	}
    }
    fuzzy_hash_entry_unlock(&group->buckets[hash_index].lock);

    entry = alloc_fuzzy_hash_entry(filename);
    if (entry) {
	entry->md5[0] = md50;
	entry->md5[1] = md51;
    } else {
	error_print("Failed to allocate the hash entry\n");
	return ERROR;
    }
    debug_print("create new entry for %s\n", filename);
    if (_fuzzy_hash_entry(entry, group) == OK) {
	fuzzy_hash_entry_lock(&group->buckets[hash_index].lock);
	STAILQ_INSERT_HEAD(&group->buckets[hash_index].head, entry, entry);
	fuzzy_hash_entry_unlock(&group->buckets[hash_index].lock);
	return OK;
    }
    error_print("failed to hash the file %s\n", filename);
    fuzzy_hash_entry_destroy(entry);
    oom_errors ++;

    return ERROR;
}

int
fuzzy_hash_insert(const char *group, const char *path, const char *id,
		  const char *md5_string, const char *filename)
{
    uint16_t hash_index;
    fuzzy_hash_table_t *db_entry;
    fuzzy_hash_group_t *entry;
    fuzzy_hash_group_t *group_filter = NULL;
    uint64_t md50;
    uint64_t md51;

    convert_md5(id, &md50, &md51);
    hash_index = ((uint16_t)(md50 & MAX_IN_MEMORY_HASH_ENTRIES)) - 1;
    debug_print("md5 hash 0x%lx-0x%lx, index %d\n", md50, md51, hash_index);
    db_entry = &fuzzy_hash_table[hash_index];
    fuzzy_lock_table(db_entry);
    debug_print("Scan for duplication\n");
    STAILQ_FOREACH(entry, &db_entry->bucket, entry) {
	if ((entry->md5[0] == md50) && (entry->md5[1] == md51)) {
	    group_filter = entry;
            debug_print("group entry %s has already inserted\n", entry->name);
	    break;
	}
    }

    fuzzy_unlock_table(db_entry);
    if (!group_filter) {
	group_filter = fuzzy_hash_alloc_group(group, path, md50, md51);
	if (!group_filter) {
	    return ERROR;
	}
	debug_print("New fuzzy hash group created\n");
	fuzzy_lock_table(db_entry);
	STAILQ_INSERT_HEAD(&fuzzy_hash_table[hash_index].bucket, group_filter, entry);
	fuzzy_unlock_table(db_entry);
    }

    return fuzzy_hash_add_entry_to_group(group_filter, filename, md5_string);
}

void fuzzy_hash_dump_policy(void)
{
    int i, j;
    fuzzy_hash_group_t *group;
    fuzzy_hash_entry_t *entry;

    printf("===========Dump policy cache ==================\n");
    for (i = 0; i < MAX_IN_MEMORY_HASH_ENTRIES; i ++) {
	fuzzy_lock_table(&fuzzy_hash_table[i]);
	STAILQ_FOREACH(group, &fuzzy_hash_table[i].bucket, entry) {
	    printf("Policy group %s on path %s, total_size %ld\n", group->name, group->path, group->total_size);
	    printf("Key %lx%lx\n", group->md5[0], group->md5[1]);
	    printf("Filters: \n");
	    cuckoo_filter_dump(group->filter, "\t");
	    for (j = 0; j < MAX_IN_MEMORY_GROUP_HASH_ENTRIES; j++)
	    {
		fuzzy_hash_entry_lock(&group->buckets[j].lock);
		STAILQ_FOREACH(entry, &group->buckets[j].head, entry) {
		    printf("\t %s:, key %lx%lx\n", entry->filename, entry->md5[0], entry->md5[1]);
		    cuckoo_filter_dump(entry->filter, "\t\t");
		}
		fuzzy_hash_entry_unlock(&group->buckets[j].lock);
	    }
	}
	fuzzy_unlock_table(&fuzzy_hash_table[i]);
    }
     printf("oom error %d, insert error %d\n", oom_errors, insert_errors);
     printf("Paramters:\n");
     printf(" rolling windoes size %d, block size %d, skipped bytes %d\n",
	    ROLLING_WINDOW, BLOCK_SIZE, SKIPPED_BYTES);
}

int fuzzy_hash_init(void)
{
    int i;

    for (i = 0; i < MAX_IN_MEMORY_HASH_ENTRIES; i++) {
	pthread_mutex_init(&fuzzy_hash_table[i].lock, NULL);
	STAILQ_INIT(&fuzzy_hash_table[i].bucket);
    }
    return 0;
}
