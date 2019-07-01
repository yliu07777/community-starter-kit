#ifndef HASH_UTIL_H
#define HASH_UTIL_H
extern int sha1hash(const char *inbuf, size_t in_size, char *outbuf, unsigned int *out_size);
extern int md5hash(const char *inbuf, size_t in_size, char *outbuf, unsigned int *out_size);
#endif
