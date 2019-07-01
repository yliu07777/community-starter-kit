#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "libraydust.h"

int sha1hash(const char *inbuf, size_t in_size, char *outbuf, unsigned int *out_size)
{
    EVP_MD_CTX mdctx;
    int ret;

    if (EVP_DigestInit(&mdctx, EVP_sha1()) == 0)
	return ERROR;
    if (EVP_DigestUpdate(&mdctx, (const void*) inbuf, in_size) == 0) {
	EVP_MD_CTX_cleanup(&mdctx);
	return ERROR;
    }
    ret = EVP_DigestFinal_ex(&mdctx, (unsigned char *)outbuf, out_size);
    EVP_MD_CTX_cleanup(&mdctx);
    if (ret == 0)
	return ERROR;
    return OK;
}

int md5hash(const char *inbuf, size_t in_size, char *outbuf, unsigned int *out_size)
{
    EVP_MD_CTX mdctx;
    int ret;

    if (EVP_DigestInit(&mdctx, EVP_md5()) == 0)
	return ERROR;

    if (EVP_DigestUpdate(&mdctx, (const void*) inbuf, in_size) == 0) {
	EVP_MD_CTX_cleanup(&mdctx);
	return ERROR;
    }
    ret = EVP_DigestFinal_ex(&mdctx, (unsigned char *)outbuf, out_size);
    EVP_MD_CTX_cleanup(&mdctx);
    if (ret == 0) return ERROR;
    return OK;
}
