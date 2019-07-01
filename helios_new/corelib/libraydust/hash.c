#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Python.h>
#include "libraydust.h"

char file_hash_query_docs[] = "Query hash of the file";

PyObject *
file_hash_query(PyObject *self, PyObject *args)
{
    const char *md5;
    const char *hash_method;

    if (!PyArg_ParseTuple(args, "ss", &md5, &hash_method)) {
	return NULL;
    }

    printf("%s is called with md5 %s, hash %s\n", __FUNCTION__, md5, hash_method);
    Py_RETURN_NONE;
}
