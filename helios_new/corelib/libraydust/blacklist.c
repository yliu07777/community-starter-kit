#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Python.h>
#include "libraydust.h"

char ip_blacklist_check_docs[] = "Check if the ip address is in the blacklist";

PyObject *
ip_blacklist_check(PyObject *self, PyObject *args)
{
    const char *ip_string;

    if (!PyArg_ParseTuple(args, "s", &ip_string)) {
	return NULL;
    }

    printf("%s is called with ip %s\n", __FUNCTION__, ip_string);

    Py_RETURN_NONE;
}
