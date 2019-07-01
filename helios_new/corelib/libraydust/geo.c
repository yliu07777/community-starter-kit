#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Python.h>
#include "libraydust.h"

char get_geo_location_by_ip_docs[] = "Get geo location by ip address";

PyObject *
get_geo_location_by_ip(PyObject *self, PyObject *args)
{
    /*
     * ip_string_get_geo_location
     */
    const char *ip_string;

    if (!PyArg_ParseTuple(args, "s", &ip_string)) {
	return NULL;
    }

    printf("%s is called with ip %s\n", __FUNCTION__, ip_string);

    Py_RETURN_NONE;
}
