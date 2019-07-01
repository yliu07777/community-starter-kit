#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Python.h>
#include "libraydust.h"

char ioc_session_close_docs[] = "session close event handler";
char ioc_session_create_docs[] = "session create event handler";

PyObject *
ioc_session_close(PyObject *self, PyObject *args)
{
    int src_ip;
    int src_port;
    int dst_ip;
    int dst_port;
    int flag;
    long timestamp;

    if (!PyArg_ParseTuple(args, "iiiiii", &src_ip, &src_port, &dst_ip, &dst_port, &flag, &timestamp))
	return NULL;

    printf("%s si called with %X/%d-%X/%d, flag %x, timestamp %ld\n",
	   __FUNCTION__, src_ip, src_port, dst_ip, dst_port, flag, timestamp);
    Py_RETURN_NONE;
}

PyObject *
ioc_session_create(PyObject *self, PyObject *args)
{
    int src_ip;
    int src_port;
    int dst_ip;
    int dst_port;
    int flag;
    long timestamp;

    if (!PyArg_ParseTuple(args, "iiiiii", &src_ip, &src_port, &dst_ip, &dst_port, &flag, &timestamp))
	return NULL;

    printf("%s si called with %X/%d-%X/%d, flag %x, timestamp %ld\n",
	   __FUNCTION__, src_ip, src_port, dst_ip, dst_port, flag, timestamp);
    Py_RETURN_NONE;

}
