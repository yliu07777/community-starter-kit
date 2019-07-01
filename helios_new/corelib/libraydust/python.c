#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Python.h>
#include "libraydust.h"

char raydust_core_docs[] = "RayDust core security module";

static struct PyMethodDef RayDustMethodTable[] = {
    {
	"fuzzy_hash_policy_update",
	(PyCFunction)fuzzy_hash_policy_update,
	METH_VARARGS,
	fuzzy_hash_policy_update_docs
    },
    {
	"fuzzy_hash_policy_delete",
	(PyCFunction)fuzzy_hash_policy_delete,
	METH_VARARGS,
	fuzzy_hash_policy_delete_docs
    },
    {
	"fuzzy_hash_policy_find_by_path",
	(PyCFunction)fuzzy_hash_policy_find_by_path,
	METH_VARARGS,
	fuzzy_hash_policy_find_by_path_docs
    },
    {
	"fuzzy_hash_similarity_lookup",
	(PyCFunction)Py_fuzzy_hash_similarity_lookup,
	METH_VARARGS,
        fuzzy_hash_similarity_lookup_docs,
    },
    {
	"fuzzy_hash_delete",
	(PyCFunction)Py_fuzzy_hash_delete,
	METH_VARARGS,
	fuzzy_hash_delete_docs
    },
    {
	"fuzzy_hash_insert",
	(PyCFunction)Py_fuzzy_hash_insert,
	METH_VARARGS,
	fuzzy_hash_insert_docs
    },
    {
	"ioc_session_close",
	(PyCFunction)ioc_session_close,
	METH_VARARGS,
	ioc_session_close_docs
    },
    {
	"ioc_session_create",
	(PyCFunction)ioc_session_create,
	METH_VARARGS,
	ioc_session_create_docs
    },
    {
	"ip_blacklist_check",
	(PyCFunction)ip_blacklist_check,
	METH_VARARGS,
	ip_blacklist_check_docs
    },
    {
	"get_geo_location_by_ip",
	(PyCFunction)get_geo_location_by_ip,
	METH_VARARGS,
	get_geo_location_by_ip_docs
    },
    {
	"file_hash_query",
	(PyCFunction)file_hash_query,
	METH_VARARGS,
	file_hash_query_docs
    },
    {
	"fuzzy_hash_dump_policy",
	(PyCFunction)Py_fuzzy_hash_dump_policy,
	METH_VARARGS,
	fuzzy_hash_dump_policy_docs
    },
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef RayDustModules = {
    PyModuleDef_HEAD_INIT,
    "RayDust",
    raydust_core_docs,
    -1,
    RayDustMethodTable
};


static int module_init(void)
{
    if (fuzzy_hash_init())
	return -1;
    return 0;
}

PyMODINIT_FUNC
PyInit_libraydust(void)
{
    PyObject *m;
    printf("Initialize Raydust security library\n");
    if (module_init() != 0) {
	printf("initialization failed\n");
	return NULL;
    }

    m = PyModule_Create(&RayDustModules);
    if (m == NULL)
	return NULL;

    RayDustError = PyErr_NewException("RayDust.error", NULL, NULL);
    Py_INCREF(RayDustError);
    PyModule_AddObject(m, "error", RayDustError);
    return m;
}
