#ifndef LIB_RAYDUST_H
#define LIB_RAYDUST_H
#include <Python.h>

#define OK 0
#define ERROR -1
#define NO_ENOUGH_SPACE -2
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
extern PyObject *RayDustError;
extern int oom_errors;
extern int insert_errors;

extern int fuzzy_hash_init(void);
extern char fuzzy_hash_policy_update_docs[];
extern char fuzzy_hash_policy_delete_docs[];
extern char fuzzy_hash_policy_find_by_path_docs[];
extern char fuzzy_hash_similarity_lookup_docs[];
extern char fuzzy_hash_insert_docs[];
extern char fuzzy_hash_delete_docs[];
extern char fuzzy_hash_get_by_file_docs[];
extern char ioc_session_close_docs[];
extern char ioc_session_create_docs[];
extern char ip_blacklist_check_docs[];
extern char get_geo_location_by_ip_docs[];
extern char file_hash_query_docs[];
extern char fuzzy_hash_dump_policy_docs[];

#define debug_print printf
#define error_print printf

PyObject *
file_hash_query(PyObject *self, PyObject *args);
PyObject *
get_geo_location_by_ip(PyObject *self, PyObject *args);
PyObject *
ip_blacklist_check(PyObject *self, PyObject *args);
PyObject *
fuzzy_hash_policy_update(PyObject *self, PyObject *args);
PyObject *
fuzzy_hash_policy_delete(PyObject *self, PyObject *args);
PyObject *
fuzzy_hash_policy_find_by_path(PyObject *self, PyObject *args);
PyObject *
Py_fuzzy_hash_similarity_lookup(PyObject *self, PyObject *args);
PyObject *
fuzzy_hash_get_by_file(PyObject *self, PyObject *args);
PyObject *
Py_fuzzy_hash_insert(PyObject *self, PyObject *args);
PyObject *
Py_fuzzy_hash_delete(PyObject *self, PyObject *args);
PyObject *
ioc_session_close(PyObject *self, PyObject *args);
PyObject *
ioc_session_create(PyObject *self, PyObject *args);
PyObject *
Py_fuzzy_hash_dump_policy(PyObject *self, PyObject *args);
void
fuzzy_hash_dump_policy(void);


#endif
