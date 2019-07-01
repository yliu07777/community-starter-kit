#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Python.h>
#include <sys/queue.h>
#include "libraydust.h"
#include "fuzzy.h"

char fuzzy_hash_policy_update_docs[] = "DLP policy update";
char fuzzy_hash_policy_delete_docs[] = "DLP policy removal";
char fuzzy_hash_policy_find_by_path_docs[] = "Find DLP policy by file path";
char fuzzy_hash_similarity_lookup_docs[] = "Match fuzzy hash values";
char fuzzy_hash_insert_docs[] = "Add hash into fuzzy hash DB";
char fuzzy_hash_delete_docs[] = "Delete hash from fuzzy hash DB";
char fuzzy_hash_dump_policy_docs[] = "Dump all fuzzy hash policies";

PyObject *RayDustError;


PyObject *
fuzzy_hash_policy_delete(PyObject *self, PyObject *args)
{
    /*
     * dlp_policy_delete
     */
    const char *name;

    if (!PyArg_ParseTuple(args, "s", &name)){
	return NULL;
    }
    printf("%s called with name as %s", __FUNCTION__, name);
    Py_RETURN_NONE;
}

PyObject *
fuzzy_hash_policy_update(PyObject *self, PyObject *args)
{
    /*
     * dlp_policy_update
     */
    const char *name;
    const char *path;
    const char *filename;
    unsigned int type;
    unsigned int action;
    unsigned int threshold;

    if (!PyArg_ParseTuple(args, "siissi", &name, &action, &type, &path, &filename, &threshold))
	return NULL;

    printf("%s called with name %s, action %d, type %d, path %s, filename %s, threshold %d\n",
	   __FUNCTION__, name, action, type, path, filename, threshold);
    Py_RETURN_NONE;
}

PyObject *
fuzzy_hash_policy_find_by_path(PyObject *self, PyObject *args)
{
    /*
     * dlp_policy_find_by_path
     */
    const char *path;
    const char *name;

    if (!PyArg_ParseTuple(args, "ss", &path, &name))
	return NULL;
    printf("%s called with path %s, name %s\n", __FUNCTION__, path, name);
    Py_RETURN_NONE;
}

PyObject *
Py_fuzzy_hash_similarity_lookup(PyObject *self, PyObject *args)
{
    /*
     * fuzzy_hash_find_closed_similarity
     */
    const char *md5_string;
    const char *filename;
    int max_returns;

    if (!PyArg_ParseTuple(args, "ssi", &md5_string, &filename, &max_returns))
	return NULL;
    printf("%s called with filename %s, md5 %s, max_return %d\n",
	   __FUNCTION__, filename, md5_string, max_returns);
    Py_RETURN_NONE;
}

PyObject *
Py_fuzzy_hash_insert(PyObject *self, PyObject *args)
{
    /*
     * fuzzy_hash_db_insert
     */
    const char *group;
    const char *md5_string;
    const char *filename;
    const char *gid;
    const char *path;
    int ret;

    if (!PyArg_ParseTuple(args, "sssss", &group, &path, &gid, &md5_string, &filename))
	return NULL;

    if (!group || !md5_string || !filename)
	return NULL;

    printf("%s is called with name %s, path %s, id %s, md5 %s, filename %s\n",
	   __FUNCTION__, group, path, gid, md5_string, filename);
    ret = fuzzy_hash_insert(group, path, gid, md5_string, filename);
    printf("%s return %d\n", __FUNCTION__, ret);
    return Py_BuildValue("i", ret);
}

PyObject *
Py_fuzzy_hash_delete(PyObject *self, PyObject *args)
{
    /*
     * fuzzy_hash_db_delete
     */
    const char *group;
    const char *md5_string;
    const char *filename;
    const char *id;
    const char *path;
    int ret;

    if (!PyArg_ParseTuple(args, "sssss", &group, &path, &id, &md5_string, &filename))
	return NULL;

    if (!group || ! md5_string || !filename)
	return NULL;

    printf("%s is called with group %s, path: %s, id: %s, md5 %s, filename %s\n",
	   __FUNCTION__, group, path, id, md5_string, filename);
    ret = fuzzy_hash_delete(group, path, id, md5_string, filename);
    return Py_BuildValue("i", ret);
}

PyObject *
Py_fuzzy_hash_dump_policy(PyObject *self, PyObject *args)
{
    fuzzy_hash_dump_policy();
    return Py_BuildValue("i", 0);
}
