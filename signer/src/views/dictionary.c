#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ldns/ldns.h>
#include "uthash.h"
#include "proto.h"

#pragma GCC optimize ("O0")

struct dictionary_struct {
    ldns_rbtree_t* tree;
    char* name;
};

struct names_iterator_struct {
    int (*iterate)(names_iterator*iter, void**);
    int (*advance)(names_iterator*iter, void**);
    int (*end)(names_iterator*iter);
    ldns_rbnode_t* current;
};

static int
iterateimpl(names_iterator*i, void** item)
{
    struct names_iterator_struct** iter = i;
    if(*iter) {
        if((*iter)->current != NULL && (*iter)->current != LDNS_RBTREE_NULL) {
            if(*item)
                *item = (*iter)->current;
            return 1;
        } else {
            free(*iter);
            *iter = NULL;
        }
    }
    return 0;
}

static int
advanceimpl(names_iterator*i, void** item)
{
    struct names_iterator_struct** iter = i;
    if(*iter) {
        if((*iter)->current != NULL && (*iter)->current != LDNS_RBTREE_NULL) {
            (*iter)->current = ldns_rbtree_next((*iter)->current);
            if((*iter)->current != NULL && (*iter)->current != LDNS_RBTREE_NULL) {
                if(*item)
                    *item = (*iter)->current;
                return 1;
            }
        }
        free(*iter);
        *iter = NULL;
    }
    return 0;
}

static int
endimpl(names_iterator*iter)
{
    if(*iter) free(*iter);
        *iter = NULL;
    return 0;
}

static int
cmp(const void *a, const void *b)
{
    const char* x;
    const char* y;
    x = (const char*) a;
    y = (const char*) b;
    return strcmp(x, y);
}

dictionary
create(char**name)
{
    struct dictionary_struct* dict;
    dict = malloc(sizeof(struct dictionary_struct));
    if(name) {
        dict->name = *name = (*name ? strdup(*name) : *name);
    } else {
        dict->name = NULL;
    }
    dict->tree = NULL;
    return (dictionary) dict;
}

static void
copytreefn(ldns_rbnode_t* node, void* cargo)
{
    dictionary dict;
    ldns_rbnode_t* newnode;
    ldns_rbtree_t* tree = (ldns_rbtree_t*) cargo;
    newnode = malloc(sizeof(ldns_rbnode_t));
    dict = copy((dictionary)node->data);
    newnode->key = get(dict, NULL);
    newnode->data = dict;
    ldns_rbtree_insert(tree, newnode);
}

dictionary
copy(dictionary d)
{
    struct dictionary_struct* dict = (struct dictionary_struct*) d;
    struct dictionary_struct* target;
    target = (struct dictionary_struct*) create(NULL);
    target->name = (dict->name ? strdup(dict->name) : NULL);
    if(dict->tree) {
        target->tree = ldns_rbtree_create(cmp);
        ldns_traverse_postorder(dict->tree, copytreefn, target->tree);
    }
    return (dictionary) dict;
}

dictionary
get(dictionary d, const char* name)
{
    struct dictionary_struct* dict = (struct dictionary_struct*) d;
    struct dictionary_struct* content;
    struct ldns_rbnode_t* node;
    if (dict->tree != NULL) {
        node = ldns_rbtree_search(dict->tree, name);
        if (node == NULL || node == LDNS_RBTREE_NULL) {
            return NULL;
        } else {
            content = (struct dictionary_struct*) node->data;
            return content;
        }
    } else {
        return NULL;
    }
}

char*
getname(dictionary d, const char* name)
{
    if(name != NULL) {
        d = get(d, name);
    }
    if (d) {
        return d->name;
    } else {
        return NULL;
    }
}

int
has(dictionary d, char* name, ...)
{
    va_list ap;
    int found = 0;
    char* nextname;
    va_start(ap, name);
    
    do {
        nextname = va_arg(ap, char*);
        if (nextname) {
            d = get(d, name);
            if(d == NULL)
                break;
            name = nextname;
        }
    } while(nextname != NULL);
    if(d != NULL) {
        if(get(d, name) != NULL) {
            found = 1;
        }
    }
    va_end(ap);
    return found;
}

int
del(dictionary d, char* name)
{
    struct dictionary_struct* dict = (struct dictionary_struct*) d;
    struct dictionary_struct* record;
    struct ldns_rbnode_t* node;
    if(dict->tree != NULL) {
            node = ldns_rbtree_delete(dict->tree, name);
            if(node != NULL && node != LDNS_RBTREE_NULL) {
                record = (struct dictionary_struct*) node->data;
                free(node);
                dispose((dictionary)record);
                return 1;
            } else {
                return 0;
            }
    }
    return 0;
}

void*
add(dictionary d, char* name)
{
    struct dictionary_struct* dict = (struct dictionary_struct*) d;
    dictionary content;
    struct ldns_rbnode_t* node;

    if (!dict->tree) {
        dict->tree = ldns_rbtree_create(cmp);
    }
    node = ldns_rbtree_search(dict->tree, name);
    if (node == NULL || node == LDNS_RBTREE_NULL) {
        content = (dictionary) create(&name);
        node = malloc(sizeof (struct ldns_rbnode_t));
        node->key = name;
        node->data = content;
        ldns_rbtree_insert(dict->tree, node);
    } else {
        content = (dictionary) node->data;
    }
    return content;
}

void
set(dictionary d, const char* name, char* value)
{
    struct dictionary_struct* dict = (struct dictionary_struct*) d;
    dictionary content;
    struct ldns_rbnode_t* node;

    if (!dict->tree) {
        dict->tree = ldns_rbtree_create(cmp);
    }
    node = ldns_rbtree_search(dict->tree, name);
    if (node == NULL || node == LDNS_RBTREE_NULL) {
        content = (dictionary) create(&value);
        node = malloc(sizeof (struct ldns_rbnode_t));
        node->key = name;
        node->data = content;
        ldns_rbtree_insert(dict->tree, node);
    } else {
        content = (dictionary) node->data;
        free(content->name);
        content->name = strdup(value);
    }
}

names_iterator
all(dictionary dict)
{
    struct names_iterator_struct* iter;
    iter = malloc(sizeof(struct names_iterator_struct));
    iter->iterate = iterateimpl;
    iter->advance = advanceimpl;
    iter->end = endimpl;
    iter->current = (dict->tree != NULL ? ldns_rbtree_first(dict->tree) : NULL);
    return iter;
}

static void
disposenode(ldns_rbnode_t* node, void* cargo)
{
    (void)cargo;
    dispose((dictionary)(node->data));
    free(node);
}

void
dispose(dictionary d)
{
    struct dictionary_struct* dict = (struct dictionary_struct*) d;
    if(dict->tree != NULL) {
        ldns_traverse_postorder(dict->tree, disposenode, NULL);
        ldns_rbtree_free(dict->tree);
    }
    if(dict->name) {
        free(dict->name);
    }
    free(dict);
}
