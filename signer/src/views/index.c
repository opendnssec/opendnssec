#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ldns/ldns.h>
#include "uthash.h"
#include "proto.h"

struct names_index_struct {
    char* keyname;
    ldns_rbtree_t* tree;
};

struct names_iterator_struct {
    int (*iterate)(names_iterator*iter, void**);
    int (*advance)(names_iterator*iter, void**);
    int (*end)(names_iterator*iter);
    ldns_rbnode_t* current;
};

#define DEFCOMPARE(C) const char* C ## data; \
                      int C ## func(const void *a, const void *b) { \
                          const dictionary x = (dictionary) a; \
                          const dictionary y = (dictionary) b; \
                          return strcmp(getname(x, C ## data), \
                                        getname(y, C ## data)); }
DEFCOMPARE(cmp1)
DEFCOMPARE(cmp2)
DEFCOMPARE(cmp3)
DEFCOMPARE(cmp4)
DEFCOMPARE(cmp5)
DEFCOMPARE(cmp6)
DEFCOMPARE(cmp7)
DEFCOMPARE(cmp8)
DEFCOMPARE(cmp9)
DEFCOMPARE(cmp10)
DEFCOMPARE(cmp11)
DEFCOMPARE(cmp12)
DEFCOMPARE(cmp13)
DEFCOMPARE(cmp14)
DEFCOMPARE(cmp15)
DEFCOMPARE(cmp16)

typedef int (*comparefunction)(const void *, const void *);

comparefunction
getcmp(const char*cmp)
{
#define RTNCOMPARE(C) if(!C ## data || !strcmp(cmp,C ## data)) { \
                          C ## data = (C ## data ? C ## data : cmp); \
                          return C ## func; }
    RTNCOMPARE(cmp1);
    RTNCOMPARE(cmp2);
    RTNCOMPARE(cmp3);
    RTNCOMPARE(cmp4);
    RTNCOMPARE(cmp5);
    RTNCOMPARE(cmp6);
    RTNCOMPARE(cmp7);
    RTNCOMPARE(cmp8);
    RTNCOMPARE(cmp9);
    RTNCOMPARE(cmp10);
    RTNCOMPARE(cmp11);
    RTNCOMPARE(cmp12);
    RTNCOMPARE(cmp13);
    RTNCOMPARE(cmp14);
    RTNCOMPARE(cmp15);
    RTNCOMPARE(cmp16);
    abort();
}

int
names_indexcreate(names_index_type* index, const char* keyname)
{
    *index = malloc(sizeof(struct names_index_struct));
    (*index)->keyname = strdup(keyname);
    (*index)->tree = ldns_rbtree_create(getcmp(keyname));
    return 0;
}
void
names_indexdestroy(names_index_type index)
{
    free(index);
}
void
names_indexinsert(names_index_type index, dictionary d)
{
    ldns_rbnode_t* node;
    node = malloc(sizeof(ldns_rbnode_t));
    node->key = d;
    node->data = d;
    ldns_rbtree_insert(index->tree, node);
}

dictionary
names_indexlookup(names_index_type index, char* keyvalue)
{
    ldns_rbnode_t* node;
    dictionary find;
    find = create(&keyvalue);
    set(find,"name",keyvalue);
    node = ldns_rbtree_search(index->tree, find);
    dispose(find);
    return node ? (dictionary) node->data : NULL;
}

int
names_indexremove(names_index_type index, dictionary d)
{
    return names_indexremovekey(index, getname(d,NULL));
}

int
names_indexremovekey(names_index_type index, char* keyvalue)
{
    ldns_rbnode_t* node;
    node = ldns_rbtree_delete(index->tree, keyvalue);
    if(node) {
        free(node);
        return 1;
    } else
        return 0;
}

static int
iterateimpl(names_iterator* i, void** item)
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


names_iterator
names_indexiterator(names_index_type index)
{
    names_iterator iter;
    iter = malloc(sizeof(struct names_iterator_struct));
    iter->iterate = iterateimpl;
    iter->advance = advanceimpl;
    iter->end = endimpl;
    iter->current = (index->tree != NULL ? ldns_rbtree_first(index->tree) : NULL);
    return iter;
}

names_iterator
names_indexrange(names_index_type index, char* selection,...)
{
    va_list ap;
    names_iterator iter;
    va_start(ap, selection);
    va_end(ap);
    iter = malloc(sizeof (struct names_iterator_struct));
    iter->iterate = iterateimpl;
    iter->advance = advanceimpl;
    iter->end = endimpl;
    if (index->tree) {
        if (!ldns_rbtree_find_less_equal(index->tree, selection, &iter->current)) {
            if (iter->current)
                iter->current = ldns_rbtree_next(iter->current);
        }
    } else
        iter->current = NULL;
    return iter;
}
