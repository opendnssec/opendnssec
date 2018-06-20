#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldns/ldns.h>
#include "proto.h"

#pragma GCC optimize ("O0")

struct names_iterator_struct {
    int (*iterate)(names_iterator*iter, void*);
    int (*advance)(names_iterator*iter, void*);
    int (*end)(names_iterator*iter);
    int itemcnt, itemidx;
    size_t itemsiz;
    void* itemdata;
    void (*itemfunc)(names_iterator iter,void*,int,void*);
    void (*itemfree)(void*);
    void* previous;
};

static int
endimpl(names_iterator*iter)
{
    if(*iter) {
        (*iter)->itemfunc(*iter, (*iter)->itemdata, -1, (*iter)->previous);
        free(*iter);
        *iter = NULL;
    }
    return 0;
}

static int
iterateimpl(names_iterator* iter, void* ptr)
{
    if (*iter) {
        if ((*iter)->itemidx < (*iter)->itemcnt) {
            if (ptr) {
                (*iter)->itemfunc(*iter, (*iter)->itemdata, (*iter)->itemidx, ptr);
                (*iter)->previous = ptr;
            }
            return 1;
        }
        endimpl(iter);
    }
    return 0;
}

static int
advanceimpl(names_iterator* iter, void* ptr)
{
    if (*iter) {
        (*iter)->itemidx += 1;
        if ((*iter)->itemidx < (*iter)->itemcnt) {
            if (ptr) {
                (*iter)->itemfunc(*iter, (*iter)->itemdata, (*iter)->itemidx, ptr);
                (*iter)->previous = ptr;
            }
            return 1;
        }
        endimpl(iter);
    }
    return 0;
}
names_iterator
names_iterator_create(int count, void* data, void (*indexfunc)(names_iterator iter,void*,int,void*), size_t itemsiz, void (*freefunc)(void*))
{
    names_iterator iter;
    iter = malloc(sizeof(struct names_iterator_struct));
    iter->iterate = iterateimpl;
    iter->advance = advanceimpl;
    iter->end = endimpl;
    iter->itemcnt = count;
    iter->itemidx = 0;
    iter->itemsiz = itemsiz;
    iter->itemdata = data;
    iter->itemfunc = indexfunc;
    iter->itemfree = freefunc;
    iter->previous = NULL;
    return iter;
}

names_iterator
names_iterator_createarray(int count, void* data, void (*indexfunc)(names_iterator iter,void*,int,void*))
{
    return names_iterator_create(count, data, indexfunc, 0, NULL);
}

static void
refsindexfunc(names_iterator iter, void** array, int index, void** ptr)
{
    if(iter->itemfree && ptr)
        iter->itemfree(*ptr);
    if(index >= 0)
        *ptr = array[index];
    if(index == -1) {
        free(array);
    }
}

names_iterator
names_iterator_createrefs(void (*freefunc)(void*))
{
    return names_iterator_create(0, NULL, refsindexfunc, sizeof(void*), freefunc);
}

static void
dataindexfunc(names_iterator iter, char* data, int index, void* ptr)
{
    if(iter->itemfree && ptr)
        iter->itemfree(ptr);
    if(index >= 0)
        memcpy(ptr, &(((char*)(iter->itemdata))[iter->itemsiz * index]), iter->itemsiz);
    if(index == -1) {
        free(data);
    }
}

names_iterator
names_iterator_createdata(size_t size)
{
    return names_iterator_create(0, NULL, dataindexfunc, size, NULL);
}

void
names_iterator_addptr(names_iterator iter, const void* ptr)
{
    iter->itemcnt += 1;
    iter->itemdata = realloc(iter->itemdata, iter->itemsiz * iter->itemcnt);
    ((void**)(iter->itemdata))[iter->itemcnt-1] = ptr;
}

void
names_iterator_adddata(names_iterator iter, const void* ptr)
{
    iter->itemcnt += 1;
    iter->itemdata = realloc(iter->itemdata, iter->itemsiz * iter->itemcnt);
    memcpy(&(((char*)(iter->itemdata))[iter->itemsiz * (iter->itemcnt-1)]), ptr, iter->itemsiz);
}
