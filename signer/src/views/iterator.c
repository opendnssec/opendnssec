#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proto.h"

struct names_iterator_struct {
    int (*iterate)(names_iterator*iter, void**);
    int (*advance)(names_iterator*iter, void**);
    int (*end)(names_iterator*iter);

    int itemcnt, itemmax, itemidx, itemsiz;
    char* items;
};

int
names_iterate(names_iterator*iter, void* item)
{
    if(*iter)
        return (*iter)->iterate(iter, (void**)item);
    else
        return 0;
}

int
names_advance(names_iterator*iter, void* item)
{
    if(*iter)
        return (*iter)->advance(iter, (void**)item);
    else
        return 0;
}

int
names_end(names_iterator*iter)
{
    if(*iter)
        return (*iter)->end(iter);
    else
        return 0;
}


static int
iterateimpl(names_iterator* iter, void** item)
{
    if (item)
        *item = NULL;
    if (*iter) {
        if ((*iter)->itemidx < (*iter)->itemcnt) {
            if (item)
                *item = &((*iter)->items[(*iter)->itemidx * (*iter)->itemsiz]);
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
    if (item)
        *item = NULL;
    if (*iter) {
        (*iter)->itemidx += 1;
        if ((*iter)->itemidx < (*iter)->itemcnt) {
            if (item)
                *item = &((*iter)->items[(*iter)->itemidx * (*iter)->itemsiz]);
            return 1;
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
generic_iterator(size_t size)
{
    names_iterator iter;
    iter = malloc(sizeof(struct names_iterator_struct));
    iter->iterate = iterateimpl;
    iter->advance = advanceimpl;
    iter->end = endimpl;
    iter->itemcnt = 0;
    iter->itemmax = 2;
    iter->itemidx = 0;
    iter->itemsiz = size;
    iter->items = malloc(iter->itemmax * iter->itemsiz);;
    return iter;
}

void
generic_add(names_iterator i, void* ptr)
{
    if(i->itemcnt == i->itemmax) {
        i->itemmax *= 2;
        i->items = realloc(i->items, i->itemmax * i->itemsiz);
    }
    memcpy(&(i->items[i->itemcnt * i->itemsiz]), ptr, i->itemsiz);
    i->itemcnt += 1;
}
