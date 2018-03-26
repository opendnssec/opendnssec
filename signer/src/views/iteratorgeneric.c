#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldns/ldns.h>
#include "proto.h"

struct names_iterator_struct {
    int (*iterate)(names_iterator*iter, void**);
    int (*advance)(names_iterator*iter, void**);
    int (*end)(names_iterator*iter);
    int itemcnt, itemmax, itemidx;
    size_t itemsiz;
    char* items;
};

static int
iterateimpl(names_iterator* iter, void** item)
{
    if (item)
        *item = NULL;
    if (*iter) {
        if ((*iter)->itemidx < (*iter)->itemcnt) {
            if (item) {
                if(!(*iter)->itemsiz) {
                    *item = (((void**)((*iter)->items))[(*iter)->itemidx]);
                } else {
                    //*item = &((*iter)->items[(*iter)->itemidx * (*iter)->itemsiz]);
                    memcpy(item, &((*iter)->items[(*iter)->itemidx * (*iter)->itemsiz]), (*iter)->itemsiz);
                }
            }
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
            if (item) {
                if(!(*iter)->itemsiz) {
                    *item = (((void**)((*iter)->items))[(*iter)->itemidx]);
                } else {
                    *item = &((*iter)->items[(*iter)->itemidx * (*iter)->itemsiz]);
                }
            }
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
names_iterator_create(size_t size)
{
    names_iterator iter;
    iter = malloc(sizeof(struct names_iterator_struct));
    iter->iterate = iterateimpl;
    iter->advance = advanceimpl;
    iter->end = endimpl;
    iter->itemcnt = 0;
    iter->itemmax = 20;
    iter->itemidx = 0;
    iter->itemsiz = size;
    iter->items = malloc(iter->itemmax * (iter->itemsiz?iter->itemsiz:sizeof(void*)));;
    return iter;
}

void
names_iterator_add(names_iterator iter, void* ptr)
{
    size_t itemsiz;
    itemsiz = (iter->itemsiz ? iter->itemsiz : sizeof(void*));
    if(iter->itemcnt == iter->itemmax) {
        iter->itemmax *= 2;
        iter->items = realloc(iter->items, iter->itemmax * itemsiz);
    }
    if(!iter->itemsiz)
        ((void**)(iter->items))[iter->itemcnt] = ptr;
    else
        memcpy(&(iter->items[iter->itemcnt * itemsiz]), ptr, itemsiz);
    iter->itemcnt += 1;
}

void
names_iterator_addall(names_iterator iter, int count, void* base, size_t memsize, ssize_t offset)
{
    int i;
    size_t itemsiz;
    itemsiz = (iter->itemsiz ? iter->itemsiz : sizeof(void*));
    iter->itemmax = iter->itemcnt + count;
    iter->items = realloc(iter->items, iter->itemmax * itemsiz);
    for(i=0; i<count; i++) {
        if(offset >= 0) {
            if(!iter->itemsiz)
                ((void**)(iter->items))[iter->itemcnt] = *(char**)&(((char*)base)[memsize*i+offset]);
            else
                memcpy(&(iter->items[iter->itemcnt * itemsiz]), *(char**)&(((char*)base)[memsize*i+offset]), itemsiz);
        } else {
            memcpy(&(iter->items[iter->itemcnt * itemsiz]), &(((char*)base)[memsize*i]), itemsiz);
        }
        iter->itemcnt += 1;
    }    
}
