#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldns/ldns.h>
#include "proto.h"

struct names_iterator_struct {
    int (*iterate)(names_iterator*iter, void**);
    int (*advance)(names_iterator*iter, void**);
    int (*end)(names_iterator*iter);
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
