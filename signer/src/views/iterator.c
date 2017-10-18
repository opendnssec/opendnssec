#include <stdio.h>
#include <stdlib.h>

typedef struct iterator_struct* iterator;

struct iterator_struct {
    int (*iterate)(iterator*iter, void**);
    int (*advance)(iterator*iter, void**);
    int (*end)(iterator*iter);
};

int
names_iterate(iterator*iter, void* item)
{
    if(*iter)
        return (*iter)->iterate(iter, (void**)item);
    else
        return 0;
}

int
names_advance(iterator*iter, void* item)
{
    if(*iter)
        return (*iter)->advance(iter, (void**)item);
    else
        return 0;
}

int
names_end(iterator*iter)
{
    if(*iter)
        return (*iter)->end(iter);
    else
        return 0;
}
