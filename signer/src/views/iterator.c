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
    return (*iter)->iterate(iter, (void**)item);
}

int
names_advance(iterator*iter, void* item)
{
    return (*iter)->advance(iter, (void**)item);
}

int
names_end(iterator*iter)
{
    return (*iter)->end(iter);
}
