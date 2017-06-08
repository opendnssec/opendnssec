#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>
#include <ldns/ldns.h>
#include "names.h"
#include "domain.h"

struct names_view_struct {
    uint32_t serial;
    ldns_rdf* apex;
    struct datastructure* dbase;
};

struct names_source_struct {
    struct names_view_struct view;
};

typedef int (*indexfunc)(ldns_rdf*, ldns_rdf*);

struct index {
    ldns_rbtree_t* tree;
    size_t offset;
    indexfunc cmpfn;
};

int compare(const void* a, const void* b)
{
    const ldns_rdf* dname1 = (const ldns_rdf *) a;
    const ldns_rdf* dname2 = (const ldns_rdf *) b;
    return ldns_dname_compare(a, b);
}

struct datastructure {
    int counter;
    int nindices;
    struct index indices;
};

struct names_iterator_struct {
    struct datastructure* dbase;
    ldns_rbnode_t* cursor;
    ldns_rbnode_t* next;
    int indexnum;
    int reverse;
};

struct node {
    domain_type* data;
    struct ldns_rbnode_t nodes; /* first node of a number of nodes */
};

void
create(struct datastructure** dbase, ...)
{
    va_list ap;
    struct index* indices;
    indexfunc cmpfn;
    size_t offset;
    int nindices, i;

    va_start(ap, dbase);
    cmpfn = va_arg(ap, indexfunc);
    nindices = 0;
    while(cmpfn != NULL) {
        va_arg(ap, size_t);
        cmpfn = va_arg(ap, indexfunc);
        ++nindices;
    }
    va_end(ap);
    if(nindices == 0)
        abort();
        
    *dbase = malloc(sizeof(struct datastructure)+sizeof(struct index)*(nindices-1));
    (*dbase)->counter = 0;
    (*dbase)->nindices = nindices;
    indices = &((*dbase)->indices);
    va_start(ap, dbase);
    for(i=0; i<nindices; i++) {
        cmpfn = va_arg(ap, indexfunc);
        offset = va_arg(ap, size_t);
        indices[i].cmpfn = cmpfn;
        indices[i].offset = offset;
        indices[i].tree = ldns_rbtree_create(cmpfn);
    }
    va_end(ap);
}

void
destroy(struct datastructure* dbase)
{
    int i;
    struct index* indices;
    indices = &dbase->indices;
    for(i=0; i<dbase->nindices; i++) {
        ldns_rbtree_free(indices[i].tree);
    }
    free(dbase);
}

void
insert(struct datastructure* dbase, void* data)
{
    int i;
    struct node* node;
    struct index* indices;
    struct ldns_rbnode_t* nodes;
    indices = &dbase->indices;
    node = malloc(sizeof(struct node)+sizeof(ldns_rbnode_t)*(dbase->nindices-1));
    nodes = &node->nodes;
    node->data = data;
    for(i=0; i<dbase->nindices; i++) {
        nodes[i].key = &((char*)(node->data))[indices[i].offset];
        nodes[i].data = node;
        ldns_rbtree_insert(indices[i].tree,&nodes[i]);
    }
}

void
names_delete(names_iterator*iter)
{
    struct ldns_rbnode_t* next;
    struct index* indices;
    struct ldns_rbnode_t* nodes;
    indices = &(*iter)->dbase->indices;
    if ((*iter)->reverse) {
        (*iter)->next = ldns_rbtree_previous((*iter)->cursor);
    } else {
        (*iter)->next = ldns_rbtree_next((*iter)->cursor);
    }
    ldns_rbtree_delete(indices[(*iter)->indexnum].tree, (*iter)->cursor->key);
    (*iter)->cursor = NULL;
}

int
names_insert(names_iterator*iter, void* data)
{
    insert((*iter)->dbase, data);
    return 0;
}

int
names_createiterator(struct datastructure*dbase, names_iterator* iter, int indexnum, int reverse)
{
    struct index* indices;
    indices = &dbase->indices;
    *iter = malloc(sizeof(names_iterator));
    (*iter)->dbase = dbase;
    (*iter)->indexnum = indexnum;
    (*iter)->reverse = reverse;
    (*iter)->next = NULL;
    if (reverse) {
        (*iter)->cursor = ldns_rbtree_last(indices[indexnum].tree);
    } else {
        (*iter)->cursor = ldns_rbtree_first(indices[indexnum].tree);
    }
    return 0;
}

int
names_iterate(names_iterator*iter, void*arg)
{
    if(*iter == NULL) {
        if(arg != NULL)
            *(void**)arg = NULL;
        return 0;
    }
    if((*iter)->cursor == NULL || (*iter)->cursor == LDNS_RBTREE_NULL) {
        if(arg != NULL)
            *(void**)arg = NULL;
        names_end(iter);
        return 0;
    }
    if(arg != NULL) {
        *(void**)arg = (void*) (*iter)->cursor->data;
    }
    return 1;
}

int
names_advance(names_iterator*iter, void*arg)
{
    struct ldns_rbnode_t* next;
    if((*iter)->next != NULL && (*iter)->next != LDNS_RBTREE_NULL) {
        next = (*iter)->next;
        (*iter)->next = NULL;
    } else {
        if ((*iter)->reverse) {
            next = ldns_rbtree_previous((*iter)->cursor);
        } else {
            next = ldns_rbtree_next((*iter)->cursor);
        }
    }
    if(next == NULL || next == LDNS_RBTREE_NULL) {
        if(arg != NULL)
            *(void**)arg = NULL;
        names_end(iter);
        return 0;
    }
    (*iter)->cursor = next;
    if(arg != NULL) {
        *(void**)arg = (void*) (*iter)->cursor->data;
    }
    return 0;
}

int
names_end(names_iterator*iter)
{
    free(*iter);
    *iter = NULL;
    return 0;
}

int
names_create(names_source_type*arg)
{
    *arg = malloc(sizeof(struct names_source_struct));
    (*arg)->view.serial = 0;
    create(&(*arg)->view.dbase, compare, offsetof(struct domain_struct, dname), NULL);
    return 0;
}

void
names_destroy(names_source_type source)
{
    names_clear(source);
    free(source);
}

int
names_clear(names_source_type source)
{
    names_view_type view = &source->view;
    names_iterator iter;
    domain_type* domain;
    /* for each view */
    for(names_alldomains(view,&iter); names_iterate(&iter,&domain); names_advance(&iter,NULL)) {
        domain_cleanup(domain);
    }
    names_commit(view);
    return 0;
}

int
names_view(names_source_type source, names_view_type* view)
{
    *view = &source->view;
    return 0;
}

int
names_commit(names_view_type view)
{
    return 0;
}

int
names_rollback(names_view_type view)
{
    abort();
}

int
names_dispose(names_view_type view)
{
    return 0;
}

uint32_t
names_getserial(names_view_type view)
{
    return view->serial;
}

void
names_setserial(names_view_type view, uint32_t serial)
{
    view->serial = serial;
}

int
names_firstdenials(names_view_type view,names_iterator*iter)
{
    return names_createiterator(view->dbase, iter, 0, 0);
}

int
names_reversedenials(names_view_type view,names_iterator*iter)
{
    return names_createiterator(view->dbase, iter, 0, 0);
}

int
names_alldomains(names_view_type view,names_iterator*iter)
{
    return names_createiterator(view->dbase, iter, 0, 0);
}

int
names_parentdomains(names_view_type view,void* domain,names_iterator*iter)
{
    return names_createiterator(view->dbase, iter, 0, 0);
}

domain_type*
names_lookupname(names_view_type view, ldns_rdf* name)
{
    ldns_rbnode_t* search;
    const struct node* node;
    assert(view->dbase->indices.tree != NULL);
    assert(name != NULL);
    search = ldns_rbtree_search(view->dbase->indices.tree, name);
    if (search != NULL && search != LDNS_RBTREE_NULL) {
        node = search->data;
        return node->data;
    } else {
        return NULL;
    }
}

domain_type*
names_addname(names_view_type view, ldns_rdf* name)
{
    assert(name != NULL);
    domain_type* domain = domain_create(name);
    insert(view->dbase, domain);
    return domain;
}
