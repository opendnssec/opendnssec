#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>
#include <ldns/ldns.h>
#include "names.h"
#include "domain.h"

struct tree {
    struct node* parent;
    struct node* left;
    struct node* right;
};

typedef int (*indexfunc)(ldns_rdf*,ldns_rdf*);

struct index {
    struct node* root;
    indexfunc cmpfn;
    size_t offset;
    int indexnum;
};

void initializeindex(struct index*, int, indexfunc, size_t offset);
void freeindex(struct index*);
void deleteindex(struct index*, struct node*);
void insertindex(struct index*, struct node*);
struct node* firstindex(struct index*);
struct node* lastindex(struct index*);
struct node* nextindex(struct index*, struct node*);
struct node* previousindex(struct index*, struct node*);
struct node* searchindex(struct index* index, ldns_rdf* key);
struct node* advanceindex(struct index*, struct node*);

struct names_view_struct {
    uint32_t serial;
    ldns_rdf* apex;
    struct datastructure* dbase;
};

struct names_source_struct {
    struct names_view_struct view;
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
    struct node* cursor;
    struct node* next;
    struct index* index;
    struct node* (*advance)(struct index*, struct node*);
};

struct node {
    domain_type* data;
    struct tree nodes; /* first node of a number of nodes */
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
        initializeindex(&(indices[i]), i, cmpfn, offset);
    }
    va_end(ap);
}

void
destroy(struct datastructure* dbase)
{
    int i;
    struct index* indices;
    indices = &(dbase->indices);
    for(i=0; i<dbase->nindices; i++) {
        freeindex(&(indices[i]));
    }
    free(dbase);
}

void
insert(struct datastructure* dbase, domain_type* data)
{
    int i;
    struct node* node;
    struct index* indices;
    assert(data);
    indices = &(dbase->indices);
    node = malloc(sizeof(struct node)+sizeof(ldns_rbnode_t)*(dbase->nindices-1));
    node->data = data;
    for(i=0; i<dbase->nindices; i++) {
        insertindex(&(indices[i]), node);
    }
}

struct tree*
node2tree(struct index* index,struct node* node)
{
    struct tree* trees = &(node->nodes);
    return &trees[index->indexnum];
}

void
names_delete(names_iterator*iter)
{
    int i;
    (*iter)->next = (*iter)->advance((*iter)->index, (*iter)->cursor);
    for(i=0; i<(*iter)->dbase->nindices; i++) {
        deleteindex((*iter)->index, (*iter)->cursor);
    }
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
    indices = &(dbase->indices);
    *iter = malloc(sizeof(struct names_iterator_struct));
    (*iter)->dbase = dbase;
    (*iter)->index = &(indices[indexnum]);
    (*iter)->next = NULL;
    if (reverse) {
        (*iter)->cursor = lastindex(&(indices[indexnum]));
        (*iter)->advance = previousindex;
    } else {
        (*iter)->cursor = firstindex(&(indices[indexnum]));
        (*iter)->advance = nextindex;
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
    if((*iter)->cursor == NULL) {
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
    struct node* next;
    if((*iter)->next != NULL) {
        next = (*iter)->next;
        (*iter)->next = NULL;
    } else {
        next = (*iter)->advance((*iter)->index, (*iter)->cursor);
    }
    if(next == NULL) {
        if(arg != NULL)
            *(void**)arg = NULL;
        names_end(iter);
        return 0;
    }
    (*iter)->cursor = next;
    if(arg != NULL) {
        *(void**)arg = (void*) (*iter)->cursor->data;
    }
    return 1;
}

int
names_end(names_iterator*iter)
{
    free(*iter);
    *iter = NULL;
    return 0;
}

int
names_create(names_source_type*arg, ldns_rdf* apex)
{
    *arg = malloc(sizeof(struct names_source_struct));
    (*arg)->view.serial = 0;
    (*arg)->view.apex = ldns_rdf_clone(apex);
    create(&(*arg)->view.dbase, compare, offsetof(struct domain_struct, dname), NULL);
    return 0;
}

void
names_destroy(names_source_type source)
{
    names_clear(source);
    ldns_rdf_free(source->view.apex);
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
names_firstdenials(names_view_type view, names_iterator*iter)
{
    return names_createiterator(view->dbase, iter, 0, 0);
}

int
names_reversedenials(names_view_type view, names_iterator*iter)
{
    return names_createiterator(view->dbase, iter, 0, 0);
}

int
names_alldomains(names_view_type view, names_iterator*iter)
{
    return names_createiterator(view->dbase, iter, 0, 1);
}

struct node*
nextparent(struct index* index, struct node* node)
{
    return (&(node->nodes))[index->indexnum].parent;
}

int
names_parentdomains(names_view_type view, domain_type* domain, names_iterator* iter)
{
    /* horrible implementation */
    int indexnum = 0;
    struct node* node;
    struct index* indices;
    struct index* index;

    indices = &(view->dbase->indices);
    index = &(indices[indexnum]);
    node = searchindex(index, domain->dname);

    names_createiterator(view->dbase, iter, 0, 0);
    (*iter)->advance = nextparent;
    (*iter)->cursor = node;

    return 0;
}

domain_type*
names_lookupname(names_view_type view, ldns_rdf* name)
{
    int indexnum = 0;
    struct node* node;
    struct index* indices;
    struct index* index;
    indices = &(view->dbase->indices);
    index = &(indices[indexnum]);
    node = searchindex(index, name);
    return (node ? node->data : NULL);
} 

domain_type*
names_lookupapex(names_view_type view)
{
    return names_lookupname(view, view->apex);
}

struct node*
searchindex(struct index* index, ldns_rdf* key)
{
    int c;
    struct node* n;
    const char *s;
    n = index->root;
    do {
        if (n != NULL) {
            /*s = (const char*) n->data;
            s = &(s[index->offset]);
            c = index->cmpfn(s, key);*/
            c = index->cmpfn(key, n->data->dname);
            if (c<0) {
                n = node2tree(index, n)->left;
            } else if(c>0) {
                n = node2tree(index, n)->right;
            } else {
                return n;
            }
        }
    } while(n != NULL);
    return NULL;
}

domain_type*
names_addname(names_view_type view, ldns_rdf* name)
{
    domain_type* domain;
    assert(name != NULL);
    assert(name->_type == LDNS_RDF_TYPE_DNAME);
    domain = domain_create(name);
    insert(view->dbase, domain);
    return domain;
}

void initializeindex(struct index* index, int indexnum, indexfunc cmpfn, size_t offset)
{
    index->cmpfn = cmpfn;
    index->offset = offset;
    index->indexnum = indexnum;
    index->root = NULL;
}

void freeindex(struct index* index)
{
}

void deleteindex(struct index* index, struct node* node)
{
    struct tree* tree = node2tree(index, node);
    struct tree* parent = node2tree(index, tree->parent);
    if(parent != NULL) {
        if(parent->left == node) {
            parent->left = tree->left;
        } else {
            assert(parent->right == node);
            parent->right = tree->left;
        }
        node2tree(index, tree->left)->parent = tree->parent;
    } else {
        index->root = tree->left;
        node2tree(index, tree->left)->parent = NULL;
    }
    tree->parent = NULL;
    node = tree->left;
    while(node2tree(index, node)->right != NULL) {
        node = node2tree(index, node)->right;
    }
    node2tree(index, node)->right = tree->right;
    node2tree(index, tree->right)->parent = node;
}


void
insertindex(struct index* index, struct node* node)
{
    int c;
    struct node* parent = NULL;
    struct node** n = &index->root;
    while (*n) {
        parent = *n;
        /*c = index->cmpfn(&( ((const char*)(node->data))[index->offset]),
                         &( ((const char*)(parent->data))[index->offset]));*/
        c = index->cmpfn(node->data->dname, parent->data->dname);
        if (c < 0) {
            n = &(node2tree(index, parent)->left);
        } else if (c > 0) {
            n = &(node2tree(index, parent)->right);
        } else {
            assert(0);
        }
    }
    *n = node;
    assert(node);
    assert(node2tree(index, node));
    node2tree(index, node)->parent = parent;
    node2tree(index, node)->left = NULL;
    node2tree(index, node)->right = NULL;
}

struct node*
firstindex(struct index* index)
{
    struct node* node = index->root;
    while(node2tree(index, node)->left) {
        node = node2tree(index, node)->left;
    }
    return node;   
}

struct node*
lastindex(struct index* index)
{
    struct node* node = index->root;
    while(node2tree(index, node)->right) {
        node = node2tree(index, node)->right;
    }
    return node;   
}

struct node*
nextindex(struct index* index, struct node* node)
{
    struct node* parent;
    struct tree* tree = node2tree(index, node);
    if (tree->right != NULL) {
        node = tree->right;
        while (node2tree(index, node)->left) {
            node = node2tree(index, node)->left;
        }
    } else {
        parent = tree->parent;
        while(parent && node2tree(index, parent)->right == node) {
            node = parent;
            tree = node2tree(index, parent);
            parent = tree->parent;
        }
        node = parent;
    }
    return node;
}

struct node*
previousindex(struct index* index, struct node* node)
{
    struct node* parent;
    struct tree* tree = node2tree(index, node);
    if (tree->left != NULL) {
        node = tree->left;
        while (node2tree(index, node)->right) {
            node = node2tree(index, node)->right;
        }
    } else {
        parent = tree->parent;
        while(parent && node2tree(index, parent)->left == node) {
            node = parent;
            tree = node2tree(index, parent);
            parent = tree->parent;
        }
        node = parent;
    }
    return node;
}
