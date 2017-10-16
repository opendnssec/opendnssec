#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>
#include <ldns/ldns.h>
#include "names.h"
#include "domain.h"

/****************************************************************************/

struct data_struct;

typedef long reference_type;
/*typedef double reference_type;*/
struct data_struct {
    myvalue_type value;
    unsigned int deleted:1;
    reference_type references;
};
struct refer_struct {
  reference_type reference;
  struct data_struct* data;
};

typedef int (*indexfunc)(ldns_rdf*,ldns_rdf*);

struct index {
    reference_type root;
    indexfunc cmpfn;
    size_t offset;
    int left, up, right;
};

struct datastructure {
    int counter;
    int nindices;
    int referencetable;
    reference_type referencecount;
    struct index indices;
};

reference_type getreference(struct refer_struct* refer, int index);
void setreference(struct refer_struct* refer, int index, reference_type);
struct data_struct* dereference(struct refer_struct* refer);
reference_type rereference(struct datastructure* dbase, struct refer_struct* refer);
reference_type newreference(struct datastructure* dbase, struct data_struct* data, struct refer_struct*);
int isreference(reference_type reference);
int isrefer(struct refer_struct* refer);
reference_type nullreference();
void overreference(struct refer_struct* refer, reference_type);
void initreference(struct refer_struct* refer, reference_type);
int issame(reference_type, struct refer_struct*, int index);

struct data_struct* lookup(reference_type);
reference_type* offset(struct data_struct*, int index);

/****************************************************************************/

reference_type
getreference(struct refer_struct* refer, int index)
{
    if(!refer->data)
        refer->data = lookup(refer->reference);
    return *offset(refer->data, index);
}

void
setreference(struct refer_struct* refer, int index, reference_type reference)
{
    *offset(lookup(refer->reference), index) = reference;
}

struct data_struct*
dereference(struct refer_struct* refer)
{
    if(refer->data == NULL)
        refer->data = lookup(refer->reference);
    return refer->data;
}

reference_type
rereference(struct datastructure* dbase, struct refer_struct* refer)
{
    return newreference(dbase, dereference(refer), NULL);
}

reference_type
newreference(struct datastructure* dbase, struct data_struct* data, struct refer_struct* refer)
{
    if(refer) {
        refer->data = data;
        refer->reference = (long) data;
    }
    return (long) data;
}

int
isreference(reference_type reference)
{
    return reference != 0;
}

int
isrefer(struct refer_struct* refer)
{
    return isreference(refer->reference);
}

reference_type
nullreference()
{
    return 0;
}

void
initreference(struct refer_struct* refer, reference_type reference)
{
    refer->reference = reference;
    refer->data = NULL;
}

void
overreference(struct refer_struct* refer, reference_type reference)
{
    refer->reference = reference;
    refer->data = NULL;
}

int
issame(reference_type reference, struct refer_struct* refer, int index)
{
    reference_type r2;
    struct data_struct* d1;
    struct data_struct* d2;
    d1 = lookup(reference);
    r2 = getreference(refer, index);
    if(isreference(r2)) {
        d2 = lookup(r2);
        if(d1 == d2)
            return 1;
        else
            return 0;
    } else
        return 0;
}

struct data_struct*
lookup(reference_type reference)
{
    return (void*)reference;
}

reference_type*
offset(struct data_struct* data, int index)
{
    reference_type* references = &data->references;
    return &references[index];
}

/****************************************************************************/

void deleteindex(struct index* index, struct refer_struct* refer);
void insertindex(struct datastructure* dbase, struct index*, struct data_struct*);
void firstindex(struct index* index, struct refer_struct* refer);
void lastindex(struct index* index, struct refer_struct* refer);
reference_type nextindex(struct index* index, struct refer_struct* refer);
reference_type previousindex(struct index* index, struct refer_struct* refer);
struct refer_struct searchindex(struct index* index, ldns_rdf* key);
struct node* advanceindex(struct index*, struct node*);

struct names_view_struct {
    uint32_t serial;
    ldns_rdf* apex;
    struct datastructure* dbase;
    struct names_source_struct* source;
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

struct names_iterator_struct {
    struct datastructure* dbase;
    struct refer_struct cursor;
    reference_type next;
    struct index* index;
    reference_type (*advance)(struct index*, struct refer_struct*);
};

void
create(struct datastructure** dbase, ...)
{
    va_list ap;
    struct index* indices;
    struct index* index;
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
    (*dbase)->referencetable = 0;
    (*dbase)->referencecount = 1;
    indices = &((*dbase)->indices);
    va_start(ap, dbase);
    for(i=0; i<nindices; i++) {
        cmpfn = va_arg(ap, indexfunc);
        offset = va_arg(ap, size_t);
        index = &(indices[i]);
        index->cmpfn = cmpfn;
        index->offset = offset;
        index->root = nullreference();
        index->left = (*dbase)->referencetable++;
        index->up = (*dbase)->referencetable++;
        index->right = (*dbase)->referencetable++;
    }
    va_end(ap);
}

void
destroy(struct datastructure* dbase)
{
    free(dbase);
}

void
insert(struct datastructure* dbase, myvalue_type value)
{
    int i;
    struct data_struct* node;
    struct index* indices;
    indices = &(dbase->indices);
    node = malloc(sizeof(struct data_struct)+(3*sizeof(reference_type)*(dbase->nindices)-1));
    node->value = value;
    node->deleted = 0;
    for(i=0; i<dbase->nindices; i++) {
        insertindex(dbase, &(indices[i]), node);
    }
}

void
names_delete(names_iterator*iter)
{
    int i;
    (*iter)->next = (*iter)->advance((*iter)->index, &(*iter)->cursor);
    dereference(&(*iter)->cursor)->deleted = 1;
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
    (*iter)->next = nullreference();
    initreference(&(*iter)->cursor, nullreference());
    if (reverse) {
        lastindex(&(indices[indexnum]), &(*iter)->cursor);
        (*iter)->advance = previousindex;
    } else {
        firstindex(&(indices[indexnum]), &(*iter)->cursor);
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
    if(!isrefer(&(*iter)->cursor)) {
        if(arg != NULL)
            *(void**)arg = NULL;
        names_end(iter);
        return 0;
    }
    if(arg != NULL) {
        *(void**)arg = (void*) dereference(&(*iter)->cursor);
    }
    return 1;
}

int
names_advance(names_iterator*iter, void*arg)
{
    reference_type next;
    if(isreference((*iter)->next)) {
        next = (*iter)->next;
        (*iter)->next = nullreference();
    } else {
        next = (*iter)->advance((*iter)->index, &(*iter)->cursor);
    }
    if(!isreference(next)) {
        if(arg != NULL)
            *(void**)arg = NULL;
        names_end(iter);
        return 0;
    }
    overreference(&(*iter)->cursor, next);
    if(arg != NULL) {
        *(void**)arg = (void*) dereference(&(*iter)->cursor);
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
    myvalue_type value;
    /* for each view */
    for(names_alldomains(view,&iter); names_iterate(&iter,&value); names_advance(&iter,NULL)) {
        domain_cleanup(value);
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
    return 0;
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

reference_type
nextparent(struct index* index, struct refer_struct* refer)
{
    reference_type parent;
    parent = getreference(refer, index->up);
    overreference(refer, parent);
    return parent;
}

int
names_parentdomains(names_view_type view, domain_type* domain, names_iterator* iter)
{
    /* horrible implementation */
    int indexnum = 0;
    struct index* indices;
    struct index* index;
    struct refer_struct refer;

    indices = &(view->dbase->indices);
    index = &(indices[indexnum]);
    refer = searchindex(index, domain->dname);

    names_createiterator(view->dbase, iter, 0, 0);
    (*iter)->advance = nextparent;
    (*iter)->cursor = refer;

    return 0;
}

domain_type*
names_lookupname(names_view_type view, ldns_rdf* name)
{
    int indexnum = 0;
    reference_type node;
    struct index* indices;
    struct index* index;
    struct refer_struct refer;
    indices = &(view->dbase->indices);
    index = &(indices[indexnum]);
    refer = searchindex(index, name);
    if(isrefer(&refer)) {
        return dereference(&refer)->value;
    } else {
        return NULL;
    }
} 

domain_type*
names_lookupapex(names_view_type view)
{
    return names_lookupname(view, view->apex);
}

struct refer_struct
searchindex(struct index* index, ldns_rdf* key)
{
    int c;
    reference_type n;
    reference_type reference;
    struct refer_struct traverse;
    initreference(&traverse, index->root);
    struct data_struct* node;
    while(isrefer(&traverse)) {
        node = dereference(&traverse);
            /*s = (const char*) n->data;
            s = &(s[index->offset]);
            c = index->cmpfn(s, key);*/
            c = index->cmpfn(key, node->value->dname);
            if (c<0) {
                reference = getreference(&traverse, index->left);
                overreference(&traverse, reference);
            } else if(c>0) {
                reference = getreference(&traverse, index->right);
                overreference(&traverse, reference);
            } else {
                if(node->deleted) {
                    reference = getreference(&traverse, index->right);
                    overreference(&traverse, reference);
                } else {
                    break;
                }
            }
    }
    return traverse;
}

myvalue_type
names_addname(names_view_type view, ldns_rdf* name)
{
    myvalue_type domain;
    assert(name != NULL);
    assert(name->_type == LDNS_RDF_TYPE_DNAME);
    domain = domain_create(name);
    insert(view->dbase, domain);
    return domain;
}

void
insertindex(struct datastructure* dbase, struct index* index, struct data_struct* newnode)
{
    int c;
    reference_type newref;
    struct refer_struct refer;
    struct data_struct* node =  NULL;
    reference_type traverse;
    struct refer_struct parent;
    int direction;
    newref = newreference(dbase, newnode, &refer);
    traverse = index->root;
    if (isreference(traverse)) {
        while (isreference(traverse)) {
            overreference(&parent, traverse);
            node = (struct data_struct*) dereference(&parent);
            c = index->cmpfn(newnode->value->dname, node->value->dname);
            if (c < 0) {
                direction = index->left;
            } else if (c >= 0) {
                direction = index->right;
            }
            traverse = getreference(&parent, direction);
        }
        setreference(&parent, direction, newref);
        setreference(&refer, index->up, rereference(dbase, &parent));
    } else {
        index->root = newref;
        setreference(&refer, index->up, nullreference());
    }
    setreference(&refer, index->left, nullreference());
    setreference(&refer, index->right, nullreference());
}

void
firstindex(struct index* index, struct refer_struct* refer)
{
    initreference(refer, index->root);
    while(isreference(refer->reference)) {
        overreference(refer, getreference(refer, index->left));
    }
}

void
lastindex(struct index* index, struct refer_struct* refer)
{
    initreference(refer, index->root);
    while(isreference(refer->reference)) {
        overreference(refer, getreference(refer, index->right));
    }
}

reference_type
nextindex(struct index* index, struct refer_struct* refer)
{
    reference_type sibling, offspring;
    if (isreference(sibling = getreference(refer, index->right))) {
        overreference(refer, sibling);
        while (isreference(sibling = getreference(refer, index->up))) {
            overreference(refer, sibling);
        }
    } else {
        do {
            offspring = refer->reference;
            overreference(refer, getreference(refer, index->up));
        } while (issame(offspring, refer, index->right));
    }
    return refer->reference;
}


reference_type
previousindex(struct index* index, struct refer_struct* refer)
{
    reference_type sibling, offspring;
    if (isreference(sibling = getreference(refer, index->left))) {
        overreference(refer, sibling);
        while (isreference(sibling = getreference(refer, index->right))) {
            overreference(refer, sibling);
        }
    } else {
        do {
            offspring = refer->reference;
            overreference(refer, getreference(refer, index->up));
        } while (issame(offspring, refer, index->left));
    }
    return refer->reference;
}

/****************************************************************************/
