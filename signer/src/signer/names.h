#ifndef NAMES_H
#define	NAMES_H

struct namesrc_struct;
typedef struct namesrc_struct* namesrc_type;

struct names_struct;
typedef struct names_struct* names_type;

typedef struct iterator_struct* iterator;

#include "signer/denial.h"
#include "signer/domain.h"

int iterate(iterator*iter, void*);
int advance(iterator*iter, void*);
int end(iterator*iter);
int names_create(namesrc_type*);
int names_clear(namesrc_type);
domain_type* names_lookupapex(names_type);
domain_type* names_lookupname(names_type, ldns_rdf* name);
void names_destroy(namesrc_type);
int names_view(namesrc_type, names_type*);
int names_commit(names_type);
int names_rollback(names_type);
int names_dispose(names_type);
uint32_t names_getserial(names_type);
void names_setserial(names_type, uint32_t serial);
int names_firstdenials(names_type,iterator*iter);
int names_reversedenials(names_type,iterator*iter);
int names_alldomains(names_type,iterator*iter);
domain_type* names_addname(names_type view, ldns_rdf* name);

#endif	/* NAMES_H */
