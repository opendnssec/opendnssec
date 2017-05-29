#include "config.h"
#include <ldns/ldns.h>
#include "names.h"

int iterate(iterator*iter, void*arg)
{ return 0; }
int advance(iterator*iter, void*arg)
{ return 0; }
int end(iterator*iter)
{ return 0; }
int names_create(namesrc_type*arg)
{ return 0; }
void names_destroy(namesrc_type source)
{ }
int names_view(namesrc_type source, names_type*view)
{ return 0; }
int names_commit(names_type view)
{ return 0; }
int names_rollback(names_type view)
{ return 0; }
int names_dispose(names_type view)
{ return 0; }
uint32_t names_getserial(names_type view)
{ return 0; }
void names_setserial(names_type view, uint32_t serial)
{ }
int names_firstdenials(names_type view,iterator*iter)
{ return 0; }
int names_reversedenials(names_type view,iterator*iter)
{ return 0; }
int names_alldomains(names_type view,iterator*iter)
{ return 0; }
int names_clear(namesrc_type source)
{ return 0; }
domain_type* names_lookupapex(names_type view)
{ return 0; }
domain_type* names_lookupname(names_type view, ldns_rdf* name)
{ return 0; }
domain_type* names_addname(names_type view, ldns_rdf* name)
{ return 0; }
