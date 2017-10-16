#ifndef NAMES_H
#define	NAMES_H

/*
 * This module handles the datastructure containing the domain names.  Since
 * domain names in a zone may be changes due to incoming changes, signing
 * process, and keeping a zone available for outgoing transfers, there
 * is a concept of a VIEW on a zone.  A view is obtained depending on the
 * usage of the zone, and a possible exclusive access right is kept during
 * the view lifetime.  A view should only be used by a single thread or
 * collection of threads that work together.  It is only possible to access
 * one view at a time by these threads.
 * 
 * A view is obtained from the collection of available views, which has been
 * named the SOURCE.  Any modifications to a view is not visible to other
 * views, until the view committed, at which time the view is no longer
 * available.
 * 
 * A view does not allow direct access to the names in a domain.  Only through
 * the use of iterators.  An iterator isn't normally created, but obtained
 * from a view.  Several ways to iterate over parts of the names available
 * are available.  One should use the specific iterator which covers the names
 * selected, and not a too generic iterator and filter out nodes afterwards.
 * While iterating, you can either abort iterating (through the use of
 * names_end()), or obtain the current data item the cursor of the iterator
 * points to (using iterator_iterate), advance the cursor to the next element
 * (names_advance).  Insert a new element before (if applicable) the cursor
 * through names_insert or delete the element the cursor of the iterator points
 * to (names_delete).
 * After either advancing or deleting, the element is no longer available and
 * you should have no references to it.
 * 
 * The following illustrates a common usage:
 * 
 *   void myupdateofofdaterecords(names_source_type source) {
 *     names_iterator_type iter;
 *     names_view_type view;
 *     struct myrecord* currentrecord;
 *     struct myrecord* newrecord;
 *     names_view(source,&view);
 *     for(names_getoutdatedrecords(view,&iter);
 *         names_iterate(&iter,&currentrecord);
 *         names_advance(&iter,NULL)) {
 *       if(!myupdaterecord(currentrecord, newrecord)) {
 *         // failure
 *         names_end(currentrecord);
 *         names_rollback(view);
 *         return;
 *       }
 *       names_delete(&iter);
 *       names_insert(&iter,&newrecord);
 *     }
 *     names_commit(view);
 */

typedef struct names_source_struct* names_source_type;
typedef struct names_view_struct* names_view_type;
typedef struct names_iterator_struct* names_iterator;
typedef struct names_reference_struct* names_reference_type;

struct datastructure;

#include "signer/denial.h"
#include "signer/domain.h"

typedef domain_type* myvalue_type;
typedef ldns_rdf* mykey_type;

int names_create(names_source_type*, ldns_rdf* apex);
int names_clear(names_source_type);
void names_destroy(names_source_type);

int names_view(names_source_type, names_view_type*);
int names_commit(names_view_type);
int names_rollback(names_view_type);
int names_dispose(names_view_type);

/* The following two calls are to be changed */
domain_type* names_lookupname(names_view_type, ldns_rdf* name);
domain_type* names_lookupapex(names_view_type);

domain_type* names_addname(names_view_type view, ldns_rdf* name);

uint32_t names_getserial(names_view_type);
void names_setserial(names_view_type, uint32_t serial);

int names_firstdenials(names_view_type,names_iterator*iter);
int names_reversedenials(names_view_type,names_iterator*iter);
int names_alldomains(names_view_type,names_iterator*iter);
int names_parentdomains(names_view_type,domain_type*,names_iterator*iter);

int names_createiterator(struct datastructure*dbase, names_iterator* iter, int indexnum, int reverse);
int names_iterate(names_iterator*iter, void*);
int names_advance(names_iterator*iter, void*);
int names_insert(names_iterator*iter,void*);
void names_delete(names_iterator*iter);
int names_end(names_iterator*iter);

#endif	/* NAMES_H */
