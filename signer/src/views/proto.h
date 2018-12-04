/*
 * Copyright (c) 2018 NLNet Labs.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PROTO_H
#define PROTO_H

typedef struct names_iterator_struct* names_iterator;
typedef struct recordset_struct* recordset_type;
typedef struct names_index_struct* names_index_type;
typedef struct names_table_struct* names_table_type;
typedef struct names_view_struct* names_view_type;

#include "signer/signconf.h"
#include "signer/zone.h"
#include "views/marshalling.h"
#include "logging.h"

extern const char* names_view_BASE[];
extern const char* names_view_INPUT[];
extern const char* names_view_PREPARE[];
extern const char* names_view_NEIGHB[];
extern const char* names_view_SIGN[];
extern const char* names_view_OUTPUT[];
extern const char* names_view_CHANGES[];
extern const char* names_view_BACKUP[];

extern logger_cls_type names_logcommitlog;

struct signature_struct {
    ldns_rr* rr;
    const char* keylocator;
    int keyflags;
};
struct signatures_struct {
    int nsigs;
    struct signature_struct* sigs;
};
void signaturedispose(struct signatures_struct* sigs);

/*
 * Definitions relating to an iterator.  An iterator is a object handle that
 * allows you to loop over the elements contained in some abstract data
 * structure.  The properties are dictated by the data structure, e.g. if the
 * data structure guarantees a certain order, then the elements are returned
 * in order, and whether the elements may be modified is also governed by
 * the data structure.  An iterator is obtained from the data structure
 * related functions.  The iterator functions only hide the implementation
 * details of the data structure, so that you do not faced whether to follow
 * a next pointer or other method to traverse the abstract data structure.
 * 
 * An iterator is a cursor into a set of items.  Initial, the cursor is
 * placed on the first item.  The entire set of items must be iterated over,
 * or the end() call must be used to terminate the iteration of elements,
 * however it should be assumed performance is directly proportionally with
 * the number of items in the set, NOT the actual number of items iterated
 * over.  Additionally obtaining an iterator should be assumed to have a
 * significant performance impact.  With both assumptions in mind, you
 * should get the right type of iteration in place, which retrieved indeed
 * the set of items needed, rather than just one every time or all of the
 * items in the data structure.
 * 
 * Two typical usaged could be:
 *     struct mystruct* item;
 *     iterator iter = getiterator(...);
 *     if(iterate(&iter, &item)) {
 *         printf("%s",item->myname);
 *         while(advance(&iter, &item)) {
 *             printf(",%s", item->myname);
 *             if(need_bail_out()) {
 *                 end(&iter);
 *                 break;
 *             }
 *         }
 *         printf("\n");
 *     } else
 *         printf("There are no items\n");
 * Or:
 *     for(iter=getiterator(...); iterate(&iter, &item); advance(&iter,NULL))
 *         printf("%s\n",item->myname);
 * 
 * The iterate() call returns whether the cursor is not yet beyond the end of
 * the set of items in the iteration.  If the second argument is not the NULL
 * pointer, the current item is returned in it.
 * 
 * The advance() call advances the cursor to the next element in the list.
 * If the cursor advances past the last item, the end() call is implicitly
 * executed.  If the second argument is not NULL, the item pointed to by the
 * cursor after advancing is returned in it.
 * 
 * The end() call terminates the iteration prematurely and releases any
 * memory or locks implied by the iterator.  If will always return
 * successful.
 */

int names_iterate(names_iterator*iter, void* item);
int names_advance(names_iterator*iter, void* item);
int names_end(names_iterator*iter);

names_iterator names_iterator_createarray(int count, void* data, void (*indexfunc)(names_iterator iter,void*,int,void*));
names_iterator names_iterator_createrefs(void (*freefunc)(void*));
names_iterator names_iterator_createdata(size_t size);
void names_iterator_addptr(names_iterator iter, const void* ptr);
void names_iterator_adddata(names_iterator iter, const void* ptr);

/* A dictionary is an abstract data structure capable of storing key
 * value pairs, where each value is again a dictionary.
 * A (sub)dictionary can also have a name.
 * 
 * The purpose is for the moment as placeholder and to be replaced with
 * the domain structure, containing the denial, rrset, etcetera structures.
 */

struct names_view_zone {
    int* defaultttl;
    const char* apex;
    signconf_type** signconf;
};

recordset_type names_recordcreate(char**name);
recordset_type names_recordcreatetemp(const char*name);
void names_recordannotate(recordset_type d, struct names_view_zone* zone);
recordset_type names_recordcopy(recordset_type, int clear);
void names_recorddispose(recordset_type);
void names_recorddisposal(recordset_type record, int doit);
const char* names_recordgetname(recordset_type dict);
int names_recordgetrevision(recordset_type dict);
const char *names_recordgetsummary(recordset_type dict, char**);
const char* names_recordgetdenial(recordset_type dict);
int names_recordcompare_namerevision(recordset_type a, recordset_type b);
int names_recordhasdata(recordset_type record, ldns_rr_type recordtype, ldns_rr* rr, int exact);
void names_recordadddata(recordset_type d, ldns_rr* rr);
void names_recorddeldata(recordset_type d, ldns_rr_type rrtype, ldns_rr* rr);
void names_recorddelall(recordset_type, ldns_rr_type rrtype);
names_iterator names_recordalltypes(recordset_type);
names_iterator names_recordallvalues(recordset_type, ldns_rr_type rrtype);
names_iterator names_recordallvaluestrings(recordset_type d, ldns_rr_type rrtype);
int names_recordvalidupto(recordset_type, int*);
int names_recordgetvalidupto(recordset_type);
int names_recordvalidfrom(recordset_type, int*);
int names_recordcmpdenial(recordset_type record, ldns_rr* denial);
void names_recordsetdenial(recordset_type record, ldns_rr* denial);
void names_recordsetvalidupto(recordset_type record, int value);
void names_recordsetvalidfrom(recordset_type, int value);
int names_recordhasexpiry(recordset_type);
int64_t names_recordgetexpiry(recordset_type);
void names_recordsetexpiry(recordset_type, int64_t value);
void names_recordaddsignature(recordset_type record, ldns_rr_type rrtype, ldns_rr* rrsig, const char* keylocator, int keyflags);
int names_recordmarshall(recordset_type*, marshall_handle);

void names_recordlookupone(recordset_type record, ldns_rr_type type, ldns_rr* template, ldns_rr** rr);
void names_recordlookupall(recordset_type record, ldns_rr_type type, ldns_rr* template, ldns_rr_list** rrs, ldns_rr_list** rrsigs);

struct dual {
    recordset_type src;
    recordset_type dst;
};

int names_indexcreate(names_index_type*, const char* keyname);
recordset_type names_indexlookup(names_index_type, recordset_type);
recordset_type names_indexlookupnext(names_index_type index, recordset_type find);
recordset_type names_indexlookupkey(names_index_type, const char* keyvalue);
int names_indexremove(names_index_type, recordset_type);
int names_indexremovekey(names_index_type,const char* keyvalue);
int names_indexinsert(names_index_type index, recordset_type d, recordset_type* existing);
void names_indexdestroy(names_index_type, void (*userfunc)(void* arg, void* key, void* val), void* userarg);
names_iterator names_indexiterator(names_index_type);

/* Table structures are used internally by views to record changes made in
 * the view.  A table is a set of changes, also dubbed a changelog.
 * The table* functions are not to be used outside of the scope of the
 * names_ module.
 */

names_table_type names_tablecreate(int (*cmpf)(const void *, const void *));
names_table_type names_tablecreate2(names_table_type oldtable);
void names_tabledispose(names_table_type table, void (*userfunc)(void* arg, void* key, void* val), void* userarg);
void* names_tableget(names_table_type table, void* name);
int names_tabledel(names_table_type table, char* name);
void** names_tableput(names_table_type table, void* name);
void names_tableconcat(names_table_type* list, names_table_type item);
names_iterator names_tableitems(names_table_type table);

/* The changelog_ functions are also not to be used directly, they
 * extend the table functionality in combination with the views.
 */

typedef struct names_commitlog_struct* names_commitlog_type;

void names_commitlogdestroy(names_table_type changelog);
void names_commitlogdestroyfull(names_table_type changelog);
void names_commitlogdestroyall(names_commitlog_type views, marshall_handle* store);
int names_commitlogpoppush(names_commitlog_type, int viewid, names_table_type* previous, names_table_type* mychangelog);
int names_commitlogsubscribe(names_view_type view, names_commitlog_type*);
void names_commitlogunsubscribe(int viewid, names_commitlog_type commitlogptr);
void names_commitlogpersistincr(names_commitlog_type, names_table_type changelog);
void names_commitlogpersistappend(names_commitlog_type, void (*persistfn)(names_table_type, marshall_handle), marshall_handle store);
int names_commitlogpersistfull(names_commitlog_type, void (*persistfn)(names_table_type, marshall_handle), int viewid, marshall_handle store, marshall_handle* oldstore);

void names_own(names_view_type view, recordset_type* record);
void names_underwrite(names_view_type view, recordset_type* record);
void names_overwrite(names_view_type view, recordset_type* record);
void names_update(names_view_type view, recordset_type* record);
void names_amend(names_view_type view, recordset_type record);
void* names_place(names_view_type store, const char* name);
void* names_take(names_view_type view, int index, const char* name);
void names_remove(names_view_type view, recordset_type record);
names_view_type names_viewcreate(names_view_type base, const char* name, const char** keynames);
void names_viewdestroy(names_view_type view);
void names_viewvalidate(names_view_type view);

typedef names_iterator (*names_indexrange_func)();
names_iterator names_viewiterator(names_view_type view, names_indexrange_func func, ...);
void names_recordindexfunction(const char* keyname, int (**acceptfunction)(recordset_type newitem, recordset_type currentitem, int* cmp), int (**comparefunction)(const void *, const void *));
void names_indexsearchfunction(names_index_type index, names_view_type view, const char* keyname);
void names_viewaddsearchfunction(names_view_type, names_index_type, names_indexrange_func);
void names_viewaddsearchfunction2(names_view_type, names_index_type, names_index_type, names_indexrange_func);
names_iterator names_iteratorancestors(names_index_type index, va_list ap);
names_iterator names_iteratordescendants(names_index_type index, va_list ap);
names_iterator names_iteratordenialchainupdates(names_index_type primary, names_index_type secondary, va_list ap);
names_iterator names_iteratorincoming(names_index_type primary, names_index_type secondary, va_list ap);
names_iterator names_iteratorexpiring(names_index_type index, va_list ap);
names_iterator names_iteratorchangedeletes(names_index_type index, va_list ap);
names_iterator names_iteratorchangeinserts(names_index_type index, va_list ap);
names_iterator names_iteratorchanges(names_index_type index, va_list ap);
names_iterator names_iteratoroutdated(names_index_type index, va_list ap);

int names_viewcommit(names_view_type view);
void names_viewreset(names_view_type view);
int names_viewpersist(names_view_type view, int basefd, char* filename);
int names_viewconfig(names_view_type view, signconf_type** signconf);
int names_viewrestore(names_view_type view, const char* apex, int basefd, const char* filename);

void names_viewlookupall(names_view_type view, ldns_rdf* dname, ldns_rr_type type, ldns_rr_list** rrs, ldns_rr_list** rrsigs);
void names_viewlookupone(names_view_type view, ldns_rdf* dname, ldns_rr_type type, ldns_rr* template, ldns_rr** rr);

int names_viewgetdefaultttl(names_view_type view, int* defaultttl);
int names_viewgetapex(names_view_type view, ldns_rdf** apexptr);

void names_dumprecord(FILE*, recordset_type record);
void names_dumpviewinfo(FILE*, names_view_type view);
void names_dumpviewfull(FILE*, names_view_type view);
void names_dumpindex(FILE* fp, names_view_type view, int index);
void names__dumpindex(FILE* fp, names_index_type index);

void writerecordcontent(recordset_type domainitem, FILE* fp);
void writezonecontent(names_view_type view, FILE* fp);
void writezoneapex(names_view_type view, FILE* fp);
int writezone(names_view_type view, const char* filename);
enum operation_enum { PLAIN, DELTAMINUS, DELTAPLUS };
int readzone(names_view_type view, enum operation_enum operation, const char* filename, char** apexptr, int* defaultttlptr);
void purgezone(zone_type* zone);

ldns_rr_type domain_is_occluded(names_view_type view, recordset_type record);
ldns_rr_type domain_is_delegpt(names_view_type view, recordset_type record);
ldns_rr* denial_nsecify(signconf_type* signconf, names_view_type view, recordset_type domain, ldns_rdf* nxt); // FIXME rename
ods_status namedb_update_serial(zone_type* globalzone);
ods_status rrset_sign(signconf_type* signconf, names_view_type view, recordset_type domain, ldns_rr_type rrtype, hsm_ctx_t* ctx, time_t signtime);
ods_status rrset_getliteralrr(ldns_rr** dnskey, const char *resourcerecord, uint32_t ttl, ldns_rdf* apex);
ods_status namedb_domain_entize(names_view_type view, recordset_type domain, ldns_rdf* dname, ldns_rdf* apex);

#endif
