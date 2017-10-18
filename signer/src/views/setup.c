#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ldns/ldns.h>
#include "uthash.h"
#include "proto.h"

#pragma GCC optimize ("O0")

#define HASH_FIND_OPAQUE(head,findptr,findlen,out) \
    HASH_FIND(hh,head,findptr,(unsigned)findlen,out)
#define HASH_ADD_OPAQUE(head,field,add,addlen) \
    HASH_ADD(hh,head,field[0],(unsigned)addlen,add)

struct removal_struct {
    dictionary record;
    UT_hash_handle hh;
    char key[];
};
struct removal_struct* removals = NULL;

static void
removeRR(names_view_type view, dictionary record, char* recordtype, char* recorddata)
{
    dictionary rrs;
    names_iterator iter;
    rrs = get(record, recordtype);
    del(rrs, recorddata);
    iter = all(rrs);
    if (names_iterate(&iter, NULL)) {
        names_end(&iter);
        del(record, recordtype);
        if (names_iterate(&iter, NULL)) {
            names_end(&iter);
            names_remove(view, record);
        }
    }
}

static void
composestring(char* dst, char* src, ...)
{
    int len;
    va_list ap;
    va_start(ap, src);
    while(src != NULL) {
        len = strlen(src);
        strncpy(dst, src, len+1);
        dst += len + 1;
        src = va_arg(ap, char*);
    }
    va_end(ap);
}

enum operation_enum { PLAIN, DELTAMINUS, DELTAPLUS };

int
readzone(names_view_type view, enum operation_enum operation, const char* filename)
{
    char* s;
    char* recordname;
    char* recordtype;
    char* recorddata;
    names_iterator domainiter;
    names_iterator rrsetiter;
    names_iterator rriter;
    dictionary domainitem;
    dictionary rrsetitem;
    dictionary rritem;
    int linenum;
    int keylength;
    size_t recorddatalen;
    unsigned int i;
    unsigned int defaultttl;
    ldns_status err;
    FILE* fp;
    ldns_rdf* origin;
    ldns_rdf* prevowner;
    dictionary record;
    struct removal_struct* removal;
    struct removal_struct* tmp;
    ldns_rr* rr;

    fp = fopen(filename,"r");
    origin = NULL;
    prevowner = NULL;

    if(operation == PLAIN) {
        for (domainiter = names_viewiterator(view, 0); names_iterate(&domainiter, &domainitem); names_advance(&domainiter, NULL)) {
            for (rrsetiter = all(get(domainitem, "rrs")); names_iterate(&rrsetiter, &rrsetitem); names_advance(&rrsetiter, NULL)) {
                for (rriter = all(get(rrsetitem, "rr")); names_iterate(&rriter, &rritem); names_advance(&rriter, NULL)) {
                    recordname = getname(domainitem, NULL);
                    recordtype = getname(rrsetitem, NULL);
                    recorddata = getname(rritem, NULL);
                    keylength = strlen(recordname) + 1 + strlen(recordtype) + 1 + strlen(recorddata) + 1;
                    removal = malloc(sizeof (struct removal_struct) + keylength);
                    removal->record = domainitem;
                    composestring(removal->key, recordname, recordtype, recorddata, NULL);
                    HASH_ADD_OPAQUE(removals, key, removal, keylength);
                }
            }
        }
    }

    while(!feof(fp)) {
        if((err = ldns_rr_new_frm_fp_l(&rr,fp,&defaultttl,&origin,&prevowner,&linenum))) {
            switch(err) {
                case LDNS_STATUS_SYNTAX_INCLUDE:
                    abort();
                    break;
                case LDNS_STATUS_SYNTAX_TTL:
                case LDNS_STATUS_SYNTAX_ORIGIN:
                    err = LDNS_STATUS_OK;
                    break;
                case LDNS_STATUS_SYNTAX_EMPTY:
                    switch(operation) {
                        case PLAIN:
                            break;
                        case DELTAMINUS:
                            operation = DELTAPLUS;
                            break;
                        case DELTAPLUS:
                            operation = DELTAMINUS;
                            break;
                    }
                    err = LDNS_STATUS_OK;
                    break;
                default:
                    fprintf(stderr,"%d %s\n", err, ldns_get_errorstr_by_id(err));
            }
        } else {
            recorddatalen = 0;
            for(i=0; i<ldns_rr_rd_count(rr); i++) {
                s = ldns_rdf2str(ldns_rr_rdf(rr,i));
                recorddatalen += strlen(s);
                free(s);
            }
            recordname = ldns_rdf2str(ldns_rr_owner(rr));
            recordtype = ldns_rr_type2str(ldns_rr_get_type(rr));
            recorddata = malloc(recorddatalen+1);
            recorddata[0] = '\0';
            for(i=0; i<ldns_rr_rd_count(rr); i++) {
                s = ldns_rdf2str(ldns_rr_rdf(rr,i));
                strcat(recorddata, s);
                free(s);
            }
            record = names_place(view, recordname);
            if (!has(record, recordtype, recorddata, NULL)) {
                switch (operation) {
                    case PLAIN:
                    case DELTAPLUS:
                        names_own(view, &record);
                        set(record, "name", recordname);
                        add(record, recordtype);
                        add(get(record, recordtype), recorddata);
                        break;
                    case DELTAMINUS:
                        break;
                }
            } else {
                switch (operation) {
                    case PLAIN:
                        keylength = strlen(recordname) + 1 + strlen(recordtype) + 1 + strlen(recorddata) + 1;
                        s = malloc(sizeof (struct removal_struct) +keylength);
                        composestring(s, recordname, recordtype, recorddata, NULL);
                        HASH_FIND_OPAQUE(removals, s, keylength, removal);
                        if (removal)
                            HASH_DEL(removals, removal);
                        free(s);
                        break;
                    case DELTAPLUS:
                        break;
                    case DELTAMINUS:
                        record = names_take(view, 0, recordname);
                        names_own(view, &record);
                        removeRR(view, record, recordtype, recorddata);
                        break;
                }
            }
            free(recordname);
            free(recordtype);
            free(recorddata);
        }
    }
    fclose(fp);

    if (removals) {
        for(removal=removals; removal!=NULL; removal=removal->hh.next) {
            recordname = (char*) removal->key;
            recordtype = &recordname[strlen(recordname) + 1];
            recorddata = &recordtype[strlen(recordtype) + 1];
            record = names_take(view, 0, recordname);
            names_own(view, &record);
            removeRR(view, record, recordtype, recorddata);
        }
        HASH_ITER(hh, removals, removal, tmp) {
            HASH_DEL(removals, removal);
            free(removal);
        }
        removals = NULL;
    }

    return 0;
}

