#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ldns/ldns.h>
#include <ldns/host2str.h>
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

void
rr2data(ldns_rr* rr, char** recorddataptr, char** recordinfoptr)
{
    unsigned int i;
    int len;
    int recorddatalen;
    char* recorddata;
    char *s;
    const char* recordclass;
    uint32_t recordttl;

    recordclass = ldns_rr_class2str(ldns_rr_get_class(rr));
    recordttl = ldns_rr_ttl(rr);
    len = snprintf(NULL,0,"%u %s",recordttl,recordclass);
    *recordinfoptr = malloc(len+1);
    snprintf(*recordinfoptr,len+1,"%u %s",recordttl,recordclass);
    names_rr2data(rr, 0);
    *recorddataptr = recorddata;
}

void
rr2data_new(ldns_rr* rr, char** recorddataptr, char** recordinfoptr)
{
    int len;
    unsigned int i, j;
    int recorddatalen ;
    char* recorddata;
    ldns_rdf* rdata;
    uint8_t* data;
    const char* recordclass;
    uint32_t recordttl;

    recordclass = ldns_rr_class2str(ldns_rr_get_class(rr));
    recordttl = ldns_rr_ttl(rr);
    len = snprintf(NULL,0,"%u %s",recordttl,recordclass);
    *recordinfoptr = malloc(len+1);
    snprintf(*recordinfoptr,len+1,"%u %s",recordttl,recordclass);

    recorddatalen = 0;
    for (i = 0; i < ldns_rr_rd_count(rr); i++) {
        recorddatalen += ldns_rdf_size(ldns_rr_rdf(rr, i));
    }
    recorddatalen += snprintf(NULL, 0, "\\# %d", recorddatalen);
    recorddata = malloc(recorddatalen);
    recorddata += snprintf(recorddata, recorddatalen, "\\# %d", recorddatalen);
    for (i = 0; i < ldns_rr_rd_count(rr); i++) {
        rdata = ldns_rr_rdf(rr, i);
        data = ldns_rdf_data(rdata);
        for (j = 0; j < ldns_rdf_size(rdata); j++) {
            recorddata[0] = "0123456789abcdef"[data[j]>>8];
            recorddata[1] = "0123456789abcdef"[data[j]&0xf];
            recorddata += 2;
        }
    }
    *recorddataptr = recorddata;
}

int
readzone(names_view_type view, enum operation_enum operation, const char* filename, char** apexptr, int* defaultttlptr)
{
    char* s;
    char* recordname;
    ldns_rr_type recordtype;
    char* recordinfo;
    char* recorddata;
    resourcerecord_t item;
    names_iterator domainiter;
    names_iterator rrsetiter;
    names_iterator rriter;
    dictionary domainitem;
    int linenum;
    int keylength;
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
    if(!fp) {
        fprintf(stderr,"unable to open file \"%s\"\n",filename);
        return -1;
    }
    origin = NULL;
    prevowner = NULL;

    if(operation == PLAIN) {
        for (domainiter = names_viewiterator(view, 0); names_iterate(&domainiter, &domainitem); names_advance(&domainiter, NULL)) {
            getset(domainitem, "name", (const char**) &recordname, NULL);
            for (rrsetiter = names_recordalltypes(domainitem); names_iterate(&rrsetiter, &recordtype); names_advance(&rrsetiter, NULL)) {
                for (rriter = names_recordallvalues(domainitem,recordtype); names_iterate(&rriter, &item); names_advance(&rriter, NULL)) {
                    removal = names_rr2ident(domainitem, recordtype, item, sizeof(struct removal_struct));
                    removal->record = domainitem;
                    HASH_ADD_OPAQUE(removals, key, removal, keylength);
                }
            }
        }
    }

    while(!feof(fp)) {
        rr = NULL;
        if((err = ldns_rr_new_frm_fp_l(&rr,fp,&defaultttl,&origin,&prevowner,&linenum))) {
            switch(err) {
                case LDNS_STATUS_SYNTAX_INCLUDE:
                    abort(); // FIXME
                    break;
                case LDNS_STATUS_SYNTAX_TTL:
                    if(defaultttlptr) {
                        defaultttlptr = malloc(sizeof(int));
                        *defaultttlptr = defaultttl;
                    }
                    err = LDNS_STATUS_OK;
                    break;
                case LDNS_STATUS_SYNTAX_ORIGIN:
                    if(apexptr) {
                        *apexptr = ldns_rdf2str(origin);
                    }
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
                    fprintf(stderr,"Error at %s:%d \n",__FILE__,__LINE__);
                    fprintf(stderr,"%d %s\n", err, ldns_get_errorstr_by_id(err));
            }
        } else {
            recordname = ldns_rdf2str(ldns_rr_owner(rr));
            recordtype = ldns_rr_get_type(rr);
            rr2data(rr, &recorddata, &recordinfo);
            switch (operation) {
                case PLAIN:
                    record = names_place(view, recordname);
                    if (!names_recordhasdata(record,recordtype,rr,1)) {
                        names_own(view, &record);
                        rrset_add_rr(record, rr);
                    } else {
                        s = NULL;
                        composestring2(&s, recordname, recordtype, recorddata, NULL);
                        HASH_FIND_OPAQUE(removals, s, keylength, removal);
                        if (removal)
                            HASH_DEL(removals, removal);
                        free(s);
                    }
                    break;
                case DELTAPLUS:
                    record = names_place(view, recordname);
                    if (!names_recordhasdata(record,recordtype,rr,1)) {
                        names_own(view, &record);
                        rrset_add_rr(record, rr);
                    }
                    break;
                case DELTAMINUS:
                    record = names_take(view, 0, recordname);
                    if (names_recordhasdata(record,recordtype,rr,0)) {
                        names_own(view, &record);
                        names_recorddeldata(record,recordtype,rr);
                    }
                    break;
            }
            free((void*)recordname);
            free((void*)recordtype);
            free((void*)recorddata);
            free((void*)recordinfo);
        }
        ldns_rr_free(rr);
    }
    if(origin)
        ldns_rdf_deep_free(origin);
    if(prevowner)
        ldns_rdf_deep_free(prevowner);
    fclose(fp);

    if (removals) {
        for(removal=removals; removal!=NULL; removal=removal->hh.next) {
            recordname = (char*) removal->key;
            recordtype = ldns_get_rr_type_by_name(&recordname[strlen(recordname) + 1]);
            recorddata = &recordname[strlen(strlen(&recordname[strlen(recordname) + 1])) + 1];
            record = names_take(view, 0, recordname);
            names_own(view, &record);
            names_recorddeldata(record,recordtype,NULL); // FIXME should be recorddata iso NULL but ident stores data not
        }
        HASH_ITER(hh, removals, removal, tmp) {
            HASH_DEL(removals, removal);
            free(removal);
        }
        removals = NULL;
    }

    return 0;
}
