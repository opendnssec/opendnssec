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

enum operation_enum { PLAIN, DELTAMINUS, DELTAPLUS };

void clearvalidity(dictionary record);

int
readzone(names_view_type view, enum operation_enum operation, const char* filename, char** apexptr, int* defaultttlptr)
{
    char* s;
    const char* recordname;
    char* recordtype;
    char* recorddata;
    names_iterator domainiter;
    names_iterator rrsetiter;
    names_iterator rriter;
    dictionary domainitem;
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
            getset(domainitem, "name", &recordname, NULL);
            for (rrsetiter = names_recordalltypes(domainitem); names_iterate(&rrsetiter, &recordtype); names_advance(&rrsetiter, NULL)) {
                for (rriter = names_recordallvalues(domainitem,recordtype); names_iterate(&rriter, &recorddata); names_advance(&rriter, NULL)) {
                    keylength = composestring2(NULL, recordname, recordtype, recorddata, NULL);;
                    removal = malloc(sizeof (struct removal_struct) + keylength);
                    removal->record = domainitem;
                    composestring(removal->key, recordname, recordtype, recorddata, NULL);
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
                    abort();
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
                    fprintf(stderr,"%d %s\n", err, ldns_get_errorstr_by_id(err));
            }
        } else {
            recorddatalen = 0;
            for(i=0; i<ldns_rr_rd_count(rr); i++) {
                s = ldns_rdf2str(ldns_rr_rdf(rr,i));
                recorddatalen += strlen(s) + 1;
                free(s);
            }
            recordname = ldns_rdf2str(ldns_rr_owner(rr));
            recordtype = ldns_rr_type2str(ldns_rr_get_type(rr));
            // FIXME class, ttl, and other fields
            recorddata = malloc(recorddatalen);
            recorddata[0] = '\0';
            for(i=0; i<ldns_rr_rd_count(rr); i++) {
                s = ldns_rdf2str(ldns_rr_rdf(rr,i));
                if (i>0)
                    strcat(recorddata, " ");
                strcat(recorddata, s); //FIXME concatename items that need " or (
                free(s);
            }
            switch (operation) {
                case PLAIN:
                    record = names_place(view, recordname);
                    if (!names_recordhasdata(record, recordtype, recorddata)) {
                        names_own(view, &record);
                        clearvalidity(record);
                        names_recordadddata(record, recordtype, recorddata);
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
                    if (!names_recordhasdata(record,recordtype,recorddata)) {
                        names_own(view, &record);
                        clearvalidity(record);
                        names_recordadddata(record,recordtype,recorddata);
                    }
                    break;
                case DELTAMINUS:
                    record = names_take(view, 0, recordname);
                    if (names_recordhasdata(record,recordtype,recorddata)) {
                        names_own(view, &record);
                        clearvalidity(record);
                        names_recorddeldata(record,recordtype,recorddata);
                    }
                    break;
            }
            free(recordname);
            free(recordtype);
            free(recorddata);
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
            recordtype = &recordname[strlen(recordname) + 1];
            recorddata = &recordtype[strlen(recordtype) + 1];
            record = names_take(view, 0, recordname);
            names_own(view, &record);
            clearvalidity(record);
            names_recorddeldata(record,recordtype,recorddata);
        }
        HASH_ITER(hh, removals, removal, tmp) {
            HASH_DEL(removals, removal);
            free(removal);
        }
        removals = NULL;
    }

    return 0;
}

void
writezone(names_view_type view, const char* filename, const char* apex, int* defaultttl)
{
    char* s;
    const char* recordname;
    char* recordtype;
    char* recorddata;
    names_iterator domainiter;
    names_iterator rrsetiter;
    names_iterator rriter;
    dictionary domainitem;
    ldns_rdf* origin;
    FILE* fp;

    origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, apex);
    fp = fopen(filename,"w");

    s = ldns_rdf2str(origin);
    fprintf(fp, "$ORIGIN %s\n", s);
    free(s);
    if(defaultttl)
        fprintf(fp, "$TTL %d\n",*defaultttl);

    for (domainiter = names_viewiterator(view, 0); names_iterate(&domainiter, &domainitem); names_advance(&domainiter, NULL)) {
        getset(domainitem, "name", &recordname, NULL);
        for (rrsetiter = names_recordalltypes(domainitem); names_iterate(&rrsetiter, &recordtype); names_advance(&rrsetiter, NULL)) {
            for (rriter = names_recordallvalues(domainitem,recordtype); names_iterate(&rriter, &recorddata); names_advance(&rriter, NULL)) {
                fprintf(fp, "%s\t%s\t%s\n", recordname, recordtype, recorddata);
            }
        }
    }
    fclose(fp);
    ldns_rdf_free(origin);
}

int markcount = 0;
int marktime;
intptr_t markbrk;

int
mark(char* message) {
    time_t t;
    intptr_t b;
    if(markcount == 0) {
        t = marktime = time(NULL);
        b = markbrk = (intptr_t) sbrk(0);
    } else {
        t = time(NULL);
        b = (intptr_t) sbrk(0);
    }
    fprintf(stderr, "MARK#%02d %2ld %4ld %s\n", markcount, t-marktime, (b-markbrk+1048576/2)/1048576, message);
    ++markcount;
    return 0;
}

void
prepare(names_view_type view, int newserial)
{
    dictionary record;
    struct dual* change;
    names_iterator iter;
    for (iter=neighbors(view); names_iterate(&iter,&change); names_advance(&iter,NULL)) {
        record = change->dst;
        if(names_recordhasexpiry(record)) {
            names_recordsetvalidupto(record, newserial);
            names_own(view, &record);
            clearvalidity(record);
            names_recordsetvalidfrom(record, newserial);
        }
    }
    for (iter=noexpiry(view); names_iterate(&iter,&change); names_advance(&iter,NULL)) {
        assert(change->src != change->dst);
        if(change->src && !names_recordhasvalidupto(change->src)) {
            names_amend(view, change->src);
            names_recordsetvalidupto(change->src, newserial);
        }
        if(!names_recordhasvalidfrom(change->dst)) {
            if(names_recordhasdata(change->dst, NULL, NULL)) {
                names_amend(view, change->dst);
                names_recordsetvalidfrom(change->dst, newserial);
            } else {
                names_remove(view, record);
            }
        }
    }
}

struct signconf {
    int nkeys;
    struct signconfkey {
        char* filename;
        FILE* fp;
        ldns_key* key;
        ldns_rr* dsrecord;
        ldns_rr* keyrecord;
    }* keys;
    ldns_key_list* keylist;
};

struct signconf*
createsignconf(int nkeys)
{
    int i;
    struct signconf* signconf;
    signconf = malloc(sizeof(struct signconf));
    signconf->nkeys = nkeys;
    signconf->keys = malloc(signconf->nkeys * sizeof(struct signconfkey));
    for(i=0; i<signconf->nkeys; i++) {
        signconf->keys[i].filename = "";
    }
    return signconf;
}

void
destroysignconf(struct signconf* signconf)
{
    int i;
    for(i=0; i<signconf->nkeys; i++) {
        free(signconf->keys[i].filename);
    }
    free(signconf->keys);
    free(signconf);
}

void
setupsignconf(struct signconf* signconf)
{
    ldns_status statuscode;
    int statusflag;
    int i;
    signconf->keylist = ldns_key_list_new();
    for(i=0; i<signconf->nkeys; i++) {
        signconf->keys[i].fp = fopen(signconf->keys[i].filename,"r");
        assert(signconf->keys[i].fp);
        statuscode = ldns_key_new_frm_fp(&(signconf->keys[i].key), signconf->keys[i].fp);
        statusflag = ldns_key_list_push_key(signconf->keylist, signconf->keys[i].key);
        signconf->keys[i].keyrecord = ldns_key2rr(signconf->keys[i].key);
        assert(signconf->keys[i].keyrecord);
        signconf->keys[i].dsrecord = NULL;
        //signconf->keys[i].dsrecord = ldns_key_rr2ds(signconf->keys[i].keyrecord, LDNS_SHA256);
    }
}

void
teardownsignconf(struct signconf* signconf)
{
    int i;
    for(i=0; i<signconf->nkeys; i++) {
        if(signconf->keys[i].dsrecord) {
            ldns_rr_free(signconf->keys[i].dsrecord);
            signconf->keys[i].dsrecord = 0;
        }
        if(signconf->keys[i].keyrecord) {
            ldns_rr_free(signconf->keys[i].keyrecord);
            signconf->keys[i].keyrecord = 0;
        }
        //if(signconf->keys[i].key) {
        //    ldns_key_deep_free(signconf->keys[i].key);
        //    signconf->keys[i].key = 0;
        //}
        if(signconf->keys[i].fp) {
            fclose(signconf->keys[i].fp);
            signconf->keys[i].fp = 0;
        }
    }
    //while(ldns_key_list_pop_key(signconf->keylist))  ;
    ldns_key_list_free(signconf->keylist);
}

void
signrecord(struct signconf* signconf, dictionary record)
{
    names_iterator typeiter;
    names_iterator dataiter;
    char* type;
    char* data;
    ldns_rdf* datardf;
    ldns_rr_type rrtype;
    ldns_rr* rr;
    ldns_rr_list* rrset;
    ldns_rr_list* rrsignatures;
    char** signatures;
    int nsignatures, signaturesidx;
    for(typeiter = names_recordalltypes(record); names_iterate(&typeiter, &type); names_advance(&typeiter, NULL)) {
        rrset = ldns_rr_list_new();
        rrtype = ldns_get_rr_type_by_name(type);
        for(dataiter = names_recordalltypes(record); names_iterate(&dataiter, &data); names_advance(&dataiter, NULL)) {
            rr = ldns_rr_new_frm_type(rrtype);
            datardf = ldns_rdf_new_frm_str(rrtype, data);
            ldns_rr_set_rdf(rr, datardf, 0); //FIXME other r fields, ttl, origin, class
            ldns_rr_list_push_rr(rrset, rr);
        }
        rrsignatures = ldns_sign_public(rrset, signconf->keylist);
        nsignatures = ldns_rr_list_rr_count(rrsignatures);
        signatures = malloc(sizeof(char*)*nsignatures);
        signaturesidx = 0;
        while((rr = ldns_rr_list_pop_rr(rrsignatures))) {
            signatures[signaturesidx++] = ldns_rdf2str(ldns_rr_rdf(rr,0));
            ldns_rr_free(rr);
        }
        ldns_rr_list_deep_free(rrset);
        ldns_rr_list_deep_free(rrsignatures);
        // FIXME names_recordsetsignatures(record, signatures);
        free(signatures);
    }
}

void
sign(names_view_type view)
{
    dictionary domain;
    names_iterator iter;
    struct signconf* signconf;
    
    signconf = createsignconf(1);
    signconf->keys[0].filename = strdup("Kexample.+008+24693.private");
    setupsignconf(signconf);
    for(iter=expiring(view); names_iterate(&iter,&domain); names_advance(&iter,NULL)) {
        signrecord(signconf, domain);
        // names_recordsetexpiry();
    }
    teardownsignconf(signconf);
    destroysignconf(signconf);
}

void
names_setup(void)
{
    const char* baseviewkeys[] = {"namerevision", NULL};
    const char* inputviewkeys[] = {"nameupcoming", NULL};
    const char* prepareviewkeys[] = {"namerevision", "namenoserial", "namenewserial", NULL};
    const char* signviewkeys[] = {"name", "expiry", "denialname", NULL};
    const char* outputviewkeys[] = {"validnow", NULL};

    names_view_type baseview;
    names_view_type inputview;
    names_view_type prepareview;
    names_view_type signview;
    names_view_type outputview;
    int basefd, status;
    char* apex = "example";

    basefd = open(".", O_PATH, 07777);

    baseview = names_viewcreate(NULL, baseviewkeys);
    mark("created base view");

    status = names_viewrestore(baseview, apex, basefd, "storage");
    mark("restored base view");

    inputview = names_viewcreate(baseview, inputviewkeys);
    prepareview = names_viewcreate(baseview, prepareviewkeys);
    signview = names_viewcreate(baseview, signviewkeys);
    outputview = names_viewcreate(baseview, outputviewkeys);
    mark("created other view");

    if(status) {
        apex = NULL;
        readzone(inputview, PLAIN, "example.zone", &apex, NULL);
        //readzone(inputview, PLAIN, "../se.zone", &apex, NULL);        
        mark("read zone");
        names_viewcommit(inputview);
names_dumpviewinfo(baseview,    "base    ");
names_dumpviewinfo(inputview,   "input   ");
names_dumpviewinfo(prepareview, "prepare ");
names_dumpviewinfo(signview,    "sign    ");
names_dumpviewinfo(outputview,  "output  ");
        mark("commit read");
    }

   
    names_viewreset(prepareview);
    prepare(prepareview, 2017101705);
    names_viewcommit(prepareview);
    names_viewreset(baseview);
    names_viewreset(outputview);
    writezone(outputview, "example.1", apex, NULL);

names_dumpviewinfo(baseview,    "base    ");
names_dumpviewinfo(inputview,   "input   ");
names_dumpviewinfo(prepareview, "prepare ");
names_dumpviewinfo(signview,    "sign    ");
names_dumpviewinfo(outputview,  "output  ");
        mark("prepared");

    apex = NULL;
    //readzone(inputview, DELTAMINUS, "se.delta", &apex, NULL);
    readzone(inputview, DELTAMINUS, "example.delta", &apex, NULL);
    mark("read delta");
    names_viewcommit(inputview);
names_dumpviewinfo(baseview,    "base    ");
names_dumpviewinfo(inputview,   "input   ");
names_dumpviewinfo(prepareview, "prepare ");
names_dumpviewinfo(signview,    "sign    ");
names_dumpviewinfo(outputview,  "output  ");
    mark("commit delta");

    names_viewreset(prepareview);
    prepare(prepareview, 2017101706);
    names_viewcommit(prepareview);
    names_viewreset(baseview);
    names_viewreset(outputview);
    writezone(outputview, "example.2", apex, NULL);
    
    names_viewreset(signview);
    sign(signview);

    names_viewpersist(baseview, basefd, "storage");
    mark("persist view");

    names_viewreset(baseview);
//names_dumpviewfull(stderr, baseview);
    mark("update base view");

    names_viewdestroy(inputview);
    names_viewdestroy(prepareview);
    names_viewdestroy(signview);
    names_viewdestroy(outputview);
    names_viewdestroy(baseview);

    close(basefd);
}
