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

#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include "config.h"

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

int
readzone(names_view_type view, enum operation_enum operation, const char* filename, char** apexptr, int* defaultttlptr)
{
    char* s;
    char* recordname;
    ldns_rr_type recordtype;
    char* recorddata;
    char* recordtypestr;
    void* item;
    names_iterator domainiter;
    names_iterator rrsetiter;
    names_iterator rriter;
    dictionary domainitem;
    int linenum;
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
        for (domainiter = names_viewiterator(view, NULL); names_iterate(&domainiter, &domainitem); names_advance(&domainiter, NULL)) {
            for (rrsetiter = names_recordalltypes(domainitem); names_iterate(&rrsetiter, &recordtype); names_advance(&rrsetiter, NULL)) {
                for (rriter = names_recordallvalueidents(domainitem,recordtype); names_iterate(&rriter, &s); names_advance(&rriter, NULL)) {
                    removal = strdup(s);
                    removal->record = domainitem;
                    HASH_ADD_OPAQUE(removals, key, removal, strlen(removal->key));
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
            switch (operation) {
                case PLAIN:
                    record = names_place(view, recordname);
                    if (!names_recordhasdata(record,recordtype,rr,1)) {
                        names_own(view, &record);
                        rrset_add_rr(record, rr);
                    } else {
                        s = NULL;
                        recorddata = names_rr2data(rr, 0);
                        recordtypestr = ldns_rr_type2str(recordtype);
                        composestring2(&s, recordname, recordtypestr, recorddata, NULL);
                        free(recordtypestr);
                        HASH_FIND_OPAQUE(removals, s, strlen(s), removal);
                        free(recorddata);
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
            recorddata = &recordname[strlen(&recordname[strlen(recordname) + 1]) + 1];
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
