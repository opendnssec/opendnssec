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
#include "uthash.h"
#include "proto.h"

#pragma GCC optimize ("O0")

void
writerecordcontent(recordset_type domainitem, FILE* fp)
{
    char* s;
    ldns_rr_type recordtype;
    names_iterator rrsetiter;
    names_iterator rriter;
    for (rrsetiter = names_recordalltypes(domainitem); names_iterate(&rrsetiter, &recordtype); names_advance(&rrsetiter, NULL)) {
        s = NULL;
        for (rriter = names_recordallvaluestrings(domainitem, recordtype); names_iterate(&rriter, &s); names_advance(&rriter, NULL)) {
            if (recordtype != LDNS_RR_TYPE_SOA) {
                fprintf(fp, "%s", s);
            }
        }
    }
    s = NULL;
    for (rriter = names_recordallvaluestrings(domainitem, LDNS_RR_TYPE_NSEC); names_iterate(&rriter, &s); names_advance(&rriter, NULL)) {
        fprintf(fp, "%s", s);
    }    
}

void
writezonecontent(names_view_type view, FILE* fp)
{
    int first;
    char* s;
    ldns_rr_type recordtype;
    names_iterator domainiter;
    names_iterator rrsetiter;
    names_iterator rriter;
    recordset_type domainitem;
    for (domainiter = names_viewiterator(view, NULL); names_iterate(&domainiter, &domainitem); names_advance(&domainiter, NULL)) {
        // FIXME we should/could use writerecordcontent method here
        for (rrsetiter = names_recordalltypes(domainitem); names_iterate(&rrsetiter, &recordtype); names_advance(&rrsetiter, NULL)) {
            s = NULL;
            first = 1;
            for (rriter = names_recordallvaluestrings(domainitem,recordtype); names_iterate(&rriter, &s); names_advance(&rriter, NULL)) {
                if(recordtype == LDNS_RR_TYPE_SOA && first) {
                    first = 0;
                    continue;
                }
                fprintf(fp, "%s", s);
            }
        }
        s = NULL;
        for (rriter = names_recordallvaluestrings(domainitem,LDNS_RR_TYPE_NSEC); names_iterate(&rriter, &s); names_advance(&rriter, NULL)) {
            fprintf(fp, "%s", s);
        }
    }
}

void
writezoneapex(names_view_type view, FILE* fp)
{
    ldns_rr* rr = NULL;
    recordset_type record;
    char* soa = NULL;
    record = names_take(view,0,NULL);
    if(record) {
        names_recordlookupone(record,LDNS_RR_TYPE_SOA,NULL,&rr);
        soa = ldns_rr2str(rr);
        fprintf(fp, "%s", soa);
        free(soa);
    }
}

int
writezone(names_view_type view, const char* filename)
{
    FILE* fp;
    int defaultttl = 0;
    ldns_rdf* origin = NULL;
    char* apex = NULL;

    fp = fopen(filename,"w");
    if (!fp) {
        fprintf(stderr,"unable to open file \"%s\"\n",filename);
    }

    names_viewgetapex(view, &origin);
    if (origin) {
        apex = ldns_rdf2str(origin);
        fprintf(fp, "$ORIGIN %s\n", apex);
        ldns_rdf_deep_free(origin);
    }
    if (names_viewgetdefaultttl(view, &defaultttl)) {
        fprintf(fp, "$TTL %d\n",defaultttl);
    }

    writezoneapex(view, fp);
    writezonecontent(view, fp);
    writezoneapex(view, fp);

    fclose(fp);
    if(apex)
        free(apex);
    return 0;
}
