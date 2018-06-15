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
writezonef(names_view_type view, FILE* fp)
{
    char* s;
    ldns_rr_type recordtype;
    names_iterator domainiter;
    names_iterator rrsetiter;
    names_iterator rriter;
    recordset_type domainitem;
    for (domainiter = names_viewiterator(view, NULL); names_iterate(&domainiter, &domainitem); names_advance(&domainiter, NULL)) {
        for (rrsetiter = names_recordalltypes(domainitem); names_iterate(&rrsetiter, &recordtype); names_advance(&rrsetiter, NULL)) {
            for (rriter = names_recordallvaluestrings(domainitem,recordtype); names_iterate(&rriter, &s); names_advance(&rriter, NULL)) {
                fprintf(fp, "%s", s);
            }
        }
        for (rriter = names_recordallvaluestrings(domainitem,LDNS_RR_TYPE_NSEC); names_iterate(&rriter, &s); names_advance(&rriter, NULL)) {
            fprintf(fp, "%s", s);
        }
    }
}

int
writezone(names_view_type view, const char* filename)
{
    char* s;
    FILE* fp;
    int defaultttl = 0;
    ldns_rdf* origin = NULL;

    fp = fopen(filename,"w");
    if(!fp) {
        fprintf(stderr,"unable to open file \"%s\"\n",filename);
    }

    names_viewgetapex(view, &origin);
    if(origin) {
        s = ldns_rdf2str(origin);
        fprintf(fp, "$ORIGIN %s\n", s);
        free(s);
        ldns_rdf_free(origin);
    }
    if(names_viewgetdefaultttl(view, &defaultttl))
        fprintf(fp, "$TTL %d\n",defaultttl);

    names_viewreset(view);
    writezonef(view, fp);

    fclose(fp);
    return 0;
}
