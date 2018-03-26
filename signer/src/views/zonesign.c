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

void
prepare(names_view_type view, int newserial)
{
    dictionary record;
    struct dual changex;
    struct dual* change;
        change = &changex;
    names_iterator iter;
    for (iter=neighbors(view); names_iterate(&iter,&changex); names_advance(&iter,NULL)) {
        assert(change->src != change->dst);
        record = change->dst;
        if(names_recordhasexpiry(record)) {
            names_recordsetvalidupto(record, newserial);
            names_own(view, &record);
            names_recordsetvalidfrom(record, newserial);
        }
    }
    for (iter=noexpiry(view); names_iterate(&iter,&changex); names_advance(&iter,NULL)) {
        assert(change->src != change->dst);
        if(change->src && !names_recordhasvalidupto(change->src)) {
            names_amend(view, change->src);
            names_recordsetvalidupto(change->src, newserial);
        }
        if(!names_recordhasvalidfrom(change->dst)) {
            if(names_recordhasdata(change->dst, 0, NULL, NULL)) {
                names_amend(view, change->dst);
                names_recordsetvalidfrom(change->dst, newserial);
            } else {
                names_remove(view, change->dst);
            }
        }
    }
}

void
sign(names_view_type view, const char* apex)
{
    dictionary domain;
    names_iterator iter;
    struct signconf* signconf;

    signconf = createsignconf(1);
    locatekeysignconf(signconf, 0, "Kexample.+008+24693.private", 0);
    setupsignconf(signconf);
    for(iter=expiring(view); names_iterate(&iter,&domain); names_advance(&iter,NULL)) {
        names_amend(view, domain);
        signrecord(signconf, domain, apex);
        names_recordsetexpiry(domain, 1);
    }
    teardownsignconf(signconf);
    destroysignconf(signconf);
}
