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
#include "utilities.h"
#include "signer/zone.h"

#pragma GCC optimize ("O0")

const char* baseviewkeys[] = { "namerevision", NULL};
const char* inputviewkeys[] = { "nameupcoming", "namehierarchy", NULL};
const char* prepareviewkeys[] = { "namerevision", "namenoserial", "namenewserial", NULL};
const char* signviewkeys[] = { "nameready", "expiry", "denialname", NULL};
const char* outputviewkeys[] = { "validnow", NULL};

int
names_docreate(zone_type* zone, const char* persist)
{
    int status = 0;

    zone->baseview = names_viewcreate(NULL, "  base    ", baseviewkeys);
    status = names_viewrestore(zone->baseview, zone->apex, -1, persist);
    zone->inputview = names_viewcreate(zone->baseview,   "  input   ", inputviewkeys);
    zone->prepareview = names_viewcreate(zone->baseview, "  prepare ", prepareviewkeys);
    zone->signview = names_viewcreate(zone->baseview,    "  sign    ", signviewkeys);
    zone->outputview = names_viewcreate(zone->baseview,  "  output  ", outputviewkeys);

    zone->persistviews = strdup(persist);

    return 0;
}

void
names_dodestroy(zone_type* zone)
{
    names_viewreset(zone->baseview);
    names_viewpersist(zone->baseview, -1, zone->persistviews);

    names_viewdestroy(zone->inputview);
    names_viewdestroy(zone->prepareview);
    names_viewdestroy(zone->signview);
    names_viewdestroy(zone->outputview);
    names_viewdestroy(zone->baseview);
}

void
names_docycle(zone_type* zone, int* serial, const char* filename)
{
    if(serial) {
        names_viewreset(zone->prepareview);
        prepare(zone->prepareview, *serial);
        if (names_viewcommit(zone->prepareview)) {
            abort();
        }
        names_viewreset(zone->signview);
        sign(zone->signview, zone->apex);
        if (names_viewcommit(zone->signview)) {
            abort();
        }
    }
    if(filename) {
        names_viewreset(zone->outputview);
        writezone(zone->outputview, filename, zone->apex, NULL);
    }
}

void
names_dopersist(zone_type* zone)
{
    names_viewreset(zone->baseview);
    names_viewpersist(zone->baseview, -1, zone->persistviews);
}
