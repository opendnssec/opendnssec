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
#include "uthash.h"
#include "utilities.h"
#include "logging.h"
#include "proto.h"

#pragma GCC optimize ("O0")

// number of ixfrs to keep

#define NUMBER_OF_IXFRS 4

void
purgezone(zone_type* zone)
{
    char* tmpname;
    recordset_type record;
    names_iterator iter;
    int serial = 4;
    names_view_type baseview = zone->baseview;

    names_viewreset(baseview);

    /* find any items that are no longer worth preserving because they are
     * outdated for too long (ie their last valid serial number is too far
     * in the past.
     */
    for(iter=names_viewiterator(baseview,names_iteratoroutdated,serial); names_iterate(&iter,&record); names_advance(&iter, NULL)) {
        names_remove(baseview, record);
    }
    if(names_viewcommit(baseview)) {
        abort(); // FIXME
    }

    /* Refresh the current state jounral file */
    struct stat statbuf;
    char* filename = ods_build_path(zone->name, ".state", 0, 1);
    if(fstatat(AT_FDCWD, filename, &statbuf, 0)) {
        if(errno == ENOENT) {
            names_viewpersist(baseview, AT_FDCWD, filename);
        } else {
            ods_log_error("unable to create state file for zone %s", zone->name);
        }
    }
    free(filename);

    /* Write the zone as it currently stands */
    names_view_type outputview = zone->outputview;
    names_viewreset(outputview);
    tmpname = ods_build_path(zone->adoutbound->configstr, ".tmp", 0, 0);
    if (!tmpname) {
        return ODS_STATUS_MALLOC_ERR;
    }
    if(writezone(outputview, tmpname)) {
        if (zone->adoutbound->error) {
            ods_log_error("unable to write zone %s file %s", zone->name, filename);
            zone->adoutbound->error = 0;
            // status = ODS_STATUS_FWRITE_ERR;
        }
    } else {
        if (rename((const char*) tmpname, zone->adoutbound->configstr) != 0) {
            ods_log_error("unable to write file: failed to rename %s to %s (%s)", tmpname, filename, strerror(errno));
            // status = ODS_STATUS_RENAME_ERR;
        }
    }
    free(tmpname);
}
