/*
 * $Id$
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 *
 */

/**
 * Inbound and Outbound Adapters.
 *
 */

#include "v2/adapter.h"
#include "v2/adfile.h"
#include "v2/zone.h"
#include "v2/se_malloc.h"

#include <stdio.h>

/**
 * Create a new adapter.
 *
 */
adapter_type*
adapter_create(const char* filename, int inbound)
{
    adapter_type* adapter = (adapter_type*) se_malloc(sizeof(adapter_type));
    adapter->filename = se_strdup(filename);
    adapter->inbound = inbound;
    return adapter;
}


/**
 * Clean up adapter.
 *
 */
void
adapter_cleanup(adapter_type* adapter)
{
    if (adapter) {
        se_free((void*)adapter->filename);
        se_free((void*)adapter);
    }
}

/**
 * Compare adapters.
 *
 */
int
adapter_compare(adapter_type* a1, adapter_type* a2)
{
    if (!a1 && !a2) {
        return 0;
    } else if (!a1) {
        return -1;
    } else if (!a2) {
        return 1;
    } else if (a1->inbound != a2->inbound) {
        return a1->inbound - a2->inbound;
    }
    return strncmp(a1->filename, a2->filename, strlen(a1->filename));
}


/**
 * Read input file adapter.
 *
 */
int
adapter_read_file(struct zone_struct* zone)
{
    FILE* fd = NULL;
    zone_type* zone_in = zone;
    int error = 0;

    /* read the zonefile */
    fd = fopen(zone_in->inbound_adapter->filename, "r");
    if (fd) {
        error = adapter_file_read(fd, zone_in, 0);
        fclose(fd);
    } else {
        error = 1;
    }
    if (error) {
        fprintf(stderr, "error reading file adapter, zone '%s', zone file '%s'\n",
            zone_in->name, zone_in->inbound_adapter->filename);
        return error;
    }

    /* add empty non-terminals, determine glue */
    error = zone_entize(zone_in);
    if (error) {
        fprintf(stderr, "error adding empty non-terminals to zone '%s'\n",
            zone_in->name);
        return error;
    }

    return error;
}


/**
 * Write to input file adapter.
 *
 */
int
adapter_write_file(struct zone_struct* zone)
{
    FILE* fd = NULL;
    zone_type* zone_out = zone;
    int error = 0;

    fd = fopen(zone_out->outbound_adapter->filename, "w");
    if (fd) {
        error = adapter_file_write(fd, zone_out);
        fclose(fd);
    }
    return error;
}


/**
 * Print adapter.
 *
 */
void
adapter_print(FILE* fd, adapter_type* adapter)
{
    if (adapter) {
        fprintf(fd, "\t\t\t<%s>\n", adapter->inbound?"Input":"Output");
        fprintf(fd, "\t\t\t\t<File>%s</File>\n", adapter->filename);
        fprintf(fd, "\t\t\t</%s>\n", adapter->inbound?"Input":"Output");
    }
}
