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

#include "adapter/adapter.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/status.h"
#include "signer/zone.h"

#include <stdio.h>
#include <stdlib.h>

static const char* adapter_str = "adapter";


/**
 * Initialize adapter.
 *
 */
ods_status
adapter_init(const char* str, adapter_mode type, int inbound)
{
    switch(type) {
        case ADAPTER_FILE:
            return adfile_init();
            break;
        case ADAPTER_MYSQL:
            ods_log_error("[%s] unable to initialize MySQL adapter: "
                "notimpl yet", adapter_str);
            return ODS_STATUS_ERR;
            break;
        default:
            ods_log_error("[%s] unable to initialize adapter: "
                "unknown adapter", adapter_str);
            return ODS_STATUS_ERR;
            break;
    }

    /* not reached */
    return ODS_STATUS_ERR;
}


/**
 * Create a new adapter.
 *
 */
adapter_type*
adapter_create(const char* str, adapter_mode type, int inbound)
{
    allocator_type* allocator;
    adapter_type* adapter;

    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create adapter: create allocator failed",
            adapter_str);
        return NULL;
    }
    ods_log_assert(allocator);

    adapter = (adapter_type*) allocator_alloc(allocator, sizeof(adapter_type));
    if (!adapter) {
        ods_log_error("[%s] unable to create adapter: allocator failed",
            adapter_str);
        allocator_cleanup(allocator);
        return NULL;
    }

    adapter->allocator = allocator;
    adapter->configstr = allocator_strdup(allocator, str);
    adapter->type = type;
    adapter->inbound = inbound;
/*
    adapter->data = allocator_alloc(allocator, sizeof(adapter_data));
*/
    return adapter;
}


/*
 * Read zone from input adapter.
 *
 */
ods_status
adapter_read(struct zone_struct* zone)
{
    zone_type* adzone = (zone_type*) zone;
    ods_status status = ODS_STATUS_OK;

    if (!adzone || !adzone->adinbound) {
        ods_log_error("[%s] unable to read zone %s: no input adapter",
            adapter_str, adzone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone);
    ods_log_assert(adzone->adinbound);
    ods_log_assert(adzone->adinbound->configstr);

    switch(adzone->adinbound->type) {
        case ADAPTER_FILE:
            ods_log_verbose("[%s] read zone %s from input file %s",
                adapter_str, adzone->name, adzone->adinbound->configstr);
            status = adfile_read(zone, adzone->adinbound->configstr);
            return status;
            break;
        case ADAPTER_MYSQL:
            ods_log_error("[%s] unable to read zone %s from adapter: MySQL "
                "adapter notimpl yet", adapter_str, adzone->name);
            return ODS_STATUS_ERR;
            break;
        default:
            ods_log_error("[%s] unable to read zone %s from adapter: unknown "
                "adapter", adapter_str, adzone->name);
            return ODS_STATUS_ERR;
            break;
    }

    /* not reached */
    return ODS_STATUS_ERR;
}


/**
 * Write zone to output adapter.
 *
 */
ods_status
adapter_write(struct zone_struct* zone)
{
    zone_type* adzone = (zone_type*) zone;
    ods_status status = ODS_STATUS_OK;

    if (!adzone || !adzone->adoutbound) {
        ods_log_error("[%s] unable to write zone %s: no output adapter",
            adapter_str, adzone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone);
    ods_log_assert(adzone->adoutbound);
    ods_log_assert(adzone->adoutbound->configstr);
    if (!adzone->zonedata) {
        ods_log_error("[%s] unable to write zone %s: no zone data",
            adapter_str, adzone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone->zonedata);

    switch(adzone->adoutbound->type) {
        case ADAPTER_FILE:
            ods_log_verbose("[%s] write zone %s serial %u to output file %s",
                adapter_str, adzone->name, adzone->zonedata->outbound_serial,
                adzone->adinbound->configstr);
            status = adfile_write(zone, adzone->adoutbound->configstr);
            return status;
            break;
        case ADAPTER_MYSQL:
            ods_log_error("[%s] unable to write zone %s to adapter: MySQL "
                "adapter notimpl yet", adapter_str, adzone->name);
            return ODS_STATUS_ERR;
            break;
        default:
            ods_log_error("[%s] unable to write zone %s to adapter: unknown "
                "adapter", adapter_str, adzone->name);
            return ODS_STATUS_ERR;
            break;
    }

    /* NOT REACHED */
    return ODS_STATUS_ERR;
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
    } else if (a1->type != a2->type) {
        return a1->type - a2->type;
    } else {
        return ods_strcmp(a1->configstr, a2->configstr);
    }
    /* not reached */
    return 0;
}


/**
 * Clean up adapter.
 *
 */
void
adapter_cleanup(adapter_type* adapter)
{
    allocator_type* allocator;
    if (!adapter) {
        return;
    }
    allocator = adapter->allocator;
    allocator_deallocate(allocator);
    allocator_cleanup(allocator);
    return;
}
