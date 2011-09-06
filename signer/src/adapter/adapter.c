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

#include <stdlib.h>

static const char* adapter_str = "adapter";


/**
 * Initialize adapter.
 *
 */
void
adapter_init(adapter_type* adapter)
{
    ods_log_assert(adapter);
    switch(adapter->type) {
        case ADAPTER_FILE:
            adfile_init(adapter);
            break;
        default:
            ods_log_error("[%s] unable to initialize adapter: "
                "unknown adapter", adapter_str);
            break;
    }
    return;
}


/**
 * Create a new adapter.
 *
 */
adapter_type*
adapter_create(const char* str, adapter_mode type, unsigned inbound)
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
    adapter->data = allocator_alloc(allocator, sizeof(adapter_data));
    return adapter;
}


/*
 * Read zone from input adapter.
 *
 */
ods_status
adapter_read(void* zone)
{
    zone_type* adzone = (zone_type*) zone;
    if (!adzone || !adzone->adinbound) {
        ods_log_error("[%s] unable to read zone: no input adapter",
            adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone->adinbound->configstr);
    switch(adzone->adinbound->type) {
        case ADAPTER_FILE:
            ods_log_verbose("[%s] read zone %s from file input adapter %s",
                adapter_str, adzone->name, adzone->adinbound->configstr);
            return adfile_read(zone, adzone->adinbound->configstr);
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
adapter_write(void* zone)
{
    zone_type* adzone = (zone_type*) zone;
    if (!adzone || !adzone->adoutbound) {
        ods_log_error("[%s] unable to write zone: no output adapter",
            adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone->adoutbound->configstr);
    if (!adzone->db) {
        ods_log_error("[%s] unable to write zone %s: no zone data",
            adapter_str, adzone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    switch(adzone->adoutbound->type) {
        case ADAPTER_FILE:
            ods_log_verbose("[%s] write zone %s serial %u to output file "
                "adapter %s", adapter_str, adzone->name,
                adzone->db->outserial, adzone->adinbound->configstr);
            return adfile_write(zone, adzone->adoutbound->configstr);
            break;
        default:
            ods_log_error("[%s] unable to write zone %s to adapter: unknown "
                "adapter", adapter_str, adzone->name);
            return ODS_STATUS_ERR;
            break;
    }
    /* not reached */
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
    }
    return ods_strcmp(a1->configstr, a2->configstr);
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
    allocator_deallocate(allocator, (void*) adapter->configstr);
    allocator_deallocate(allocator, (void*) adapter->data);
    allocator_deallocate(allocator, (void*) adapter);
    allocator_cleanup(allocator);
    return;
}
