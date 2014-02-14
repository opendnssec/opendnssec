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
 * Create a new adapter.
 *
 */
adapter_type*
adapter_create(const char* str, adapter_mode type, unsigned in)
{
    adapter_type* adapter = NULL;
    allocator_type* allocator = NULL;
    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create adapter: allocator_create() "
            "failed", adapter_str);
        return NULL;
    }
    adapter = (adapter_type*) allocator_alloc(allocator, sizeof(adapter_type));
    if (!adapter) {
        ods_log_error("[%s] unable to create adapter: allocator_alloc() "
            "failed", adapter_str);
        allocator_cleanup(allocator);
        return NULL;
    }
    adapter->allocator = allocator;
    adapter->type = type;
    adapter->inbound = in;
    adapter->error = 0;
    adapter->config = NULL;
    adapter->config_last_modified = 0;
    adapter->configstr = allocator_strdup(allocator, str);
    if (!adapter->configstr) {
        ods_log_error("[%s] unable to create adapter: allocator_strdup() "
            "failed", adapter_str);
        adapter_cleanup(adapter);
        return NULL;
    }
    /* type specific */
    switch(adapter->type) {
        case ADAPTER_FILE:
            break;
        case ADAPTER_DNS:
            if (adapter->inbound) {
                adapter->config = (void*) dnsin_create();
                if (!adapter->config) {
                    ods_log_error("[%s] unable to create adapter: "
                        "dnsin_create() failed", adapter_str);
                    adapter_cleanup(adapter);
                    return NULL;
                }
            } else {
                adapter->config = (void*) dnsout_create();
                if (!adapter->config) {
                    ods_log_error("[%s] unable to create adapter: "
                        "dnsout_create() failed", adapter_str);
                    adapter_cleanup(adapter);
                    return NULL;
                }
            }
            break;
        default:
            break;
    }
    return adapter;
}


/**
 * Load ACL.
 *
 */
ods_status
adapter_load_config(adapter_type* adapter)
{
    dnsin_type* dnsin = NULL;
    dnsout_type* dnsout = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!adapter || !adapter->configstr) {
        return ODS_STATUS_ASSERT_ERR;
    }
    /* type specific */
    switch(adapter->type) {
        case ADAPTER_FILE:
            break;
        case ADAPTER_DNS:
            ods_log_assert(adapter->config);
            if (adapter->inbound) {
                status = dnsin_update(&dnsin, adapter->configstr,
                    &adapter->config_last_modified);
                if (status == ODS_STATUS_OK) {
                    ods_log_assert(dnsin);
                    dnsin_cleanup((dnsin_type*) adapter->config);
                    adapter->config = (void*) dnsin;
                } else if (status != ODS_STATUS_UNCHANGED) {
                    return status;
                }
                return ODS_STATUS_OK;
            } else { /* outbound */
                status = dnsout_update(&dnsout, adapter->configstr,
                    &adapter->config_last_modified);
                if (status == ODS_STATUS_OK) {
                    ods_log_assert(dnsout);
                    dnsout_cleanup((dnsout_type*) adapter->config);
                    adapter->config = (void*) dnsout;
                } else if (status != ODS_STATUS_UNCHANGED) {
                    return status;
                }
            }
            break;
        default:
            break;
    }
    return ODS_STATUS_OK;
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
    switch (adzone->adinbound->type) {
        case ADAPTER_FILE:
            ods_log_verbose("[%s] read zone %s from file input adapter %s",
                adapter_str, adzone->name, adzone->adinbound->configstr);
            return adfile_read(zone);
            break;
        case ADAPTER_DNS:
            ods_log_verbose("[%s] read zone %s from dns input adapter %s",
                adapter_str, adzone->name, adzone->adinbound->configstr);
            return addns_read(zone);
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
    if (!adzone || !adzone->db || !adzone->adoutbound) {
        ods_log_error("[%s] unable to write zone: no output adapter",
            adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone->name);
    ods_log_assert(adzone->adoutbound->configstr);

    switch(adzone->adoutbound->type) {
        case ADAPTER_FILE:
            ods_log_verbose("[%s] write zone %s serial %u to output file "
                "adapter %s", adapter_str, adzone->name,
                adzone->db->intserial, adzone->adoutbound->configstr);
            return adfile_write(zone, adzone->adoutbound->configstr);
            break;
        case ADAPTER_DNS:
            return addns_write(zone);
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
    allocator_type* allocator = NULL;
    if (!adapter) {
        return;
    }
    allocator = adapter->allocator;
    allocator_deallocate(allocator, (void*) adapter->configstr);
    switch(adapter->type) {
        case ADAPTER_FILE:
            break;
        case ADAPTER_DNS:
            if (adapter->inbound) {
                dnsin_cleanup((dnsin_type*) adapter->config);
            } else { /* outbound */
                dnsout_cleanup((dnsout_type*) adapter->config);
            }
            break;
        default:
            break;
    }
    allocator_deallocate(allocator, (void*) adapter);
    allocator_cleanup(allocator);
    return;
}
