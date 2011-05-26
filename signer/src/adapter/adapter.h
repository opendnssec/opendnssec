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

#ifndef ADAPTER_ADAPTER_H
#define ADAPTER_ADAPTER_H

#include "config.h"
#include "adapter/adfile.h"
#include "adapter/addns.h"
#include "shared/status.h"

#include <stdio.h>

struct zone_struct;

/** Adapter mode. */
enum adapter_mode_enum
{
    ADAPTER_FILE = 1,
    ADAPTER_DNS
};
typedef enum adapter_mode_enum adapter_mode;

/** Adapter mode specific. */
union adapter_data_union
{
    void* file;
    void* dns;
};
typedef union adapter_data_union adapter_data;

/**
 * Adapter.
 *
 */
typedef struct adapter_struct adapter_type;
struct adapter_struct {
    const char* configstr;
    adapter_mode type;
    int inbound;
    allocator_type* allocator;
    adapter_data* data;
};

/**
 * Initialize adapter.
 * \param[in] adapter adapter
 * /return ods_status stats
 *
 */
ods_status adapter_init(adapter_type* adapter);

/**
 * Create new adapter.
 * \param[in] str configuration string
 * \param[in] type type of adapter
 * \param[in] inbound inbound or not (thus outbound)
 * \return adapter_type* created adapter
 *
 */
adapter_type* adapter_create(const char* str, adapter_mode type, int inbound);

/**
 * Compare adapters.
 * /param[in] a1 adapter 1
 * /param[in] a2 adapter 2
 * /return int 0 on equal, -1 if a1 < a2, 1 if a1 > a2
 *
 */
int adapter_compare(adapter_type* a1, adapter_type* a2);

/**
 * Read zone from input adapter.
 * /param[in] zone zone
 * /return ods_status stats
 *
 */
ods_status adapter_read(struct zone_struct* zone);

/**
 * Write zone to output adapter.
 * /param[in] zone zone
 * /return ods_status stats
 *
 */
ods_status adapter_write(struct zone_struct* zone);

/**
 * Clean up adapter.
 * \param[in] adapter adapter to cleanup
 *
 */
void adapter_cleanup(adapter_type* adapter);

#endif /* ADAPTER_ADAPTER_H */
