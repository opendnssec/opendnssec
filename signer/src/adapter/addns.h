/*
 * $Id: addns.h 4958 2011-04-18 07:11:09Z matthijs $
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
 * DNS Adapters.
 *
 */

#ifndef ADAPTER_ADDNS_H
#define ADAPTER_ADDNS_H

#include "config.h"
#include "shared/allocator.h"
#include "shared/status.h"

#include <stdio.h>

struct zone_struct;

/**
 * Initialize DNS adapters.
 * \param[in] str configuration string
 * \return ods_status status
 *
 */
ods_status addns_init(const char* str);

/**
 * Read zone from input DNS adapter.
 * \param[in] zone zone structure
 * \param[in] str configuration string
 * \return ods_status status
 *
 */
ods_status addns_read(struct zone_struct* zone, const char* str);

/**
 * Write zone to output DNS adapter.
 * \param[in] zone zone structure
 * \param[in] str configuration string
 * \return ods_status status
 *
 */
ods_status addns_write(struct zone_struct* zone, const char* str);

#endif /* ADAPTER_ADDNS_H */
