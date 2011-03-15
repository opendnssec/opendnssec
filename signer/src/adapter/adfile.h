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
 * File Adapters.
 *
 */

#ifndef ADAPTER_ADFILE_H
#define ADAPTER_ADFILE_H

#include "config.h"
#include "shared/allocator.h"
#include "shared/status.h"

#include <stdio.h>

struct zone_struct;

/**
 * File adapter.
 *
 */
/** NULL */

/**
 * Initialize file adapters.
 * \return ods_status status
 *
 */
ods_status adfile_init(void);

/**
 * Read zone from input file adapter.
 * \param[in] zone zone structure
 * \param[in] filename read from this specific file
 * \return ods_status status
 *
 */
ods_status adfile_read(struct zone_struct* zone, const char* filename);

/**
 * Read zone from backup file.
 * \param[in] zone zone structure
 * \param[in] filename read from this specific file
 * \return ods_status status
 *
 */
ods_status adbackup_read(struct zone_struct* zone, const char* filename);

/**
 * Write zone to output file adapter.
 * \param[in] zone zone structure
 * \param[in] filename write to this specific file
 * \return ods_status status
 *
 */
ods_status adfile_write(struct zone_struct* zone, const char* filename);

#endif /* ADAPTER_ADFILE_H */
