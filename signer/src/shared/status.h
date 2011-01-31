/*
 * $Id$
 *
 * Copyright (c) 2010-2011 NLNet Labs. All rights reserved.
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
 *
 * Status.
 */

#ifndef UTIL_STATUS_H
#define UTIL_STATUS_H

#include "config.h"

enum ods_enum_status {
    ODS_STATUS_OK,
    ODS_STATUS_ASSERT_ERR,
    ODS_STATUS_CFG_ERR,
    ODS_STATUS_CHDIR_ERR,
    ODS_STATUS_CHROOT_ERR,
    ODS_STATUS_CMDHANDLER_ERR,
    ODS_STATUS_CONFLICT_ERR,
    ODS_STATUS_ERR,
    ODS_STATUS_FOPEN_ERR,
    ODS_STATUS_FORK_ERR,
    ODS_STATUS_HSM_ERR,
    ODS_STATUS_INSECURE,
    ODS_STATUS_MALLOC_ERR,
    ODS_STATUS_PARSE_ERR,
    ODS_STATUS_PRIVDROP_ERR,
    ODS_STATUS_RNG_ERR,
    ODS_STATUS_SETSID_ERR,
    ODS_STATUS_UNCHANGED,
    ODS_STATUS_WRITE_PIDFILE_ERR,
    ODS_STATUS_XML_ERR
};
typedef enum ods_enum_status ods_status;

typedef struct ods_struct_lookup_table ods_lookup_table;
struct ods_struct_lookup_table {
    int id;
    const char* name;
};

extern ods_lookup_table ods_status_str[];


/**
 * Look up item in table.
 * \param[in] table table
 * \param[in] id identifier
 *
 */
ods_lookup_table* ods_lookup_by_id(ods_lookup_table *table, int id);

/**
 * Look up a descriptive text by each status.
 * \param[in] status status identifierr
 * \return const char* corresponding descriptive text
 *
 */
const char *ods_status2str(ods_status status);

#endif /* UTIL_STATUS_H */
