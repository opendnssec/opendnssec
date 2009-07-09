/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

#ifndef KSM_DB_FIELDS_H
#define KSM_DB_FIELDS_H

#ifdef __cplusplus
extern "C" {
#endif

/*+
 * db_fields.h - KSM database Field Definitions
 *
 * Description:
 *      Gives the relative positions of fields with a table.
 *
 *      Each constant is of the form
 *
 *          DB_<table name>_<field name>
 *
 *      Also defined are:
 *
 *          DB_INVALID          A value that is always an invalid field value
 *          DB_<table>_NFIELD   Number of fields in the given table
-*/

/* Invalid field number */

#define DB_INVALID              -1

/* Keydata_view fields */

#define DB_KEYDATA_FIELDS       "id, state, generate, publish, ready, active, retire, dead, keytype, algorithm, location, zone_id"
#define DB_KEYDATA_ID            0
#define DB_KEYDATA_STATE         1
#define DB_KEYDATA_GENERATE      2
#define DB_KEYDATA_PUBLISH       3
#define DB_KEYDATA_READY         4
#define DB_KEYDATA_ACTIVE        5
#define DB_KEYDATA_RETIRE        6
#define DB_KEYDATA_DEAD          7
#define DB_KEYDATA_KEYTYPE       8
#define DB_KEYDATA_ALGORITHM     9
#define DB_KEYDATA_LOCATION     10
#define DB_KEYDATA_ZONE_ID      11

#define DB_KEYDATA_NFIELD       12

/* Parameter_view (and list) fields */

#define DB_PARAMETER_VIEW_FIELDS    "name, category, parameter_id, value, policy_id"
#define DB_PARAMETER_LIST_FIELDS    "name, category, parameter_id"
#define DB_PARAMETER_NAME        0
#define DB_PARAMETER_CATEGORY    1
#define DB_PARAMETER_ID          2
#define DB_PARAMETER_VALUE       3
#define DB_PARAMETER_POLICY_ID   4

#define DB_PARAMETER_VIEW_NFIELD      5
#define DB_PARAMETER_LIST_NFIELD      3

#define DB_POLICY_PARAMETER_NAME        0
#define DB_POLICY_PARAMETER_CATEGORY	1
#define DB_POLICY_PARAMETER_VALUE       2

#define DB_SECURITY_MODULE_TABLE	"securitymodules"
#define DB_SECURITY_MODULE_FIELDS	"id, name, capacity"
#define DB_SECURITY_MODULE_ID		0
#define DB_SECURITY_MODULE_NAME 	1
#define DB_SECURITY_MODULE_CAPACITY 2

#define DB_ZONE_TABLE			"zones"
#define DB_ZONE_FIELDS 			"id, name"
#define DB_ZONE_ID				0
#define DB_ZONE_NAME			1
#define DB_ZONE_POLICY_ID   	2

/* policy select variables, including salt */
#define DB_POLICY_ID	0
#define DB_POLICY_NAME	1
#define DB_POLICY_DESCRIPTION	2
#define DB_POLICY_SALT	1
#define DB_POLICY_SALT_STAMP	2


/* when selecting count(*) from ... */
#define DB_COUNT 0

#ifdef __cplusplus
};
#endif

#endif /* KSM_DB_FIELDS_H */
