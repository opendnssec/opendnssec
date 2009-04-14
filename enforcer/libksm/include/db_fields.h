#ifndef DB_FIELDS_H
#define DB_FIELDS_H

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
 *
 *
 * Copyright:
 *      Copyright 2008 Nominet
 *      
 * Licence:
 *      Licensed under the Apache Licence, Version 2.0 (the "Licence");
 *      you may not use this file except in compliance with the Licence.
 *      You may obtain a copy of the Licence at
 *      
 *          http://www.apache.org/licenses/LICENSE-2.0
 *      
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the Licence is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the Licence for the specific language governing permissions and
 *      limitations under the Licence.
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
#define DB_SECURITY_MODULE_FIELDS	"id, name, location, capacity, pin"
#define DB_SECURITY_MODULE_ID		0
#define DB_SECURITY_MODULE_NAME 	1
#define DB_SECURITY_MODULE_LOCATION 2
#define DB_SECURITY_MODULE_CAPACITY 3
#define DB_SECURITY_MODULE_PIN		4

#define DB_ZONE_TABLE_RAW       "zones z"
#define DB_ZONE_TABLE			"zones z, adapters i, adapters o"
#define DB_ZONE_FIELDS 			"z.id, z.name, i.name, o.name"
#define DB_ZONE_ID				0
#define DB_ZONE_NAME			1
#define DB_ZONE_IADAPTER		2
#define DB_ZONE_OADAPTER		3

/* policy select variables, including salt */
#define DB_POLICY_ID	0
#define DB_POLICY_NAME	1
#define DB_POLICY_SALT	1
#define DB_POLICY_SALT_STAMP	2


/* when selecting count(*) from ... */
#define DB_COUNT 0

#ifdef __cplusplus
};
#endif

#endif
