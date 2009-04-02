/*+
 * ksm_purge.c - Purge Dead Keys
 *
 * Description:
 *      Holds all the functions needed to implement the "purge" command.
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

#include "database.h"
#include "database_statement.h"
#include "db_fields.h"
#include "kmedef.h"
#include "ksm.h"


/*+
 * KsmPurge - Purge Dead Keys
 *
 * Description:
 *      Implements the code to execute the "purge" command, which removes
 *      dead keys from the database.
 *
 * Arguments:
 *      None.
-*/

void KsmPurge(void)
{
    char*   sql = NULL;
    char*   sql2 = NULL;
    DB_RESULT	result;         /* Result of parameter query */
    int     where = 0;
    int     keypair_id;
	DB_ROW		row;		/* Row object */
    int status = 0;

    /* Construct the SQL; don't rely on cascading delete */
    /* select ids of keys in dead state */
    sql = DqsSpecifyInit("KEYDATA_VIEW", DB_KEYDATA_FIELDS);
    DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, KSM_STATE_DEAD, where++);
	DqsEnd(&sql);
    
    /* delete rows in dnsseckeys which match */
    status = DbExecuteSql(DbHandle(), sql, &result);
    if (status == 0) {
        status = DbFetchRow(result, &row);
        while (status == 0) {
            status = DbInt(row, DB_KEYDATA_ID, &keypair_id);
            if (status == 0) {
                /* delete all entries in dnsseckeys that match */
                where = 0;
                sql2 = DdsInit("dnsseckeys");
                DdsConditionInt(&sql2, "keypair_id", DQS_COMPARE_EQ, keypair_id, where++);
                DdsEnd(&sql2);
                (void) DbExecuteSqlNoResult(DbHandle(), sql2);
                DdsFree(sql2);
            }

            status = DbFetchRow(result, &row);
        }
    }
    DdsFree(sql);

    /* Finally, delete the rows from keypairs */
    where = 0;
    sql = DdsInit("keypairs");
    DdsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, KSM_STATE_DEAD, where++);
    DdsEnd(&sql);
    
    /*
     * Just execute the appropriate SQL.  Ignore the status return as we don't
     * need to pass anything back to the caller, and if there is an error, any
     * message will have been output.
     */

    (void) DbExecuteSqlNoResult(DbHandle(), sql);
    DdsFree(sql);
    DbFreeRow(row);

    return;
}
