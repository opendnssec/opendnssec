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

/*+
 * ksm_purge.c - Purge Dead Keys
 *
 * Description:
 *      Holds all the functions needed to implement the "purge" command.
-*/

#include "ksm/database.h"
#include "ksm/database_statement.h"
#include "ksm/db_fields.h"
#include "ksm/kmedef.h"
#include "ksm/ksm.h"


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
    char*   sql3 = NULL;
    DB_RESULT	result;         /* Result of parameter query */
    int     where = 0;
    int     keypair_id;
	DB_ROW		row = NULL;		/* Row object */
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

                /* Delete the row from keypairs */
                sql3 = DdsInit("keypairs");
                DdsConditionInt(&sql3, "ID", DQS_COMPARE_EQ, keypair_id, 0);
                DdsEnd(&sql3);
                (void) DbExecuteSqlNoResult(DbHandle(), sql3);
                DdsFree(sql3);
            }

            status = DbFetchRow(result, &row);
        }
    }
    DdsFree(sql);

    DbFreeRow(row);
    DbFreeResult(result);
    
    return;
}
