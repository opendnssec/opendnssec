/*+
 * ksm_key_delete - Deletion of keys
 *
 * Description:
 *      Holds the functions needed to delete information from the KEYDATA
 *      table.
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "database.h"
#include "database_statement.h"
#include "kmedef.h"
#include "ksm.h"


/*+
 * KsmDeleteKeyRange - Delete Range of Keys
 *
 * Description:
 *      Deletes keys whose ID (the primary key of the table) lies between the
 *      given arguments.
 *
 * Arguments:
 *      int minid
 *          Minimum ID of the set of keys to be deleted.
 *
 *      int maxid
 *          Maximum ID of the keys to be deleted.  This can be equal to the
 *          minid.
 *
 *      Note, if minid > maxid, the values are silently swapped.
 *
 * Returns:
 *      int
 *          0       Success
 *          <>0     Error.  A message will have been output.
-*/

int KsmDeleteKeyRange(int minid, int maxid)
{
    char*   sql = NULL;     /* Constructed SQL deletion string */
    int     status;         /* Status return */
    int     temp;           /* For swapping inetegers */
    int     where = 0;      /* For constructing the delete statement */

    /* Ensure minimum and maximum are in the correct order */

    if (minid > maxid) {
        temp = minid;
        minid = maxid;
        maxid = temp;
    }

    /*
     * Create the deletion string.  Although we could have one code path, the
     * check for the minimum and maximum IDs the same lease to the (possible
     * more efficient) single condition check.
     *
     * Don't rely on cascading delete, so we need to go through this twice
     */

    /* First delete from dnsseckeys */
    sql = DdsInit("dnsseckeys");
    if (minid == maxid) {
        DdsConditionInt(&sql, "keypair_id", DQS_COMPARE_EQ, minid, where++);
    }
    else {
        DdsConditionInt(&sql, "keypair_id", DQS_COMPARE_GE, minid, where++);
        DdsConditionInt(&sql, "keypair_id", DQS_COMPARE_LE, maxid, where++);
    }
    DdsEnd(&sql);

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DdsFree(sql);

    /* Then delete from keypairs */
    where = 0;
    sql = DdsInit("keypairs");
    if (minid == maxid) {
        DdsConditionInt(&sql, "id", DQS_COMPARE_EQ, minid, where++);
    }
    else {
        DdsConditionInt(&sql, "id", DQS_COMPARE_GE, minid, where++);
        DdsConditionInt(&sql, "id", DQS_COMPARE_LE, maxid, where++);
    }
    DdsEnd(&sql);

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DdsFree(sql);

    return status;
}


/*+
 * KsmDeleteKeyRanges - Delete Ranges of Keys
 *
 * Description:
 *      Deletes a number of ranges of keys.
 *
 *      A range of keys is set by two numbers, the ID of the lowest key in the
 *      range, and the ID of the highest key.  This function allows the
 *      specification of multiple ranges.
 *
 * Arguments:
 *      int limit[]
 *          Array of ranges.  Each range is set by two consecurity elements in
 *          the array, i.e. elements 0 and 1 are one range, 2 and 3 another.
 *
 *      int size
 *          Size of the array.  This must be even.
 *
 * Returns:
 *      int
 *          0       Success
 *          <>0     Error.  A message will have been output.  In this case,
 *                  not all of the ranges may have been deleted.
-*/

int KsmDeleteKeyRanges(int limit[], int size)
{
    int     i;              /* Loop counter */
    int     status = 0;     /* Status return */

    assert((size % 2) == 0);

    for (i = 0; ((i < size) && (status == 0)); i+= 2) {
        status = KsmDeleteKeyRange(limit[i], limit[i + 1]);
    }

    return status;
}
