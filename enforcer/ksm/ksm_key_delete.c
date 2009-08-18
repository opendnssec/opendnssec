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
 * ksm_key_delete - Deletion of keys
 *
 * Description:
 *      Holds the functions needed to delete information from the KEYDATA
 *      table.
-*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ksm/database.h"
#include "ksm/database_statement.h"
#include "ksm/kmedef.h"
#include "ksm/ksm.h"


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
