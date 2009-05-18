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
 * database_access - database Access Functions
 *
 * Description:
 *      Holds miscellaneous utility functions associated with the MySql
 *      database.
 *
 *      This particular file holds encapsulations of the underlying access
 *      functions - querying/modifying the database and retrieving results.
-*/

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "mysql.h"

#include "ksm/dbsdef.h"
#include "ksm/database.h"
#include "ksm/debug.h"
#include "ksm/memory.h"
#include "ksm/message.h"
#include "ksm/string_util.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))


/*+
 * DbExecuteSqlStatement - Execute SQL Statement
 *
 * Description:
 *      A wrapper round mysql_query that outputs the query being executed
 *      if the appropriate debug flag is set.
 *
 * Arguments:
 *      DB_HANDLE handle
 *          Handle to the currently opened database.
 *
 *      const char* stmt_str
 *          SQL statement to execute.
 *
 * Returns:
 *      int
 *          Any return value from mysql_query.
-*/

static int DbExecuteSqlStatement(DB_HANDLE handle, const char* stmt_str)
{
    DbgOutput(DBG_M_SQL, "%s\n", stmt_str);
    return mysql_query((MYSQL*) handle, stmt_str);
}



/*+
 * DbExecuteSql - Execute SQL Statement
 *
 * Description:
 *      Executes the given SQL statement and returns the results (if any).
 *
 * Arguments:
 *      DB_HANDLE handle
 *          Handle to the currently opened database.
 *
 *      const char* stmt_str
 *          Statement to execute.
 *
 *      DB_RESULT* result
 *          Pointer to the result set is put here.  It must be freed by
 *          DbFreeResult().  This is NULL if no data is returned; on error, the
 *          value is undefined.
 *
 * Returns:
 * 		int
 * 			0		Success
 * 			Other	Error code.  A message will have been output.
-*/

int DbExecuteSql(DB_HANDLE handle, const char* stmt_str, DB_RESULT* result)
{
    const char* errmsg = NULL;  /* Error message from MySql on failure */
    int         status = 0;     /* Status return */

	/* Argument check */

	if ((!handle) || (!stmt_str) || (*stmt_str == '\0') || (! result)) {
		status = MsgLog(DBS_INVARG, "DbExecuteSql");
		return status;
	}

	/* Allocate the result structure */

    *result = (DB_RESULT) MemCalloc(1, sizeof(struct db_result));
	(*result)->magic = DB_RESULT_MAGIC;
	(*result)->handle = handle;

    /* Execute statement */

    status = DbExecuteSqlStatement(handle, stmt_str);
    if (status == 0) {

        /* Get the pointer to the result set */

        (*result)->data = mysql_store_result((MYSQL*) handle);
        if ((*result)->data == NULL) {

            /*
             * No result set, so could be some error.  See if this is the case
             * by checking if there is error text.  If not, there are no results
			 * from the SQL - it could have been a statement such as DELETE or
			 * INSERT.
             */

            errmsg = DbErrmsg(handle);
            if (errmsg && *errmsg) {

				/* Error text, so error occurred.  Output message & tidy up */

                status = MsgLog(DBS_SQLFAIL, errmsg);
            }
			/*
			 * else {
			 *
			 * 		No error, so we just don't have any results.
			 * }
			 */

			/*
			 * Regardless of what heppened, there is no result set, so free up
			 * allocated memory.
			 */

			MemFree(*result);
			*result = NULL;
        }
        else {

			/*
			 * Success. "result" holds the result set.  Store the number of
			 * fields along with the length of each one for possible later use.
			 */

			(*result)->count = mysql_field_count((MYSQL*) (*result)->handle);
		}
    }
    else {

        /* Query failed.  Log the error and free up the structure */

        status = MsgLog(DBS_SQLFAIL, DbErrmsg(handle));
		MemFree(*result);
		*result = NULL;
    }

    return status;
}



/*+
 * DbRowCount - Return Count of Rows
 *
 * Description:
 * 		Returns the number of rows in the result set.
 *
 * Arguments:
 * 		None.
 *
 * Returns:
 * 		int
 * 			Number of rows.  This is 0 on error or if the query did not return
 * 			any rows.  Note that on error, a message will have been output.
-*/
/*
int DbRowCount(DB_RESULT result)
{
	int rowcount = 0;

	if (result && (result->magic == DB_RESULT_MAGIC)) {
		rowcount = (int) mysql_num_rows(result->data);
	}
	else {
		(void) MsgLog(DBS_INVARG, "DbRowCount");
	}

	return rowcount;
}
*/


/*+
 * DbFreeResult - Free Result
 *
 * Description:
 *      Frees up resources allocated for the result by DbExecuteSql.
 *
 * Arguments:
 *      DB_RESULT result
 *          Handle to the query result. May be NULL, in which case this
 *          function is a no-op.
 *
 *          If invalid, an error message will be output.
-*/

void DbFreeResult(DB_RESULT result)
{
    if (result) {
		if (result->magic == DB_RESULT_MAGIC) {

			/* Free up data */

			mysql_free_result((MYSQL_RES*) result->data);
			MemFree(result);
		}
		else {

			/* Invalid structure - output a warning but do nothing */

			(void) MsgLog(DBS_INVARG, "DbFreeResult");
		}
    }

    return;
}



/*+
 * DbFetchRow - Fetch Row from Result
 *
 * Description:
 * 		Fetches the next row from the result set.  The structure returned
 * 		*must* be freed by DbFreeRow() after use.
 *
 * Arguments:
 * 		DB_RESULT result
 * 			The result handle returned by the call to DbExecuteSql.
 *
 * 		DB_ROW* row
 * 			The row object is put here.  It will be NULL end of file; on error,
 * 			it is undefined.
 *
 * Returns:
 * 		int
 * 			0		Success, row information returned
 * 			-1		Success, no more rows for this result
 * 			Other	Error code or error number from DbErrno().
-*/

int DbFetchRow(DB_RESULT result, DB_ROW* row)
{
	int			status = 0;			/* Status return */
	MYSQL_ROW	rowdata;		/* Fetched row information */

	if (result && (result->magic == DB_RESULT_MAGIC) && row) {

		/* There is a result structure (and row pointer), do something */

		rowdata = mysql_fetch_row(result->data);
		if (rowdata) {

			/* Something returned, encapsulate the result in a structure */
		
			*row = (DB_ROW) MemCalloc(1, sizeof(struct db_row));
			(*row)->magic = DB_ROW_MAGIC;
			(*row)->result = result;
			(*row)->data = rowdata;
		}
		else {

			/*
			 * End of file - in this implementation, only mysql_store_result is
			 * used, so mysql_fetch_row returns NULL only on end of file.
			 */

			*row = NULL;
			status = -1;
		}
	}
	else {
		status = MsgLog(DBS_INVARG, "DbFetchRow");
	}

	return status;
}



/*+
 * DbFreeRow - Free Row
 *
 * Description:
 *      Frees up resources allocated for the row.
 *
 * Arguments:
 *      DB_RESULT result
 *          Handle to the query result. May be NULL, in which case this
 *          function is a no-op.
-*/

void DbFreeRow(DB_ROW row)
{
    if (row) {
		if (row->magic == DB_ROW_MAGIC) {
			MemFree(row);
		}
		else {

			/* Output warning, but otherwise do nothing */

			(void) MsgLog(DBS_INVARG, "DbFreeRow");
		}
    }

    return;
}



/*+
 * DbString - Return String Value
 *
 * Description:
 *      Returns string value from the current row.
 *
 * Arguments:
 *      DB_ROW row
 *          Pointer to the row object.
 *
 *      int field_index
 *          Index of the value required.
 *
 *      char** result
 *          Value of the field.  It is up to the caller to free it with
 *          a call to DbStringFree().  Note that this can be NULL if the
 *          corresponding field is NULL.
 *
 * Returns:
 *      int
 *      	0		Success
 *      	Other	Some error.  A message will have been output
-*/

int DbString(DB_ROW row, int field_index, char** result)
{
	int				status = 0;			/* Status return */
	unsigned long	*lengths;			/* Lengths of columns in each row */

	/* Check arguments */

	if (row && (row->magic == DB_ROW_MAGIC) && result) {

		/* Is the index requested valid? */

		if ((field_index >= 0) && (field_index < row->result->count)) {

			/* Get the lengths of the fields in the row */

			lengths = mysql_fetch_lengths((MYSQL_RES*) row->result->data);

			/* Get string into null-terminated form */

			if (row->data[field_index] != NULL) {
                /* TODO replece the below with strdup or StrStrdup ? */
				*result = MemMalloc(lengths[field_index] + 1);
				memcpy(*result, row->data[field_index], lengths[field_index]);
				(*result)[lengths[field_index]] = 0;
			}
			else {
				*result = NULL;
			}
		}
		else {

			/* Invalid field, tell the user */

			status = MsgLog(DBS_INVINDEX, field_index, row->result->count);
		}

	}
	else {

		/* Problem with the command arguments */

		status = MsgLog(DBS_INVARG, "DbString");
	}

    return status;

}


/*+
 * DbStringFree - Free String Returned by DbString
 *
 * Description:
 *      Frees the pointer-to string.
 *
 * Arguments:
 *      char* string
 *          String allocated by DbString.  On exit, this pointer is invalid.
-*/

void DbStringFree(char* string)
{
    MemFree(string);
}

/*+
 * DbBeginTransaction - Start a (non-nested) transaction
 *
 * Description:
 *              NB the following will not work if your tables are MyISAM
 *              as transactions are not supported
 *
 * Arguments:
 *              NONE
-*/

int DbBeginTransaction(void)
{
    const char* sql = "start transaction";
    return DbExecuteSqlNoResult(DbHandle(), sql);
}

/*+
 * DbCommit - End a (non-nested) transaction by commiting it
 *
 * Description:
 *      
 *
 * Arguments:
 *              NONE
-*/

int DbCommit(void)
{
    const char* sql = "commit";
    return DbExecuteSqlNoResult(DbHandle(), sql);
}

/*+
 * DbRollback - End a (non-nested) transaction by rolling it back
 *
 * Description:
 *      
 *
 * Arguments:
 *              NONE
-*/

int DbRollback(void)
{
    const char* sql = "rollback";
    return DbExecuteSqlNoResult(DbHandle(), sql);
}
