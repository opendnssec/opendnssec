/*
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
 * database_access_lite - database Access Functions
 *
 * Description:
 *      Holds miscellaneous utility functions associated with the sqlite
 *      database.
 *
 *      This particular file holds encapsulations of the underlying access
 *      functions - querying/modifying the database and retrieving results.
-*/

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

#include "ksm/dbsdef.h"
#include "ksm/database.h"
#include "ksm/debug.h"
#include "ksm/memory.h"
#include "ksm/message.h"
#include "ksm/string_util.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

/* possible wrapper for sqlite3_step which will wait for a block to go */
int sqlite3_my_step(sqlite3_stmt *pStmt)
{
	int rc;
    struct timeval tv;

    rc = sqlite3_step(pStmt);
    
    while (rc == SQLITE_LOCKED || rc == SQLITE_BUSY) {
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        select(0, NULL, NULL, NULL, &tv);

        rc = sqlite3_step(pStmt);
    }

    return rc;

}

/*+
 * DbExecuteSqlStatement - Execute SQL Statement
 *
 * Description:
 *      A wrapper round sqlite3_prepare_v2 and one call to sqlite3_step
 *      that outputs the query being executed if the appropriate debug flag 
 *      is set.
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
 *          Any return value from sqlite3_prepare_v2 or sqlite3_step.
 *          SQLITE_OK if the command executes correctly
-*/

static int DbExecuteSqlStatement(DB_HANDLE handle, const char* stmt_str, DB_RESULT* result)
{
	int rc;
    DbgOutput(DBG_M_SQL, "%s\n", stmt_str);
    rc = sqlite3_prepare_v2((sqlite3*) handle, stmt_str, -1, &((*result)->data), 0);
	if( rc != SQLITE_OK )
    {
		return rc;
	}

    return sqlite3_step((*result)->data);
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
	(*result)->first_row = 1;

    /* Execute statement */

    status = DbExecuteSqlStatement(handle, stmt_str, result);
    if (status == SQLITE_ROW) {
		/* Reset the status so that it is consistent across db engines */
		status = 0;

        /* Check the pointer to the result set */
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

			(*result)->count = sqlite3_data_count((sqlite3_stmt*) (*result)->data);
		}
    }
	else if (status == SQLITE_DONE)
	{
		/* Correct for one-shot statements like insert etc 
         * finalise the statement to avoid locking the database */
		status = sqlite3_finalize((sqlite3_stmt*) (*result)->data);

		MemFree(*result);
		*result = NULL;
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

			sqlite3_finalize(result->data);
			MemFree(result);
			result = NULL;
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
 * 		Steps to the next row in the result set.
 *
 * Arguments:
 * 		DB_RESULT result
 * 			The result handle returned by the call to DbExecuteSql.
 *
 * 		DB_ROW* row
 * 			This is really just the same as RESULT for sqlite, but it is left
 * 			in for MySQL compatibility.
 *
 * Returns:
 * 		int
 * 			0	Success, row information returned
 * 			-1  Success, no more rows for this result
 * 			Other	    Error code or error number from DbErrno().
-*/

int DbFetchRow(DB_RESULT result, DB_ROW* row)
{
	int			status = 0;			/* Status return */

	if (result && (result->magic == DB_RESULT_MAGIC) && row) {

		/* There is a result structure (and row pointer), do something */

		if (result->first_row == 1)
		{
			result->first_row = 0;
			*row = (DB_ROW) MemCalloc(1, sizeof(struct db_row));
			(*row)->magic = DB_ROW_MAGIC;
			(*row)->result=result;
		}
		else
		{
			status = sqlite3_step(result->data);
			if (status == SQLITE_DONE) {
				/* End of result set */
                /* leave freeing the row to the calling function */
				/* *row = NULL; */

				status = -1;
			}
			else if (status == SQLITE_ROW)
			{
				*row = (DB_ROW) MemCalloc(1, sizeof(struct db_row));
				(*row)->magic = DB_ROW_MAGIC;
				(*row)->result=result;
				status = 0;
			}
		}
	}
	else if (row) {
		*row = NULL; /* no results to report */
		status = -1;
	}
	else{
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
	unsigned long	width;			    /* Width of column */

	/* Check arguments */

	if (row && (row->magic == DB_ROW_MAGIC) && result) {

		/* Is the index requested valid? */

		if ((field_index >= 0) && (field_index < row->result->count)) {

			/* Get the width of the column */

			width = sqlite3_column_bytes(row->result->data, field_index);

			/* Get string into null-terminated form */

			if (sqlite3_column_text(row->result->data, field_index) != NULL) {
                /* TODO replece the below with strdup or StrStrdup ? */
				*result = MemMalloc(width + 1);
				memcpy(*result, sqlite3_column_text(row->result->data, field_index), width);
				(*result)[width] = 0;
			}
			else {
				*result = NULL;
			}
		}
		else {

			/* Invalid field, tell the user */

			status = MsgLog(DBS_INVINDEX, field_index, row->result->count-1);
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
 *      
 *
 * Arguments:
 *              NONE
-*/

int DbBeginTransaction(void)
{
    const char* sql = "begin transaction";
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
    const char* sql = "commit transaction";
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
    const char* sql = "rollback transaction";
    return DbExecuteSqlNoResult(DbHandle(), sql);
}
