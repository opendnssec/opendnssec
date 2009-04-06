/*+
 * database_support - Database Utility Functions
 *
 * Description:
 *      Holds miscellaneous utility functions associated with the MySql
 *      database.
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

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <sqlite3.h>

#include "dbsdef.h"
#include "database.h"
#include "debug.h"
#include "message.h"
#include "string_util.h"
#include "string_util2.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))



/*+
 * DbExecuteSqlNoResult - Execute SQL Statement and Ignore Result
 *
 * Description:
 *      Executes the given SQL statement; any results are discarded.
 *
 *      This function is useful for statements such as DELETE and INSERT.
 *
 * Arguments:
 *      DB_HANDLE handle
 *          Handle to the currently opened database.
 *
 *      const char* stmt_str
 *          Statement to execute
 *
 * Returns:
 *      int
 *          Status return.
 *          	0		Success
 *          	Other	Error. A message will have been output.
-*/

int DbExecuteSqlNoResult(DB_HANDLE handle, const char* stmt_str)
{
    DB_RESULT	result;     /* Pointer to result string */
    int         status;     /* Status return */

    status = DbExecuteSql(handle, stmt_str, &result);
    if (status == 0) {
        if (result) {

            /* Result given - get rid of it, we don't want it */

            status = MsgLog(DBS_UNEXRES, stmt_str);
            DbFreeResult(result);
        }
    }

    return status;
}


/*+
 * DbRowId - Return ID of Current Row
 *
 * Description:
 * 		Returns the ID of the current row.  This is assumed to be an auto-
 * 		increment column at index 0 of the table.
 *
 * Arguments:
 * 		DB_ROW row
 * 			Row in question.
 *
 * 		DB_ID* id
 * 			ID of the row is returned here.
 *
 * Returns:
 * 		int
 * 			Status return.
 *
 * 				0		Success
 * 				Other	Error.  A message will have been output.
-*/

int DbRowId(DB_ROW row, DB_ID* id)
{
	unsigned long	rowid;		/* ID of the row as a known type */
	int				status;		/* Status return */

	status = DbUnsignedLong(row, 0, &rowid);
	*id = (DB_ID) rowid;		/* Do the conversion between types here */

	return status;
}
	



/*+
 * DbInt - Return Integer from Field
 *
 * Description:
 * 		Returns an integer value from the current row.
 *
 * Arguments:
 *      DB_ROW row
 *          Pointer to the row object.
 *
 *      int field_index
 *          Index of the value required.
 *
 *      int *value
 *      	Value returned.
 *
 * Returns:
 *      int
 *      	Status return:
 *      		0		Success
 *      		Other	Error accessing data.  A message will have been output.
-*/

int DbInt(DB_ROW row, int field_index, int *value)
{
    char*   buffer;		/* Text buffer for returned string */
	int		status;		/* Status return */

	/* Access the text in the field */

    status = DbString(row, field_index, &buffer);
	if (status == 0) {

		/* Got the string, can we convert it? */

		if (buffer) {

			/* Not best-efforts - ignore trailing non-numeric values */

			status = StrStrtoi(buffer, value);
			if (status == -1) {

				/* Could not translate the string to an integer */

				status = MsgLog(DBS_NOTINT, buffer);
				*value = 0;
			}
			DbStringFree(buffer);
		}
		else {

			/* Field is NULL, return 0 */
            /* TODO should we do something better here ? */

			*value = 0;
		}
	}

    return status;
}



/*+
 * DbUnsignedLong - Return Unsigned Long from Field
 *
 * Description:
 * 		Returns an integer value from the current row.
 *
 * Arguments:
 *      DB_ROW row
 *          Pointer to the row object.
 *
 *      int field_index
 *          Index of the value required.
 *
 *      unsigned long *value
 *      	Value returned.
 *
 * Returns:
 *      int
 *      	Status return:
 *      		0		Success
 *      		Other	Error accessing data.  A message will have been output.
-*/

int DbUnsignedLong(DB_ROW row, int field_index, unsigned long *value)
{
    char*   buffer;		/* Text buffer for returned string */
	int		status;		/* Status return */

	/* Access the text in the field */

    status = DbString(row, field_index, &buffer);
	if (status == 0) {

		/* Got the string, can we convert it? */

		if (buffer) {

			/* Not best-efforts - ignore trailing non-numeric values */

			status = StrStrtoul(buffer, value);
			if (status == -1) {

				/* Could not translate the string to an integer */

				status = MsgLog(DBS_NOTINT, buffer);
				*value = 0;
			}
			DbStringFree(buffer);
		}
		else {

			/* Field is NULL, return 0 */

			*value = 0;
		}
	}

    return status;
}



/*+
 * DbIntQuery - Perform Query Returning Single Integer
 *
 * Description:
 *      Many queries are of the form:
 *
 *          SELECT COUNT(*) FROM ...
 *      or
 *          SELECT <single integer value> FROM ...
 *
 *      This function performs the query and returns the single value.
 *
 * Arguments:
 *      DB_HANDLE handle
 *          Handle to the currently opened database.
 *
 *      int* value
 *          Result of the query.  Note that if the query returns no rows,
 *          a zero is returned.
 *
 *      const char* query
 *          Query to run.
 *
 * Returns:
 *      int
 *          0 		Success
 *          Other	Error (a message will have been output)
-*/

int DbIntQuery(DB_HANDLE handle, int* value, const char* query)
{
	DB_RESULT	result;		/* Result object */
	DB_ROW		row;		/* Row object */
    int			status;		/* Status return */

    status = DbExecuteSql(handle, query, &result);
    if (status == SQLITE_OK) {

        /* Get first row */
        status = DbFetchRow(result, &row);
		if (status == 0) {
            /* Got the row, so convert to integer */

            status = DbInt(row, 0, value);

			/* Query succeeded, but are there any more rows? */
        	if (DbFetchRow(result, &row) != -1) {
            	(void) MsgLog(DBS_TOOMANYROW, query);	/* Too much data */
        	}

        }
        else 
        {
			status = MsgLog(DBS_NORESULT);	/* Query did not return a result */
        }

		DbFreeResult(result);
		DbFreeRow(row);

    }

    return status;
}


/*+
 * DbStringBuffer - Return String Value into User-Supplied Buffer
 *
 * Description:
 *      Returns string value from the current row into a user-supplied
 *      buffer.  The returned value is truncated if required.
 *
 * Arguments:
 *      DB_ROW row
 *          Pointer to the row object.
 *
 *      int field_index
 *          Index of the value required.
 *
 *      char* buffer
 *          Null-terminated buffer into which the data is put.  If the returned
 *          string is NULL, the buffer will contain a zero-length string.  There
 *          is no way to distinguish between this and the database holding an
 *          empty string.
 *
 *      size_t buflen
 *          Length of the buffer.
 *
 * Returns:
 * 		int
 * 			0		Success
 * 			Other	Error.  A message will have been output.
-*/

int DbStringBuffer(DB_ROW row, int field_index, char* buffer, size_t buflen)
{
	char*	data;		/* Data returned from DbString */
	int		status;		/* Status return */

	if (row && (row->magic == DB_ROW_MAGIC) && buffer && (buflen != 0)) {

		/* Arguments OK, get the information */

		status = DbString(row, field_index, &data);
		if (status == 0) {

			/* Success, copy the data into destination & free buffer */

			StrStrncpy(buffer, data, buflen);
			DbStringFree(data);
		}
	}
	else {

		/* Invalid srguments, notify the user */

		status = MsgLog(DBS_INVARG, "DbStringBuffer");
	}

	return status;
}



/*+
 * DbErrno - Return Last Error Number
 *
 * Description:
 * 		Returns the numeric code associated with the last operation
 * 		on this connection that gave an error.
 *
 * Arguments:
 *      DB_HANDLE handle
 *          Handle to an open database.
 *
 * Returns:
 * 		int
 * 			Error number.
-*/

int DbErrno(DB_HANDLE handle)
{
    return sqlite3_errcode((sqlite3*) handle);
}



/*+
 * DbErrmsg - Return Last Error Message
 *
 * Description:
 *      Returns the last error on this connection.  This is just an
 *      encapsulation of mysql_error.
 *
 * Arguments:
 *      DB_HANDLE handle
 *          Handle to an open database.
 *
 * Returns:
 *      const char*
 *          Error string.  This should be copied and must not be freed.
-*/

const char* DbErrmsg(DB_HANDLE handle)
{
    return sqlite3_errmsg((sqlite3*) handle);
}


/*+
 * DbLastRowId - Return Last Row ID
 *
 * Description:
 * 		Returns the ID field of the last row inserted.
 *
 * 		All tables are assumed to include an auto-incrementing ID field.  Apart
 * 		from providing the unique primary key, this is a relatively
 * 		implementation-unique way of uniquely identifying a row in a table.
 *
 * Arguments:
 * 		DB_HANDLE handle
 * 			Handle to the database connection.
 *
 * 		DB_ID* id
 * 			ID of the last row inserted (into any table) on this connection.
 *
 * Returns:
 * 		int
 * 			Status return
 *
 * 				0		Success
 * 				Other	Error code.  An error message will have been output.
-*/

int DbLastRowId(DB_HANDLE handle, DB_ID* id)
{
    /* TODO returns a sqlite_int64; can this be cast into an unsigned long?
     * do we need to check this for each platform? */
	*id = (DB_ID) sqlite3_last_insert_rowid((sqlite3*) handle);

	/*
	 * In sqlite, there is no error code; a value of 0 is returned if there
	 * is no matching row.  In this case, convert it to an error code.
	 */

	return (*id != 0) ? 0 : DBS_NOSUCHROW;
}
