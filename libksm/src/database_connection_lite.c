/*+
 * database_connection_lite.c - Database Connection Functions
 *
 * Description:
 *      Contains the database management functions (such as connect and
 *      disconnect) and holds session-specific database information.
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
#include <stdlib.h>

#include <sqlite3.h>

#include "database.h"
#include "dbsdef.h"
#include "message.h"

static sqlite3* m_dbhandle = NULL;  /* Non-NULL if connected */



/*+
 * DbConnect - Connect to Database
 *
 * Description:
 *      Creates a connection to the specified database using the parameters
 *      supplied.  If successful, the handle to the connection is stored
 *      locally, for retrieval by DbHandle().
 *
 *      Should there be an error, a suitable message is output.
 *
 * Arguments:
 * 		DB_HANDLE* dbhandle
 * 			Address of a location into which the connection handle is put.  This
 * 			is also stored locally for retrieval by DbHandle().  If this argument
 * 			is NULL, no handle is returned through the function call.
 *
 * 			Note that if a handle for an active connection is already stored
 * 			locally, this function will overwrite it, regardless of success or
 * 			failure.
 *
 *      const char* database
 *          name of database (NULL to pick up the default).
 *
 *      ...
 *          Optional arguments.
 *
 *      These are used for the MySql implementation, sqlite doesn't need them
 *
 * Returns:
 *      int
 *          0       Success
 *          Other   Error on connection.  The message will have been logged via
 *                  the MsgLog() function.
-*/

int DbConnect(DB_HANDLE* dbhandle, const char* database, ...)
{
	sqlite3*	connection = NULL;	/* Local database handle */
    va_list     ap;                 /* Argument pointer */
    int         status = 0;         /* Return status */

    /* Initialize if not already done so */

    DbInit();

    /* Get arguments */

    va_start(ap, database);
    va_end(ap);

    /* ... and connect */

    status = sqlite3_open(database, &connection);

    if (status) {
        /* Unable to connect */
        status = MsgLog(DBS_CONNFAIL, sqlite3_errmsg(connection));
    }

	/* Store the returned handle for retrieval by DbHandle() */

	m_dbhandle = connection;

	/* ... and pass back to the caller via the argument list */

	if (dbhandle) {
		*dbhandle = (DB_HANDLE) connection;
	}

    return status;
}


/*+
 * DbDisconnect - Disconnect from Database
 *
 * Description:
 *      Disconnects from the current database.  If there is no current database,
 *      this is a no-op.
 *
 * Arguments:
 * 		DB_HANDLE dbhandle
 * 			Pointer to the connection handle.  After this function is called,
 * 			the handle is invalid.
 *
 * 			If the handle passed to this function is the same as the one stored
 * 			locally (and returned by DbHandle()), then the local copy is zeroed.
 *
 * Returns:
 *      int
 *          Status return.  One of:
 *
 *              0               Success
 *              DBS_NOTCONN     Not connected to a database
 *      None.
-*/

int DbDisconnect(DB_HANDLE dbhandle)
{
    int status = 0;     /* Return status */

    if (dbhandle) {
		if (dbhandle == m_dbhandle) {
			m_dbhandle = NULL;
		}
        sqlite3_close((sqlite3*) dbhandle);
    }
    else {
        status = MsgLog(DBS_NOTCONN);
    }

    return status;
}



/*+
 * DbConnected - Check if Connected to a Database
 *
 * Description:
 *      Interrogates the connection status.
 *
 * Arguments:
 *      DB_HANDLE dbhandle
 *      	Handle to the connection.
 *
 * Returns:
 *      int
 *          true if connected to a database, false otherwise.
-*/

int DbConnected(DB_HANDLE dbhandle)
{
    return dbhandle != NULL;
}



/*+
 * DbCheckConnected - Check If Connected
 *
 * Description:
 *      Checks if connected to the database, and if not, outputs an error.
 *
 * Arguments:
 *      DB_HANDLE dbhandle
 *      	Handle to the connection.
 *
 * Returns:
 *      int
 *          1 if connected, 0 if not.
-*/

int DbCheckConnected(DB_HANDLE dbhandle)
{
    int connected;

    connected = DbConnected(dbhandle);
    if (! connected) {
        MsgLog(DBS_NOTCONERR);
    }

    return connected;
}


/*+
 * DbHandle - Return Database Handle
 *
 * Description:
 *      Returns the handle to the database (the pointer to the MYSQL
 *      structure).
 *
 * Arguments:
 *      None.
 *
 * Returns:
 *      DB_HANDLE
 *          Database handle, which is NULL if none is stored.
-*/

DB_HANDLE DbHandle(void)
{
    return (DB_HANDLE) m_dbhandle;
}
