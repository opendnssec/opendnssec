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
 * database_connection_lite.c - Database Connection Functions
 *
 * Description:
 *      Contains the database management functions (such as connect and
 *      disconnect) and holds session-specific database information.
-*/

#include <stdarg.h>
#include <stdlib.h>

#include <sqlite3.h>

#include "ksm/database.h"
#include "ksm/dbsdef.h"
#include "ksm/message.h"

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
    /* status = sqlite3_open_v2(database, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, NULL); */

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

    /* Check the version against what we have in database.h */
    if (status == 0) {
        status = db_version_check();
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
