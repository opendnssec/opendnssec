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
 * test_routines_database.c - Database Test Routines
 *
 * Description:
 * 		A set of routines to help with the tests that access the database.
-*/

#include <stdlib.h>

#include "ksm/database.h"
#include "test_routines.h"


/*+
 * TdbUsername - Return database username
 * TdbPassword - Return database password
 * TdbHost - Return database host
 * TdbPort - Return database port
 * TdbName - Return database name
 *
 * Description:
 * 		Translates the environment variables:
 *
 * 			DB_USERNAME
 * 			DB_PASSWORD
 * 			DB_HOST
 * 			DB_PORT
 * 			DB_NAME
 *
 * 		... and returns the value.
 *
 * Arguments:
 * 		None.
 *
 * Returns:
 * 		const char*
 * 			Pointer to the appropriate value.  This may be NULL if the value
 * 			is not defined.
 *
 * 			The string should not be modified by the caller - it points to
 * 			internal storage.
-*/

const char* TdbUsername(void)
{
	return getenv("DB_USERNAME");
}

const char* TdbPassword(void)
{
	return getenv("DB_PASSWORD");
}

const char* TdbHost(void)
{
	return getenv("DB_HOST");
}

const char* TdbName(void)
{
	return getenv("DB_NAME");
}

const char* TdbPort(void)
{
	return getenv("DB_PORT");
}

/*+
 * TdbSetup - Set Up Database
 * TdbTeardown - Teardown Database
 *
 * Description:
 *		Sets up a database and connects to it/tears down a database and
 *		disconnects from it.
 *
 * Arguments:
 * 		None.
 *
 * Returns:
 *		int
 *			0		Success
 *			Other	Some failure
-*/

int TdbSetup(void)
{
	DB_HANDLE	handle;		/* database handle (unused) */
	int			status;		/* Status return from connection */

#ifdef USE_MYSQL
	(void) system("sh ./database_setup_mysql.sh setup");
#else
	(void) system("sh ./database_setup_sqlite3.sh setup");
#endif

	DbInit();

	status = DbConnect(&handle, TdbName(), TdbHost(), TdbPassword(),
		TdbUsername(), TdbPort());

	return status;
}

int TdbTeardown(void)
{
	/* Ignore errors - teardown failure does not imply test failure */

	(void) DbDisconnect(DbHandle());

	DbRundown();

#ifdef USE_MYSQL
	(void) system("sh ./database_setup_mysql.sh teardown");
#else
	(void) system("sh ./database_setup_sqlite3.sh teardown");
#endif

	return 0;
}
