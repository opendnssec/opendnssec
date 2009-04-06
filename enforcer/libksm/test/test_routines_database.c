/*+
 * test_routines_database.c - Database Test Routines
 *
 * Description:
 * 		A set of routines to help with the tests that access the database.
-*/

#include <stdlib.h>

#include "database.h"
#include "test_routines.h"


/*+
 * TdbUsername - Return database username
 * TdbPassword - Return database password
 * TdbHost - Return database host
 * TdbName - Return database name
 *
 * Description:
 * 		Translates the environment variables:
 *
 * 			DB_USERNAME
 * 			DB_PASSWORD
 * 			DB_HOST
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
	(void) system("./database_setup.sh setup");
#else
	(void) system("./database_setup_lite.sh setup");
#endif

	DbInit();

	status = DbConnect(&handle, TdbName(), TdbHost(), TdbPassword(),
		TdbUsername());

	return status;
}

int TdbTeardown(void)
{
	/* Ignore errors - teardown failure does not imply test failure */

	(void) DbDisconnect(DbHandle());

	DbRundown();

#ifdef USE_MYSQL
	(void) system("./database_setup.sh teardown");
#else
	(void) system("./database_setup_lite.sh teardown");
#endif

	return 0;
}
