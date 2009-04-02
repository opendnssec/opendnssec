/*+
 * ksm_version.ver (version.c) - Return Version
 *
 * Description:
 *		The file "ksm_version.c" is created at build time from this file,
 *		"ksm_version.ver".  It simply returns a string identifying the version
 *		of the library.
 *
 *		Typically this string is expected to include the date and time of the
 *		build.
 *
 *		In the string below, the "make" procedure will replace the following
 *		tags:
 *
 *		Wed Apr  1 16:25:02 BST 2009		The current date and time (from the "date" command).
 *
 * Arguments:
 *		None.
 *
 * Returns:
 *		const char *
 *			Version of the build.
-*/

#include "ksm_version.h"

static const char* LIBRARY_VERSION = "0.7"
#ifndef NDEBUG
	"-DEBUG"
#endif
" (built on Wed Apr  1 16:25:02 BST 2009)";

const char* KsmVersion(void)
{
	return LIBRARY_VERSION;
}
