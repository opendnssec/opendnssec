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

#include "ksm/ksm_version.h"

static const char* LIBRARY_VERSION = "0.7"
#ifndef NDEBUG
	"-DEBUG"
#endif
" (built on Wed Apr  1 16:25:02 BST 2009)";

const char* KsmVersion(void)
{
	return LIBRARY_VERSION;
}
