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

#ifndef KSM_DBEDEF_H
#define KSM_DBEDEF_H

#ifdef __cplusplus
extern "C" {
#endif

/*+
 * dbsdef.h - Define Database Status Codes
 *
 * Description:
 *      Defines the various status codes that can be returned by the various
 *      DB routines.
-*/

#define DBS_BASE		(65536 + 6144)	/* Base of DB status codes */

#define DBS_AUTOCOMM	(DBS_BASE +  0)	/* ERROR: failed to enable autocommit - %s */
#define DBS_BUFFEROVF	(DBS_BASE +  1)	/* ERROR: buffer overflow in %s */
#define DBS_CONNFAIL	(DBS_BASE +  2)	/* ERROR: unable to connect to database - %s */
#define DBS_INITFAIL	(DBS_BASE +  3)	/* ERROR: could not initialize handle to database */
#define	DBS_INVARG		(DBS_BASE +  4)	/* ERROR: invalid arguments to %s */
#define	DBS_INVINDEX	(DBS_BASE +  5)	/* ERROR: invalid index of %d, maximum index is %d */
#define DBS_NORESULT	(DBS_BASE +  6)	/* ERROR: no result obtained from query where one was expected */
#define DBS_NOSUCHROW	(DBS_BASE +  7)	/* ERROR: unable to get ID of last inserted row - no such row created? */
#define DBS_NOTCONERR	(DBS_BASE +  8)	/* ERROR: not connected to the database */
#define DBS_NOTCONN		(DBS_BASE +  9)	/* INFO: not connected to the database */
#define DBS_NOTINT		(DBS_BASE + 10)	/* ERROR: expected integer result from query, but obtained '%s' instead */
#define DBS_SQLFAIL		(DBS_BASE + 11)	/* ERROR: error executing SQL - %s */
#define DBS_STMTALLOC	(DBS_BASE + 12)	/* ERROR: unable to allocate prepared statement structure */
#define DBS_STMTPREP	(DBS_BASE + 13)	/* ERROR: unable to create prepared statement - %s */
#define DBS_TOOMANYROW	(DBS_BASE + 14)	/* WARNING: query '%s' returned too many rows, excess ignored */
#define DBS_UNEXRES		(DBS_BASE + 15)	/* ERROR: unexpected result from executing SQL statement '%s' */

#ifdef __cplusplus
};
#endif

#endif /* KSM_DBEDEF_H */
