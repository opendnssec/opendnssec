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

#ifndef KSM_KSMDEF_H
#define KSM_KSMDEF_H

/*+
 * status.h - Define Status Codes
 *
 * Description:
 *      Defines the various status codes that can be returned by the various
 *      KSM routines.
 *
 *      All status codes - with the exception of KSM_SUCCESS - are above
 *      65,536.  Below this, status values are assumed to be error values
 *      returned from the operating system.
-*/

#define KSM_SUCCESS 0           /* Successful completion */

#define KSM_BASE        (65536 + 400)       /* Base of KSM status codes */

#define KSM_INVOPTION   (KSM_BASE +  0)     /* ERROR: Invalid command option -%c */
#define KSM_UNRCOMMAND  (KSM_BASE +  1)     /* ERROR: Unrecognised command */
#define KSM_AMBCOMMAND  (KSM_BASE +  2)     /* ERROR: Ambiguous command */
#define KSM_NOTIMPL     (KSM_BASE +  3)     /* WARNING: Command not implemented yet */
#define KSM_INITFAIL    (KSM_BASE +  4)     /* ERROR: MySQL initialization failure */
#define KSM_CONNFAIL    (KSM_BASE +  5)     /* ERROR: Unable to connect to database: %s */
#define KSM_NOTCONN     (KSM_BASE +  6)     /* INFO: not connected to a database */
#define KSM_TOOMANYARG  (KSM_BASE +  7)     /* ERROR: too many command line arguments */
#define KSM_GRPCREFAIL  (KSM_BASE +  8)     /* ERROR: unable to create group %s - %s */
#define KSM_OBJECTID    (KSM_BASE +  9)     /* ERROR: unable to get ID of %s - %s */
#define KSM_EXTRADATA   (KSM_BASE + 10)     /* ERROR: extra data in result set */
#define KSM_NOGROUP     (KSM_BASE + 11)     /* ERROR: no groups specified */
#define KSM_GRPCREATE   (KSM_BASE + 12)     /* INFO: created group %s */
#define KSM_GRPDELETE   (KSM_BASE + 13)     /* INFO: created group %s */
#define KSM_COUNTFAIL   (KSM_BASE + 14)     /* ERROR: failed to perform count of objects in database - %s */
#define KSM_EXISTS      (KSM_BASE + 15)     /* ERROR: object with name '%s' already exists */
#define KSM_CREFAIL     (KSM_BASE + 16)     /* ERROR: failed to create '%s' */
#define KSM_NOTFOUND    (KSM_BASE + 17)     /* ERROR: unable to find object '%s' */
#define KSM_CHILDZONE   (KSM_BASE + 18)     /* ERROR: unable to delete group as child zones are attached to it */
#define KSM_INSFARG     (KSM_BASE + 19)     /* ERROR: insufficient command line arguments */
#define KSM_INVARG      (KSM_BASE + 20)     /* ERROR: invalid argument */
#define KSM_SQLFAIL     (KSM_BASE + 21)     /* ERROR: database operation failed - %s */
#define KSM_FLDMISMAT   (KSM_BASE + 22)     /* ERROR: program error - number of fields returned did not match number expected */
#define KSM_EXCESS      (KSM_BASE + 23)     /* WARNING: too much data in result set - excess ignored */
#define KSM_PERMANENT   (KSM_BASE + 24)     /* ERROR: it is not permitted to delete the permanent object %s */
#define KSM_CHILDREN    (KSM_BASE + 25)     /* ERROR: unable to delete %s because child objects are associated with it */
#define KSM_DELFAIL     (KSM_BASE + 26)     /* ERROR: unable to delete %s - %s */
#define KSM_INVNAME     (KSM_BASE + 27)     /* ERROR: object name is invalid */
#define KSM_NOTGROUP    (KSM_BASE + 28)     /* ERROR: %s is not a group */
#define KSM_NOTZONE     (KSM_BASE + 29)     /* ERROR: %s is not a zone */
#define KSM_NOTCONNE    (KSM_BASE + 30)     /* ERROR: not connected to the database */
#define KSM_STMTALLOC   (KSM_BASE + 31)     /* ERROR: unable to allocate space for prepared statement structure */
#define KSM_STMTPREP    (KSM_BASE + 32)     /* ERROR: unable to create SQL statement - %s */
#define KSM_STMTBIND    (KSM_BASE + 33)     /* ERROR: unable to bind parameters to statement - %s */
#define KSM_STMTEXEC    (KSM_BASE + 34)     /* ERROR: unable to execute SQL statement - %s */
#define KSM_UNRCONCOD   (KSM_BASE + 35)     /* WARNING: unrecognised condition code %d: code ignored */
#define KSM_PAREXIST    (KSM_BASE + 36)     /* ERROR: parameter '%' already exists attached to '%s' */
#define KSM_NOPARWTHID  (KSM_BASE + 37)     /* ERROR: cannot find parameter with ID of %d */
#define KSM_NOPARPNAME  (KSM_BASE + 38)     /* WARNING: no parameter named %s found on parent %s, default value used */
#define KSM_NOPARPID    (KSM_BASE + 39)     /* WARNING: no parameter named %s found on parent with ID %d, default value used */
#define KSM_UNRKEYSTA   (KSM_BASE + 40)     /* WARNING: key ID %d is in unrecognised state %d */
#define KSM_BUFFEROVF   (KSM_BASE + 41)     /* ERROR: internal error, buffer overflow in %s */
#define KSM_REQKEYTYPE  (KSM_BASE + 42)     /* INFO: requesting issue of %s signing keys */
#define KSM_KEYCHSTATE  (KSM_BASE + 43)     /* INFO: moving %d key(s) from '%s' state to '%s' state */
#define KSM_RETIRECNT   (KSM_BASE + 44)     /* INFO: %d 'active' keys will be retiring in the immediate future */
#define KSM_AVAILCNT    (KSM_BASE + 45)     /* INFO: %d keys current in 'publish', 'ready' and 'active' states */
#define KSM_KEYCNTSUMM  (KSM_BASE + 46)     /* INFO: %d keys required, therefore %d new keys need to be put in 'publish' state */
#define KSM_INSFGENKEY  (KSM_BASE + 47)     /* ERROR: only %d %ss available in 'generate' state - request abandoned */
#define KSM_GENERATECNT (KSM_BASE + 48)     /* INFO: %d %ss available in 'generate' state */
#define KSM_REMAINACT   (KSM_BASE + 49)     /* INFO: %d %ss remaining in 'active' state */
#define KSM_READYCNT    (KSM_BASE + 50)     /* INFO: %d %ss in the 'ready' state */
#define KSM_NOREADYKEY  (KSM_BASE + 51)     /* WARNING: cannot continue with key rollover as there are no keys in the 'ready' state */
#define KSM_ACTKEYRET   (KSM_BASE + 52)     /* INFO: %d keys in 'active' state will have their expected retire date modified */
#define KSM_NOSUCHPAR   (KSM_BASE + 53)     /* ERROR: no such parameter with name %s */

#endif /* KSM_KSMDEF_H */
