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

#ifndef KSM_KMEDEF_H
#define KSM_KMEDEF_H

/*+
 * kmedef.h - Define KSM Error Codes
 *
 * Description:
 *      Defines the various status codes that can be returned by the various
 *      KSM routines.
 *
 *      All status codes - with the exception of KME_SUCCESS - are above
 *      65,536.  Below this, status values are assumed to be error values
 *      returned from the operating system.
-*/

#define KME_SUCCESS 0                       /* Successful completion */

#define KME_BASE        65536               /* Base of KSM status codes */

#define KME_ACTKEYRET   (KME_BASE +  0)     /* INFO: %d keys in 'active' state will have their expected retire date modified */
#define KME_AVAILCNT    (KME_BASE +  1)     /* INFO: %d keys current in 'publish', 'ready' and 'active' states */
#define KME_BUFFEROVF   (KME_BASE +  2)     /* ERROR: internal error, buffer overflow in %s */
#define KME_CHILDREN    (KME_BASE +  3)     /* ERROR: unable to delete %s because child objects are associated with it */
#define KME_CREFAIL     (KME_BASE +  4)     /* ERROR: failed to create '%s' */
#define KME_EXISTS      (KME_BASE +  5)     /* ERROR: object with name '%s' already exists */
#define KME_FLDMISMAT   (KME_BASE +  6)     /* ERROR: program error - number of fields returned did not match number expected */
#define KME_GENERATECNT (KME_BASE +  7)     /* INFO: %d %ss available in 'generate' state */
#define KME_INSFGENKEY  (KME_BASE +  8)     /* ERROR: %d %ss available in 'generate' state (need %d) - unable to promote until key generation has run */
#define KME_KEYCHSTATE  (KME_BASE +  9)     /* INFO: moving %d key(s) from '%s' state to '%s' state */
#define KME_KEYCNTSUMM  (KME_BASE + 10)     /* INFO: %d keys required, therefore %d new keys need to be put in 'publish' state */
#define KME_NOREADYKEY  (KME_BASE + 11)     /* WARNING: key rollover not completed as there are no keys in the 'ready' state; communicated will try again when it runs next */
#define KME_NOSUCHPAR   (KME_BASE + 12)     /* ERROR: no such parameter with name %s */
#define KME_NOTFOUND    (KME_BASE + 13)     /* ERROR: unable to find object '%s' */
#define KME_NOTIMPL     (KME_BASE + 14)     /* WARNING: Command not implemented yet */
#define KME_NOTZONE     (KME_BASE + 15)     /* ERROR: %s is not a zone */
#define KME_PERMANENT   (KME_BASE + 16)     /* ERROR: it is not permitted to delete the permanent object %s */
#define KME_READYCNT    (KME_BASE + 17)     /* INFO: %d %ss in the 'ready' state */
#define KME_REMAINACT   (KME_BASE + 18)     /* INFO: %d %ss remaining in 'active' state */
#define KME_REQKEYTYPE  (KME_BASE + 19)     /* INFO: requesting issue of %s signing keys */
#define KME_RETIRECNT   (KME_BASE + 20)     /* INFO: %d 'active' keys will be retiring in the immediate future */
#define KME_SQLFAIL     (KME_BASE + 21)     /* ERROR: database operation failed - %s */
#define KME_UNKEYTYPE	(KME_BASE + 22)		/* ERROR: unknown key type, code %d */
#define KME_UNRCONCOD   (KME_BASE + 23)     /* WARNING: unrecognised condition code %d: code ignored */
#define KME_UNRKEYSTA   (KME_BASE + 24)     /* WARNING: key ID %d is in unrecognised state %d */
#define KME_PROM_PUB    (KME_BASE + 25)     /* INFO: Promoting %s from publish to active as this is the first pass for the zone */
#define KME_BACK_FATAL  (KME_BASE + 26)     /* ERROR: Trying to make non-backed up %s active when RequireBackup flag is set */
#define KME_BACK_NON_FATAL  (KME_BASE + 27)     /* WARNING: Making non-backed up %s active, PLEASE make sure that you know the potential problems of using keys which are not recoverable */
#define KME_DS_REM_ZONE  (KME_BASE + 28)     /* INFO: Old DS record for %s can now be removed (key moved for retired to dead state) */
#define KME_DS_REM_POLICY  (KME_BASE + 29)     /* INFO: Old DS record for %s and all zones on its policy can now be removed (key moved for retired to dead state) */
#define KME_ROLL_ZONE  (KME_BASE + 30)     /* INFO: %s has been rolled for %s  */
#define KME_ROLL_POLICY  (KME_BASE + 31)     /* INFO: %s has been rolled for %s (and any zones sharing keys with %s) */
#define KME_TIMESHIFT  (KME_BASE + 32)     /* DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to %s */
#define KME_MAN_ROLL_REQUIRED  (KME_BASE + 33)     /* INFO: Manual rollover due for %s of zone %s */
#define KME_WRONG_DB_VER (KME_BASE + 34)     /* ERROR: database version number incompatible with software; require %d, found %d. Please run the migration scripts */
#define KME_DB_ADMIN    (KME_BASE + 35)     /* ERROR: Too many rows returned from dbadmin table; there should be only one. */


#endif /* KSM_KMEDEF_H */
