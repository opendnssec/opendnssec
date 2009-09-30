/*
 * $Id$
 *
 * Copyright (c) 2009 Nominet UK. All rights reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>

#include "config.h"
#include "privdrop.h"


int
privdrop(const char *username, const char *groupname, const char *chroot)
{
    int status;

    struct passwd *pwd;
    struct group  *grp;

    uid_t uid, olduid;
    gid_t gid, oldgid;

    /* Save effective uid/gid */
    uid = olduid = geteuid();
    gid = oldgid = getegid();

    /* Check if we're going to drop uid */
    if (username) {
        /* Lookup the user id in /etc/passwd */
        if ((pwd = getpwnam(username)) == NULL) {
            syslog(LOG_ERR, "user '%s' does not exist. exiting...\n", username);
            exit(1);
        } else {
	    uid = pwd->pw_uid;
        }
        endpwent();
    }

    /* Check if we're going to drop gid */
    if (groupname) {
        /* Lookup the group id in /etc/groups */
        if ((grp = getgrnam(groupname)) == NULL) {
            syslog(LOG_ERR, "group '%s' does not exist. exiting...\n", groupname);
            exit(1);
        } else {
            gid = grp->gr_gid;
        }
        endgrent();
    }

    /* XXX when we implement chroot(), we do it here */

    /* Drop gid? */
    if (groupname) {
        /* If we are root then drop all groups other than the final one */
        if (!olduid) setgroups(1, &(grp->gr_gid));

#if !defined(linux)
        setegid(gid);
        status = setgid(gid);
#else
        status = setregid(gid, gid);
#endif /* !defined(linux) */

        if (status != 0) {
           syslog(LOG_ERR, "unable to drop group privileges: %s (%lu). exiting...\n", groupname, gid);
           exit(1);
           return -1;
        } else {
            syslog(LOG_ERR, "group set to: %s (%lu)\n", groupname, gid);
        }
    }

    /* Drop uid? */
    if (username) {
        /* Set the user to drop to if specified; else just set the uid as the real one */
#if defined(HAVE_SETRESUID) && !defined(BROKEN_SETRESUID)
        status = setresuid(uid, uid, uid);
#elif defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
        status = setreuid(uid, uid);
#else

# ifndef SETEUID_BREAKS_SETUID
        seteuid(uid);
# endif  /* SETEUID_BREAKS_SETUID */

        status = setuid(uid);
#endif

        if (status != 0) {
           syslog(LOG_ERR, "unable to drop user privileges: %s (%lu). exiting...\n", username, uid);
           exit(1);
           return -1;
        } else {
            syslog(LOG_ERR, "user set to: %s (%lu)\n", username, uid);
        }
    }

    return 0;
}
