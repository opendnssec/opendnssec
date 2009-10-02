/*
 * $Id: privdrop.c 1933 2009-09-30 09:06:07Z jakob $
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
#include <sys/types.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>

#include "config.h"
#include "logging.h"
#include "privdrop.h"


int
privdrop(const char *username, const char *groupname, const char *newroot)
{
    int status;

    struct passwd *pwd;
    struct group  *grp;

    uid_t uid, olduid;
    gid_t gid, oldgid;

    /* Save effective uid/gid */
    uid = olduid = getuid();
    gid = oldgid = getgid();

    /* Check if we're going to drop uid */
    if (username) {
        /* Lookup the user id in /etc/passwd */
        if ((pwd = getpwnam(username)) == NULL) {
            log_msg(LOG_ERR, "zone fetcher user '%s' does not exist. exiting...", username);
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
            log_msg(LOG_ERR, "zone fetcher group '%s' does not exist. exiting...", groupname);
            exit(1);
        } else {
            gid = grp->gr_gid;
        }
        endgrent();
    }

    /* Change root if requested */
    if (newroot) {
       if (chroot(newroot) != 0 || chdir("/") != 0) {
            log_msg(LOG_ERR, "zone fetcher chroot to '%s' failed. exiting...", newroot);
            exit(1);
       }

       log_msg(LOG_INFO, "zone fetcher changed root to '%s'", newroot);
    }

    /* Drop gid? */
    if (groupname) {
#ifdef HAVE_SETRESGID
        if ((status = setresgid(gid, gid, gid)) != 0)
#elif defined(HAVE_SETREGID) && !defined(DARWIN_BROKEN_SETREUID)
            if ((status = setregid(gid)) != 0)
#else /* use setgid */
                if ((status = setgid(gid)) != 0)
#endif /* HAVE_SETRESGID */
                    log_msg(LOG_ERR, "zone fetcher unable to set group id of %s (%lu): %s",
                        groupname, (unsigned long) gid, strerror(errno));

        if (status != 0)
            return status;
        else
            log_msg(LOG_INFO, "zone fetcher dropped group privileges to %s (%lu)",
                        groupname, (unsigned long) gid);
    }

    /* Drop uid? */
    if (username) {
#ifdef HAVE_SETRESUID
        if ((status = setresuid(uid,uid,uid)) != 0)
#elif defined(HAVE_SETREUID) && !defined(DARWIN_BROKEN_SETREUID)
            if ((status = setreuid(uid,uid)) != 0)
#else /* use setuid */
                if ((status = setuid(uid)) != 0)
#endif /* HAVE_SETRESUID */
                    log_msg(LOG_ERR, "zone fetcher unable to set user id of %s (%lu): %s",
                        username, (unsigned long) uid, strerror(errno));
        if (status != 0)
            return status;
        else
            log_msg(LOG_INFO, "zone fetcher dropped user privileges to %s (%lu)",
                        username, (unsigned long) uid);
    }

    return 0;
}
