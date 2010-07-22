/*
 * $Id: privdrop.c 2284 2009-10-20 14:30:54Z sion $
 *
 * Copyright (c) 2009 Nominet UK. All rights reserved.
 *
 * Based heavily on uidswap.c from openssh-5.2p1
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

/**
 *
 * Privileges.
 */

#define _GNU_SOURCE /* defines for setres{g|u}id */

#include "config.h"
#include "util/log.h"
#include "util/privdrop.h"
#include "util/se_malloc.h"

#include <errno.h>
#include <string.h> /* strerror() */
#include <grp.h> /* getgrnam_r(), endgrent(), initgroups() */
#include <pwd.h> /* getpwnam_r(), endpwent() */
#include <sys/types.h> /* geteuid(), getegid(), getpwnam_r(), endpwent(), initgroups(),
                          getgroups(), setgroups(), setuid(), seteuid(), setreuid(),
                          setgid(), setegid(), setregid()  */
#include <unistd.h> /* sysconf(), geteuid(), getegid(), chroot(), chdir(),
                       getgroups(), setgroups(), setuid(), seteuid(), setreuid(), setresuid(),
                       setgid(), setegid(), setregid(), setresgid() */

#ifndef _SC_GETPW_R_SIZE_MAX
#define _SC_GETPW_R_SIZE_MAX 16384
#endif /* _SC_GETPW_R_SIZE_MAX */

#ifndef _SC_GETGR_R_SIZE_MAX
#define _SC_GETGR_R_SIZE_MAX 16384
#endif /* _SC_GETGR_R_SIZE_MAX */


/**
 * Get the user identifier from the username.
 *
 */
uid_t
privuid(const char* username)
{
    struct passwd pwd;
    struct passwd* result;
    long bufsize;
    char* buf;
    uid_t uid, olduid;
    int s;

    uid = olduid = geteuid();

    if (username) {
        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize == -1) {
            bufsize = 16384; /* should be more than enough */
        }
        buf = (char*) se_calloc(bufsize, sizeof(char));
        /* Lookup the user id in /etc/passwd */
        s = getpwnam_r(username, &pwd, buf, bufsize, &result);
        if (result == NULL) {
            return -1;
        } else {
            uid = pwd.pw_uid;
            se_free((void*) buf);
        }
        endpwent();
    } else {
        uid = -1;
    }
    return uid;
}


/**
 * Get the group identifier from the group name.
 *
 */
gid_t
privgid(const char *groupname)
{
    struct group grp;
    struct group* result;
    long bufsize;
    char* buf;
    gid_t gid, oldgid;
    int s;

    gid = oldgid = getegid();

    if (groupname) {
        bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (bufsize == -1) {
            bufsize = 16384; /* should be more than enough */
        }
        buf = (char*) se_calloc(bufsize, sizeof(char));
        /* Lookup the group id in /etc/group */
        s = getgrnam_r(groupname, &grp, buf, bufsize, &result);
        if (result == NULL) {
            return -1;
        } else {
            gid = grp.gr_gid;
            se_free((void*) buf);
        }
        endgrent();
    } else {
        gid = -1;
    }
    return gid;
}


/**
 * Drop privileges.
 *
 */
int
privdrop(const char *username, const char *groupname, const char *newroot)
{
    int status;
    uid_t uid, olduid;
    gid_t gid, oldgid;
    long ngroups_max;
    gid_t *final_groups;
    int final_group_len = -1;

    /* Save effective uid/gid */
    uid = olduid = geteuid();
    gid = oldgid = getegid();

    /* Check if we're going to drop uid */
    if (username) {
        uid = privuid(username);
        if (uid == (uid_t)-1) {
            se_log_error("user %s does not exist", username);
            return -1;
        }
    }

    /* Check if we're going to drop gid */
    if (groupname) {
        gid = privgid(groupname);
        if (gid == (gid_t)-1) {
            se_log_error("group %s does not exist", groupname);
            return -1;
        }
    }

    /* Change root if requested */
    if (newroot) {
       if (chroot(newroot) != 0 || chdir("/") != 0) {
            se_log_error("chroot to %s failed", newroot);
            return -1;
       }
    }

    /* Do additional groups first */
    if (username != NULL && !olduid) {
        if (initgroups(username, gid) < 0) {
            se_log_error("initgroups failed: %s: %.100s", username,
                strerror(errno));
            return -1;
        }

        ngroups_max = sysconf(_SC_NGROUPS_MAX) + 1;
        final_groups = (gid_t *)se_malloc(ngroups_max *sizeof(gid_t));
        final_group_len = getgroups(ngroups_max, final_groups);
        /* If we are root then drop all groups other than the final one */
        if (!olduid) {
            setgroups(final_group_len, final_groups);
        }
        se_free((void*)final_groups);
    }
    else {
        /* If we are root then drop all groups other than the final one */
        if (!olduid) setgroups(1, &(gid));
    }

    /* Drop gid? */
    if (groupname) {

#if defined(HAVE_SETRESGID) && !defined(BROKEN_SETRESGID)
        status = setresgid(gid, gid, gid);
#elif defined(HAVE_SETREGID) && !defined(BROKEN_SETREGID)
        status = setregid(gid, gid);
#else

# ifndef SETEUID_BREAKS_SETUID
        status = setegid(gid);
        if (status != 0) {
           se_log_error("setegid() for %s (%lu) failed: %s",
               groupname, (unsigned long) gid, strerror(errno));
           return -1;
        }
# endif  /* SETEUID_BREAKS_SETUID */

        status = setgid(gid);
#endif

        if (status != 0) {
           se_log_error("setgid() for %s (%lu) failed: %s",
               groupname, (unsigned long) gid, strerror(errno));
           return -1;
        } else {
            se_log_debug("group set to %s (%lu)", groupname, (unsigned long) gid);
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
        status = seteuid(uid);
        if (status != 0) {
           se_log_error("seteuid() for '%s' (%lu) failed: %s",
               username, (unsigned long) uid, strerror(errno));
           return -1;
        }
# endif  /* SETEUID_BREAKS_SETUID */

        status = setuid(uid);
#endif

        if (status != 0) {
           se_log_error("setuid() for %s (%lu) failed: %s",
               username, (unsigned long) uid, strerror(errno));
           return -1;
        } else {
            se_log_debug("user set to %s (%lu)", username, (unsigned long) uid);
        }
    }

    return 0;
}
