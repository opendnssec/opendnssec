/*
 * $Id$
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 * File access.
 */

#include "config.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <errno.h>
#include <stdio.h> /* fgetc(), fopen(), fclose(), ferror() */
#include <stdlib.h> /* system() */
#include <string.h> /* strlen(), strncmp(), strncat(), strncpy(), strerror() */
#include <sys/stat.h> /* stat() */
#include <unistd.h> /* chown() */

#define SYSTEM_MAXLEN 255


/**
 * Convert file mode to readable string.
 *
 */
const char*
se_file_mode2str(const char* mode)
{
    se_log_assert(mode);

    if (se_strcmp(mode, "a") == 0) {
        return "appending";
    } else if (se_strcmp(mode, "r") == 0) {
        return "reading";
    } else if (se_strcmp(mode, "w") == 0) {
        return "writing";
	}
    return "unknown mode";
}


/**
 * Get next char.
 *
 */
int
se_fgetc(FILE* fd, unsigned int* line_nr)
{
    int c;

    se_log_assert(fd);
    se_log_assert(line_nr);

    c = fgetc(fd);
	if (c == '\n') {
        (*line_nr)++;
    }
    return c;
}


/**
 * Skip white space.
 *
 */
int
se_skip_whitespace(FILE* fd, unsigned int* line_nr)
{
    int c;

    se_log_assert(fd);
    se_log_assert(line_nr);

    while ((c=se_fgetc(fd, line_nr)) != EOF) {
        if (c == ' ' || c == '\t' || c == '\r') {
            continue;
        }
        return c;
    }
    return EOF;
}


/**
 * Construct file name. (StrAppend?, snprintf?)
 *
 */
char*
se_build_path(const char* file, const char* suffix, int dir)
{
    size_t len_file = 0;
    size_t len_suffix = 0;
    size_t len_total = 0;
    char* openf = NULL;

    if (file) {
        len_file = strlen(file);
    }
    if (suffix) {
        len_suffix = strlen(suffix);
    }
    len_total = len_suffix + len_file;
    if (dir) {
        len_total++;
    }
    if (len_total > 0) {
        openf = (char*) se_malloc(sizeof(char)*(len_total + 1));
        strncpy(openf, file, len_file);
        openf[len_file] = '\0';
        strncat(openf, suffix, len_suffix);
        if (dir) {
            strncat(openf, "/", 1);
        }
        openf[len_total] = '\0';
    }

    return openf;
}


/**
 * Open a file.
 *
 */
FILE*
se_fopen(const char* file, const char* dir, const char* mode)
{
    FILE* fd = NULL;
    size_t len_file = 0;
    size_t len_dir = 0;
    size_t len_total = 0;
    char* openf = NULL;

    se_log_assert(mode);
    se_log_debug("open file: dir %s file %s for %s", dir, file,
        se_file_mode2str(mode));

	if (dir) {
        len_dir= strlen(dir);
    }
    if (file) {
        len_file= strlen(file);
    }
    len_total = len_dir + len_file;
    if (len_total > 0) {
        openf = (char*) se_malloc(sizeof(char)*(len_total + 1));
        strncpy(openf, dir, len_dir);
        openf[len_dir] = '\0';
        strncat(openf, file, len_file);
        openf[len_total] = '\0';

        if (len_file) {
            fd = fopen(openf, mode);
            if (!fd) {
                se_log_error("unable to open file '%s' for %s: %s",
                    openf, se_file_mode2str(mode), strerror(errno));
            }
        }
        se_free((void*) openf);
    }
    return fd;
}

/**
 * Close a file.
 *
 */
void
se_fclose(FILE* fd)
{
    if (fd) {
        fclose(fd);
    }
    return;
}


/**
 * Write to file descriptor.
 *
 */
ssize_t
se_writen(int fd, const void* vptr, size_t n)
{
    size_t nleft;
    ssize_t nwritten;
    const char* ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ((nwritten = write(fd, ptr, nleft)) <= 0) {
            if (nwritten < 0 && errno == EINTR) {
                nwritten = 0; /* and call write again */
            } else {
                return -1; /* error */
            }
        }
        nleft -= nwritten;
        ptr += nwritten;
    }
    return n;
}


/**
 * Get file last modified.
 *
 */
time_t
se_file_lastmodified(const char* file)
{
    int ret;
    struct stat buf;
    FILE* fd;

    se_log_assert(file);

    if ((fd = se_fopen(file, NULL, "r")) != NULL) {
        ret = stat(file, &buf);
        se_fclose(fd);
        return buf.st_mtime;
    }
    return 0;
}


/**
 * Compare strings.
 *
 */
int
se_strcmp(const char* s1, const char* s2)
{
    if (!s1 && !s2) {
        return 0;
    } else if (!s1) {
        return -1;
    } else if (!s2) {
        return -1;
    } else if (strlen(s1) != strlen(s2)) {
        if (strncmp(s1, s2, strlen(s1)) == 0) {
            return strlen(s1) - strlen(s2);
        }
    }
    return strncmp(s1, s2, strlen(s1));
}


/**
 * File copy.
 *
 */
int
se_file_copy(const char* file1, const char* file2)
{
    char str[SYSTEM_MAXLEN];

    se_log_assert(file1);
    se_log_assert(file2);

    snprintf(str, SYSTEM_MAXLEN, "cp %s %s", file1, file2);
    se_log_debug("system call: %s", str);
    return system(str);
}

/**
 * Get directory part of filename.
 *
 */
char*
se_dir_name(const char* file) {
    int l = strlen(file);
    char* dir = NULL;

    se_log_assert(file);

    /* find seperator */
    while (l>0 && strncmp(file + (l-1), "/", 1) != 0) {
        l--;
    }

    /* now strip off (multiple seperators) */
    while (l>0 && strncmp(file + (l-1), "/", 1) == 0) {
        l--;
    }

    if (l) {
        dir = (char*) se_calloc(l+1, sizeof(char));
        dir = strncpy(dir, file, l);
        return dir;
    }
    return NULL;
}

/**
 * (Create) and change ownership of directories
 *
 */
void
se_chown(const char* file, uid_t uid, gid_t gid, int getdir)
{
    char* dir = NULL;

    if (!getdir) {
        se_log_debug("create and chown directory %s [user %ld] [group %ld]",
           file, (signed long) uid, (signed long) gid);
        if (chown(file, uid, gid) != 0) {
            se_log_error("chown() for %s failed: %s", file, strerror(errno));
        }
    } else if ((dir = se_dir_name(file)) != NULL) {
        se_log_debug("create and chown directory %s [user %ld] [group %ld]",
           dir, (signed long) uid, (signed long) gid);
        if (chown(dir, uid, gid) != 0) {
            se_log_error("chown() for %s failed: %s", dir, strerror(errno));
        }
        se_free((void*) dir);
    } else {
        se_log_warning("use of relative path: %s", file);
    }
    return;
}


/**
 * Remove leading and trailing whitespace.
 *
 */
void
se_str_trim(char* str)
{
    int i = strlen(str), nl = 0;

    /* trailing */
    while (i>0) {
        --i;
        if (str[i] == '\n') {
            nl = 1;
        }
        if (str[i] == ' ' || str[i] == '\t' || str[i] == '\n') {
            str[i] = '\0';
        } else {
            break;
        }
    }
    if (nl) {
        str[++i] = '\n';
    }

    /* leading */
    i = 0;
    while (str[i] == ' ' || str[i] == '\t') {
        i++;
    }
    while (*(str+i) != '\0') {
        *str = *(str+i);
        str++;
    }
    *str = '\0';
    return;
}
