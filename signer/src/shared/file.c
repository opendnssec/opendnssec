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
#include "shared/file.h"
#include "shared/log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char* file_str = "file";


/**
 * Convert file mode to readable string.
 *
 */
const char*
ods_file_mode2str(const char* mode)
{
    if (!mode) {
        return "no mode";
    }

    if (ods_strcmp(mode, "a") == 0) {
        return "appending";
    } else if (ods_strcmp(mode, "r") == 0) {
        return "reading";
    } else if (ods_strcmp(mode, "w") == 0) {
        return "writing";
	}
    return "unknown mode";
}


/**
 * Get next char.
 *
 */
int
ods_fgetc(FILE* fd, unsigned int* line_nr)
{
    int c;

    ods_log_assert(fd);
    ods_log_assert(line_nr);

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
ods_skip_whitespace(FILE* fd, unsigned int* line_nr)
{
    int c;

    ods_log_assert(fd);
    ods_log_assert(line_nr);

    while ((c=ods_fgetc(fd, line_nr)) != EOF) {
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
ods_build_path(const char* file, const char* suffix, int dir)
{
    size_t len_file = 0;
    size_t len_suffix = 0;
    size_t len_total = 0;
    char* openf = NULL;

    if (file) {
        len_file = strlen(file);
        if (suffix) {
            len_suffix = strlen(suffix);
        }
        len_total = len_suffix + len_file;
        if (dir) {
            len_total++;
        }

        if (len_total > 0) {
            openf = (char*) malloc(sizeof(char)*(len_total + 1));
            if (!openf) {
                ods_log_crit("[%s] build path failed: malloc failed", file_str);
                return NULL;
            }

            strncpy(openf, file, len_file);
            openf[len_file] = '\0';
            if (suffix) {
                strncat(openf, suffix, len_suffix);
            }
            if (dir) {
                strncat(openf, "/", 1);
            }
            openf[len_total] = '\0';
        }
    }

    return openf;
}


/**
 * Open a file.
 *
 */
FILE*
ods_fopen(const char* file, const char* dir, const char* mode)
{
    FILE* fd = NULL;
    size_t len_file = 0;
    size_t len_dir = 0;
    size_t len_total = 0;
    char* openf = NULL;

    ods_log_assert(mode);
    ods_log_debug("[%s] open file %s%s file=%s mode=%s", file_str,
        (dir?"dir=":""), (dir?dir:""), (file?file:"(null)"),
        ods_file_mode2str(mode));

    if (dir) {
        len_dir= strlen(dir);
    }
    if (file) {
        len_file= strlen(file);
    }
    len_total = len_dir + len_file;
    if (len_total > 0) {
        openf = (char*) malloc(sizeof(char)*(len_total + 1));
        if (!openf) {
            return NULL;
        }
        if (dir) {
           strncpy(openf, dir, len_dir);
           openf[len_dir] = '\0';
           if (file) {
               strncat(openf, file, len_file);
           }
        } else if (file) {
           strncpy(openf, file, len_file);
        }
        openf[len_total] = '\0';

        if (len_file) {
            fd = fopen(openf, mode);
            if (!fd) {
                ods_log_verbose("[%s] unable to open file %s for %s: %s",
                    file_str, openf?openf:"(null)",
                    ods_file_mode2str(mode), strerror(errno));
            }
        }
        free((void*) openf);
    }
    return fd;
}

/**
 * Close a file.
 *
 */
void
ods_fclose(FILE* fd)
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
ods_writen(int fd, const void* vptr, size_t n)
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
ods_file_lastmodified(const char* file)
{
    int ret;
    struct stat buf;
    FILE* fd;

    ods_log_assert(file);

    if ((fd = ods_fopen(file, NULL, "r")) != NULL) {
        ret = stat(file, &buf);
        ods_fclose(fd);
        return buf.st_mtime;
    }
    return 0;
}


/**
 * Compare strings.
 *
 */
int
ods_strcmp(const char* s1, const char* s2)
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
 * Replace a substring in string.
 *
 */
const char*
ods_replace(const char *str, const char *oldstr, const char *newstr)
{
    char* buffer = NULL;
    char* ch = NULL;
    size_t part1_len = 0;
    size_t part2_len = 0;
    size_t part3_len = 0;

    if (!str) {
       return NULL;
    }
    if (!oldstr || !newstr) {
       return str;
    }

    if (!(ch = strstr(str, oldstr))) {
        buffer = strdup(str);
        return buffer;
    }

    part1_len = ch-str;
    part2_len = strlen(newstr);
    part3_len = strlen(ch+strlen(oldstr));
    buffer = calloc(part1_len+part2_len+part3_len+1, sizeof(char));
    if (!buffer) {
        return NULL;
    }

    if (part1_len) {
        strncpy(buffer, str, part1_len);
        buffer[part1_len] = '\0';

        if (part2_len) {
            strncat(buffer, str, part2_len);
            buffer[part1_len+part2_len] = '\0';
        }
    } else {
        strncpy(buffer, newstr, part2_len);
        buffer[part2_len] = '\0';
    }

    if (part3_len) {
        strncat(buffer, ch+strlen(oldstr), part3_len);
        buffer[part1_len+part2_len+part3_len] = '\0';
    }

    buffer[ch-str] = '\0';
    snprintf(buffer+(ch-str), SYSTEM_MAXLEN, "%s%s", newstr, ch+strlen(oldstr));
    return buffer;
}


/**
 * File copy.
 *
 */
int
ods_file_copy(const char* file1, const char* file2)
{
    char str[SYSTEM_MAXLEN];
    FILE* fd = NULL;

    if (!file1 || !file2) {
        return 1;
    }

    if ((fd = ods_fopen(file1, NULL, "r")) != NULL) {
        ods_fclose(fd);
        snprintf(str, SYSTEM_MAXLEN, "%s %s %s > /dev/null",
            CP_COMMAND, file1, file2);
        ods_log_debug("system call: %s", str);
        return system(str);
    }
    /* no such file */
    return 1;
}

/**
 * Get directory part of filename.
 *
 */
char*
ods_dir_name(const char* file) {
    int l = strlen(file);
    char* dir = NULL;

    ods_log_assert(file);

    /* find seperator */
    while (l>0 && strncmp(file + (l-1), "/", 1) != 0) {
        l--;
    }

    /* now strip off (multiple seperators) */
    while (l>0 && strncmp(file + (l-1), "/", 1) == 0) {
        l--;
    }

    if (l) {
        dir = (char*) calloc(l+1, sizeof(char));
        if (dir) {
            dir = strncpy(dir, file, l);
        }
        return dir;
    }
    return NULL;
}

/**
 * (Create) and change ownership of directories
 *
 */
void
ods_chown(const char* file, uid_t uid, gid_t gid, int getdir)
{
    char* dir = NULL;

    if (!file) {
        ods_log_warning("[%s] no filename given for chown()", file_str);
        return;
    }

    if (!getdir) {
        ods_log_debug("[%s] create and chown %s with user=%ld group=%ld",
           file_str, file, (signed long) uid, (signed long) gid);
        if (chown(file, uid, gid) != 0) {
            ods_log_error("[%s] chown() %s failed: %s", file_str, file,
                strerror(errno));
        }
    } else if ((dir = ods_dir_name(file)) != NULL) {
        ods_log_debug("[%s] create and chown %s with user=%ld group=%ld",
            file_str, dir, (signed long) uid, (signed long) gid);
        if (chown(dir, uid, gid) != 0) {
            ods_log_error("[%s] chown() %s failed: %s", file_str,
                dir, strerror(errno));
        }
        free((void*) dir);
    } else {
        ods_log_warning("[%s] use of relative path: %s", file_str, file);
    }
    return;
}


/**
 * Remove leading and trailing whitespace.
 *
 */
void
ods_str_trim(char* str)
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
