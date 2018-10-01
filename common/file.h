/*
 * Copyright (c) 2009-2018 NLNet Labs.
 * All rights reserved.
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
 */

/**
 *
 * File access wrapper.
 */

#ifndef SHARED_FILE_H
#define SHARED_FILE_H

#include "config.h"
#include "status.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#define SYSTEM_MAXLEN 1024

/**
 * Convert file mode to readable string.
 * \param[in] mode file mode
 * \return const char* string
 *
 */
const char* ods_file_mode2str(const char* mode);

/**
 * Get next character.
 * \param[in] fd file descriptor
 * \param[in] line_nr line number
 * \return int next character.
 *
 */
int ods_fgetc(FILE* fd, unsigned int* line_nr);

/**
 * Construct file or directory name.
 * \param[in] file filename without extension
 * \param[in] suffix extension.
 * \param[in] dir directory or not
 * \param[in] no_slash no forward slashes and such characters allowed
 * \return char* concatenation of file and suffix
 *
 */
char* ods_build_path(const char* file, const char* suffix, int dir,
    int no_slash);

/**
 * Open a file.
 * \param[in] file filename.
 * \param[in] dir directory.
 * \param[in] mode file mode
 * \return FILE* file descriptor
 *
 */
FILE* ods_fopen(const char* file, const char* dir, const char* mode);

/**
 * Close a file.
 * \param[in] fd the file descriptor
 *
 */
void ods_fclose(FILE* fd);

/**
 * Write to file descriptor.
 * \param[in] fd file descriptor
 * \param[in] vptr pointer to data
 * \param[in] n size of data
 *
 */
ssize_t ods_writen(int fd, const void* vptr, size_t n);

/**
 * Write string to file descriptor followed by newline
 * \return bytes written, -1 on failure.
 *
 */
ssize_t ods_writeln(int fd, char const *str);

/**
 * Combined error logging and writing to file descriptor.
 * \param[in] fd file descriptor
 * \param[in] mod module name to report in the error
 * \param[in] format pointer to C format string
 * \param[in] ... parameters to be expanded in format string
 *
 */
void ods_log_error_and_printf(int fd, const char *mod, const char *format, ...);
	
/**
 * Get file status.
 * \param[in] file file name
 * \return time_t last modified
 *
 */
time_t ods_file_lastmodified(const char* file);

/**
 * Compare strings.
 * \param[in] s1 one string
 * \param[in] s2 another string
 * \return -1, 0 or 1
 *
 */
int ods_strcmp(const char* s1, const char* s2);

/**
 * Compare strings lowercased.
 * \param[in] s1 one string
 * \param[in] s2 another string
 * \return -1, 0 or 1
 *
 */
int ods_strlowercmp(const char* s1, const char* s2);

/**
 * Replace a substring in string.
 * \param[in] str The string
 * \param[in] oldstr old substring
 * \param[in] newstr new substring
 * \return char* the substituted string.
 *
 */
const char* ods_replace(const char *str, const char *oldstr,
    const char *newstr);

/**
 * Get directory part of filename.
 * \param[in] file file name
 * \return char* directory part
 *
 */
char* ods_dir_name(const char* file);

/**
 * Copy file.
 * \param[in] file1 from file name
 * \param[in] file2 to file name
 * \param[in] startpos starting file position in file1
 * \param[in] append whether to append or do a regular copy
 * \return ods_status
 *
 */
ods_status ods_file_copy(const char* file1, const char* file2, long startpos,
    int append);

/**
 * (Create) and change ownership of directories.
 * \param[in] file file name
 * \param[in] uid user id
 * \param[in] gid group id
 * \param[in] getdir fetch directory part
 *
 */
void ods_chown(const char* file, uid_t uid, gid_t gid, int getdir);


/**
 * Add a string to a list of strings. Taken from ods-enforcer.
 * \param[out] list string list
 * \param[in] str string to add
 *
 */
void ods_str_list_add(char*** list, char* str);

#endif /* SHARED_FILE_H */
