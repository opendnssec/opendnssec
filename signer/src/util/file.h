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
 * File access wrapper.
 */

#ifndef UTIL_FILE_H
#define UTIL_FILE_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/**
 * Convert file mode to readable string.
 * \param[in] mode file mode
 * \return const char* string
 *
 */
const char* se_file_mode2str(const char* mode);

/**
 * Get next character.
 * \param[in] fd file descriptor
 * \param[in] line_nr line number
 * \return int next character.
 *
 */
int se_fgetc(FILE* fd, unsigned int* line_nr);

/**
 * Skip white space.
 * \param[in] fd file descriptor
 * \param[in] line_nr line number
 * \return int first encountered non-whitespace character
 *
 */
int se_skip_whitespace(FILE* fd, unsigned int* line_nr);

/**
 * Construct file or directory name.
 * \param[in] file filename without extension
 * \param[in] suffix extension.
 * \param[in] dir directory or not
 * \return char* concatenation of file and suffix
 *
 */
char* se_build_path(const char* file, const char* suffix, int dir);

/**
 * Open a file.
 * \param[in] file filename.
 * \param[in] dir directory.
 * \param[in] mode file mode
 * \return FILE* file descriptor
 *
 */
FILE* se_fopen(const char* file, const char* dir, const char* mode);

/**
 * Close a file.
 * \param[in] fd the file descriptor
 *
 */
void se_fclose(FILE* fd);

/**
 * Write to file descriptor.
 * \param[in] fd file descriptor
 * \param[in] vptr pointer to data
 * \param[in] n size of data
 *
 */
ssize_t se_writen(int fd, const void* vptr, size_t n);

/**
 * Get file status.
 * \param[in] file file name
 * \return time_t last modified
 *
 */
time_t se_file_lastmodified(const char* file);

/**
 * Compare strings.
 * \param[in] s1 one string
 * \param[in] s2 another string
 * \return -1, 0 or 1
 *
 */
int se_strcmp(const char* s1, const char* s2);

/**
 * Get directory part of filename.
 * \param[in] file file name
 * \return char* directory part
 *
 */
char* se_dir_name(const char* file);

/**
 * Copy file.
 * \param[in] file1 from file name
 * \param[in] file2 to file name
 * \return 0 on success, 1 on error
 *
 */
int se_file_copy(const char* file1, const char* file2);

/**
 * (Create) and change ownership of directories.
 * \param[in] file file name
 * \param[in] uid user id
 * \param[in] gid group id
 * \param[in] getdir fetch directory part
 *
 */
void se_chown(const char* file, uid_t uid, gid_t gid, int getdir);


/**
 * Remove leading and trailing whitespace.
 * \param[in] str string to trim
 *
 */
void se_str_trim(char* str);

#endif /* UTIL_FILE_H */
