/*
 * Copyright (c) 2009-2011 NLNet Labs. All rights reserved.
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
 * Adapter utilities.
 */

#ifndef ADAPTER_ADUTIL_H
#define ADAPTER_ADUTIL_H

#include "config.h"

#include <stdio.h>
#include <ldns/ldns.h>

#define SE_ADFILE_MAXLINE 65535

/**
 * Read one line from file.
 * \param[in] fd file descriptor of zonefile
 * \param[out] line the one line
 * \param[out] l keeps track of line numbers
 * \param[in] keep_comments if true, keep comments
 * \return int number of characters read
 *
 */
extern int adutil_readline_frm_file(FILE* fd, char* line, unsigned int* l,
    int keep_comments);

/*
 * Trim trailing whitespace.
 * \param[in] line line to be trimmed
 * \param[out] line_len maintain line length
 *
 */
extern void adutil_rtrim_line(char* line, int* line_len);

/**
 * Check for white space.
 * \param[in] line line to be checked
 * \param[in] line_len line length
 *
 */
extern int adutil_whitespace_line(char* line, int line_len);

#endif /* ADAPTER_ADUTIL_H */
