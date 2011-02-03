/*
 * $Id$
 *
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

#include "config.h"

#include <stdio.h>
#include <ldns/ldns.h>

#define SE_ADFILE_MAXLINE 65535

/**
 * Lookup SOA RR.
 * \param[in] fd file descriptor of zonefile
 * \return ldns_rr* SOA RR
 *
 */
ldns_rr* adfile_lookup_soa_rr(FILE* fd);

/**
 * Read one line from zonefile.
 * \param[in] fd file descriptor of zonefile
 * \param[out] line the one line
 * \param[out] l keeps track of line numbers
 * \return int number of characters read
 *
 */
int adfile_read_line(FILE* fd, char* line, unsigned int* l);

/*
 * Trim trailing whitespace.
 * \param[in] line line to be trimmed
 * \param[out] line_len maintain line length
 *
 */
void adfile_rtrim(char* line, int* line_len);

/**
 * Check for white space.
 * \param[in] line line to be checked
 * \param[in] line_len line length
 *
 */
int adfile_whitespace_line(char* line, int line_len);

