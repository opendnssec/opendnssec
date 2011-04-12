/*
 * $Id$
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 * String utilities
 */

#include "config.h"
#include "shared/str.h"
#include "shared/log.h"

#include <errno.h>
#include <stdio.h> /* snprintf() */
#include <string.h> /* strlen(), strcpy() */

/**
 * Join arguments together with a join character into a single string.
 *
 */
char *
ods_str_join(allocator_type* allocator, int argc, char *argv[], char cjoin)
{
    char* buf = NULL;
    int c;
    int options_size = 0;
    for (c = 0; c < argc; ++c)
		options_size += strlen(argv[c]) + 1;
    if (options_size > 0) {
        buf = (char*) allocator_alloc(allocator, (options_size+1) * sizeof(char));
		/*	allocator_alloc will terminate on memory allocation
		 *	problems, so buf is always assigned when we get here.
		 */

		options_size = 0;
		for (c = 0; c < argc; ++c) {
			(void)strcpy(&buf[options_size], argv[c]);
			options_size += strlen(argv[c])+1;
			buf[options_size-1] = cjoin; /* put join character instead of 0 */
		}
		buf[options_size-1] = '\0'; /* replace join character with 0 */
		buf[options_size] = '\0'; /* set last character in buf to 0 */
    }
	return buf;
}
