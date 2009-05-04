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
 * Some general utility function for the OpenDNSSEC signing tools
 */

#include <stdio.h>
#include "util.h"

int
read_line(FILE *input, char *line)
{
	int i;
	
	char c;
	for (i = 0; i < MAX_LINE_LEN; i++) {
		c = getc(input);
		if (c == EOF) {
			return -1;
		} else if (c != '\n') {
			line[i] = c;
		} else {
			break;
		}
	}
	line[i] = '\0';
	return i;
}

/* frees all ldns_rr records in the list, and sets the count to 0 */
void
rr_list_clear(ldns_rr_list *rr_list) {
	size_t i;
	for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
		ldns_rr_free(ldns_rr_list_rr(rr_list, i));
	}
	ldns_rr_list_set_rr_count(rr_list, 0);
}

