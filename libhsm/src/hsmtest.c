/*
 * $Id$
 *
 * Copyright (c) 2009 Nominet UK.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libhsm.h>

int
main (int argc, char *argv[])
{
	int result;
	hsm_ctx_t *ctx;
	hsm_key_t **keys;
	size_t key_count = 0;
	size_t i;
	
	(void) argc;
	(void) argv;
	fprintf(stdout, "Starting HSM lib test\n");
	result = hsm_open("/home/jelte/opt/opendnssec/etc/opendnssec/conf.xml", NULL, NULL);
	fprintf(stdout, "hsm_open result: %d\n", result);
	ctx = hsm_create_context();
	/*printf("global: ");
	hsm_print_ctx(NULL);
	printf("my: ");
	hsm_print_ctx(ctx);
	*/
	keys = hsm_list_keys(ctx, &key_count);
	printf("I have found %u keys\n", (unsigned int) key_count);
	for (i = 0; i < key_count; i++) {
		hsm_print_key(keys[i]);
		hsm_key_free(keys[i]);
	}
	free(keys);
	fprintf(stdout, "hsm_close result: %d\n", result);
	hsm_destroy_context(ctx);
	result = hsm_close();
	return 0;
}
