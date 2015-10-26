/*
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
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
 *
 */

#include "config.h"

#include "daemon/engine.h"
#include "daemon/cmdhandler.h"
#include "enforcer/enforce_task.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "db/key_data.h"
#include "keystate/keystate_ds.h"

#include "keystate/keystate_ds_seen_cmd.h"

static const char *module_str = "key_ds_seen_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key ds-seen            Issue a ds-seen to the enforcer for a KSK.\n"
		"                       (This command with no parameters lists eligible keys.)\n"
		"      --zone <zone>              (aka -z)  zone.\n"
		"      --keytag <keytag> | --cka_id <CKA_ID>      (aka -x | -k)\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_ds_seen_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	char* buf;
	const char* argv[6];
	int argc;
	zone_t* zone;
	const char* zone_name = NULL;
	const char* keytag = NULL;
	const char* ckaid = NULL;

	cmd = ods_check_command(cmd, n, key_ds_seen_funcblock()->cmdname);

	if (!(buf = strdup(cmd))) {
        	client_printf_err(sockfd, "memory error\n");
	        return -1;
    	}

	argc = ods_str_explode(buf, 6, argv);
	if (argc > 6) {
		client_printf_err(sockfd, "too many arguments\n");
		free(buf);
		return -1;
	}

	ods_find_arg_and_param(&argc, argv, "zone", "z", &zone_name);
	ods_find_arg_and_param(&argc, argv, "keytag", "x", &keytag);
	ods_find_arg_and_param(&argc, argv, "cka_id", "k", &ckaid);

	if (argc) {
        	client_printf_err(sockfd, "unknown arguments\n");
	        free(buf);
	        return -1;
	}

	if (zone_name && (!(zone = zone_new(dbconn)) || zone_get_by_name(zone, zone_name))) {
		ods_log_warning ("[%s] Error: Unable to find a zone named \"%s\" in database\n", module_str, zone_name);
	        client_printf(sockfd, "Error: Unable to find a zone named \"%s\" in database\n", zone_name);
		zone_free(zone);
		zone = NULL;
        	return -1;
	}

        if (!zone_name && (keytag || ckaid)) {
                ods_log_warning ("[%s] Error: expected --zone <zone>", module_str);
                client_printf_err(sockfd, "Error: expected --zone <zone>\n");
                free(buf);
                return -1;
        }

	if (zone_name && !keytag && !ckaid) {
		ods_log_warning ("[%s] Error: expected --keytag OR --cka_id", module_str);
	        client_printf_err(sockfd, "Error: expected --keytag <keytag> OR --cka_id <CKA_ID>\n");
        	free(buf);
	        return -1;
	}

	int error;
	error = run_ds_cmd(sockfd, cmd, n, dbconn,
		KEY_DATA_DS_AT_PARENT_SUBMITTED,
		KEY_DATA_DS_AT_PARENT_SEEN, engine);
	if (error == 0) {
		flush_enforce_task(engine, 1);
	}
	return error;

}

static struct cmd_func_block funcblock = {
	"key ds-seen", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_ds_seen_funcblock(void)
{
	return &funcblock;
}
