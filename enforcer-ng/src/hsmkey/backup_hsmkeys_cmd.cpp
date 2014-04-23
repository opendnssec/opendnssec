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

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "hsmkey/backup_hsmkeys_task.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"

#include "hsmkey/backup_hsmkeys_cmd.h"

static const char *module_str = "backup_hsmkeys_cmd";


static void
usage(int sockfd)
{
	client_printf(sockfd,
		"backup list            Enumerate backup status of keys.\n"
		"      --repository <repository>  (aka -r)  Limit to this repository.\n");
	client_printf(sockfd,
		"backup prepare         Flag the keys found in all configured HSMs as to be \n"
		"                       backed up.\n"
		"      --repository <repository>  (aka -r)  Limit to this repository.\n");
	client_printf(sockfd,
		"backup commit          Mark flagged keys found in all configured HSMs as\n"
		"                       backed up.\n"
		"      --repository <repository>  (aka -r)  Limit to this repository.\n");
	client_printf(sockfd,
		"backup rollback        Cancel a 'backup prepare' action.\n"
		"      --repository <repository>  (aka -r)  Limit to this repository.\n");
}

static int
handles(const char *cmd, ssize_t n)
{
	if (ods_check_command(cmd, n, "backup prepare")) return 1;
	if (ods_check_command(cmd, n, "backup commit")) return 1;
	if (ods_check_command(cmd, n, "backup rollback")) return 1;
	if (ods_check_command(cmd, n, "backup list")) return 1;
	return 0;
}

static int
handled_backup_cmd(int sockfd, engine_type* engine, 
		const char *scmd, ssize_t n, 
		int task(int, engineconfig_type *, const char *))
{
	char buf[ODS_SE_MAXLINE];
    const int NARGV = 8;
    const char *argv[NARGV];
    int argc;
	const char *repository = NULL;

	ods_log_debug("[%s] %s command", module_str, scmd);

	// Use buf as an intermediate buffer for the command.
	strncpy(buf, scmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	// separate the arguments
	argc = ods_str_explode(buf, NARGV, argv);
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str,scmd);
		client_printf(sockfd,"too many arguments\n");
		return -1;
	}
	(void)ods_find_arg_and_param(&argc,argv,"repository","r",&repository);
	return task(sockfd,engine->config, repository);
}


static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	if (ods_check_command(cmd,n,"backup prepare")) {
		return handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_prepare);
	} else if (ods_check_command(cmd,n,"backup commit")) {
		return handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_commit);
	} else if (ods_check_command(cmd,n,"backup rollback")) {
		return handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_rollback);
	} else if (ods_check_command(cmd,n,"backup list")) {
		return handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_list);
	} else {
		return -1;
	}
}

static struct cmd_func_block funcblock = {
	"backup", &usage, NULL, &handles, &run
};

struct cmd_func_block*
backup_funcblock(void)
{
	return &funcblock;
}
