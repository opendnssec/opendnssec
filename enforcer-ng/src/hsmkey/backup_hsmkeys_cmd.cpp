/*
 * $Id$
 *
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

#include <ctime>
#include <iostream>
#include <cassert>

#include "hsmkey/hsmkey.pb.h"

#include "hsmkey/backup_hsmkeys_cmd.h"
#include "hsmkey/backup_hsmkeys_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

static const char *module_str = "backup_hsmkeys_cmd";


void
help_backup_cmd(int sockfd)
{
	ods_printf(sockfd,
		       "backup list            Enumerate backup status of keys.\n"
		       "      --repository <repository>  (aka -r)  Limit to this repository.\n");
	ods_printf(sockfd,
		       "backup prepare         Flag the keys found in all configured HSMs as to be \n"
			   "                       backed up.\n"
		       "      --repository <repository>  (aka -r)  Limit to this repository.\n");
	ods_printf(sockfd,
		       "backup commit          Mark flagged keys found in all configured HSMs as\n"
			   "                       backed up.\n"
		       "      --repository <repository>  (aka -r)  Limit to this repository.\n");
	ods_printf(sockfd,
		       "backup rollback        Cancel a 'backup prepare' action.\n"
		       "      --repository <repository>  (aka -r)  Limit to this repository.\n");
}

static int
handled_backup_cmd(int sockfd, engine_type* engine, 
		const char *scmd, ssize_t n, 
		void task(int, engineconfig_type *, const char *)) {
	char buf[ODS_SE_MAXLINE];
    const char *argv[8];
    const int NARGV = sizeof(argv)/sizeof(char*);
    int argc;
	const char *repository = NULL;

	ods_log_debug("[%s] %s command", module_str, scmd);

	// Use buf as an intermediate buffer for the command.
	strncpy(buf,scmd,sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	// separate the arguments
	argc = ods_str_explode(buf,NARGV,argv);
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str,scmd);
		ods_printf(sockfd,"too many arguments\n");
		help_backup_cmd(sockfd);
		return 1; // errors, but handled
	}
	(void)ods_find_arg_and_param(&argc,argv,"repository","r",&repository);

	time_t tstart = time(NULL);
	task(sockfd,engine->config, repository);
	ods_printf(sockfd,"%s completed in %ld seconds.\n",
		scmd,time(NULL)-tstart);
	return 1;
}


int
handled_backup_cmds(int sockfd, engine_type* engine, 
		const char *cmd, ssize_t n)
{
	int res;
	       if (ods_check_command(cmd,n,"backup prepare")) {
		res = handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_prepare);
	} else if (ods_check_command(cmd,n,"backup commit")) {
		res = handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_commit);
	} else if (ods_check_command(cmd,n,"backup rollback")) {
		res = handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_rollback);
	} else if (ods_check_command(cmd,n,"backup list")) {
		res = handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_list);
	} else {
		return 0;
	}
	return res;
}
