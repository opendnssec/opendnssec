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

#include "enforcer/update_all_cmd.h"
#include "enforcer/setup_cmd.h"
#include "enforcer/autostart_cmd.h"
#include "enforcer/update_repositorylist_task.h"

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
#include "utils/kc_helper.h"


#include "policy/update_kasp_task.h"
#include "policy/kasp.pb.h"

#include "keystate/update_keyzones_task.h"
#include "keystate/keystate.pb.h"

#include "hsmkey/update_hsmkeys_task.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "hsmkey/hsmkey.pb.h"




static const char *module_str = "update_all_cmd";

void help_update_all_cmd(int sockfd)
{
	ods_printf(sockfd,
	           "update all             Perform update kasp, zonelist and repositorylist.\n"
	);
}

int
handled_update_all_cmd(int sockfd, engine_type* engine, const char *cmd,
	ssize_t n)
{
	const char *scmd = "update all";
	cmd = ods_check_command(cmd,n,scmd);
	if (!cmd) return 0; // not handled
	ods_log_debug("[%s] %s command", module_str, scmd);

	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	time_t tstart = time(NULL);

	autostart(engine);

	/* Check all files for errors. The perform_update_*()
	 * functions check as well but this gives us all or nothing.
	 * Plus we get a complete check of the files mentioned in the 
	 * conf which need not be the same as the files in use by the 
	 * running enforcer!*/
	char *kasp = NULL;
	char *zonelist = NULL;
	char **replist = NULL;
	int repcount, i;
	int error = 1;
	if (check_conf(engine->config->cfg_filename, &kasp, 
			&zonelist, &replist, &repcount, 0))
		ods_log_error_and_printf(sockfd, module_str, 
			"Unable to validate '%s' consistency.", 
			engine->config->cfg_filename);
	else if (check_kasp(kasp, replist, repcount, 0))
		ods_log_error_and_printf(sockfd, module_str, 
			"Unable to validate '%s' consistency.", kasp);
	else if (check_zonelist(zonelist, 0))
		ods_log_error_and_printf(sockfd, module_str, 
			"Unable to validate '%s' consistency.", zonelist);
	else error = 0;
	
	free(kasp);
	free(zonelist);
	if (replist) {
		for (i = 0; i < repcount; i++) free(replist[i]);
	}

	if (!error) 
		error |= perform_update_repositorylist(sockfd, engine);
	if (!error) 
		error |= perform_update_kasp(sockfd, engine->config);
	if (!error) 
		error |= perform_update_keyzones(sockfd, engine->config);
	if (!error) {
		perform_update_hsmkeys(sockfd, engine->config, 0 /* automatic */);
		perform_hsmkey_gen(sockfd, engine->config, 0 /* automatic */,
						   engine->config->automatic_keygen_duration);
		flush_all_tasks(sockfd, engine);
	}
	ods_printf(sockfd, "%s completed in %ld seconds.\n",scmd,time(NULL)-tstart);
	return 1;
}


