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
#include "daemon/cfg.h"
#include "parser/confparser.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/status.h"
#include "utils/kc_helper.h"
#include "daemon/engine.h"
#include "libhsm.h"

#include "update_repositorylist_task.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char *module_str = "update_repositorylist_task";

/* 0 succes, 1 error */
static int
validate_configfile(const char* cfgfile)
{
	char *kasp = NULL, *zonelist = NULL, **replist = NULL;
	int repcount;
	int cc_status = check_conf(cfgfile, &kasp, &zonelist, &replist, 
		&repcount, 0);
	free(kasp);
	free(zonelist);
	if (replist) for (int i = 0; i < repcount; i++) free(replist[i]);
	return cc_status;
}

int perform_update_repositorylist(int sockfd, engine_type* engine)
{
	const char* cfgfile = ODS_SE_CFGFILE;
	int status = 1;

	if (validate_configfile(cfgfile)) {
		ods_log_error_and_printf(sockfd, module_str,
			"Unable to validate '%s' consistency.", cfgfile);
		return 0;
	}
	
	/* key gen tasks must be stopped, hsm connections must be closed
	 * easiest way is to stop all workers,  */
	lock_basic_lock(&engine->signal_lock);
		/** we have got the lock, daemon thread is not going anywhere 
		 * we can safely stop all workers */
		engine_stop_workers(engine);
		struct engineconfig_repository *new_reps;
		new_reps = parse_conf_repositories(cfgfile);
		if (!new_reps) {
			/* revert */
			status = 0;
			ods_printf(sockfd, "Could not load new repositories. Will continue with old.\n");
		} else {
			/* succes */
			engine_config_freehsms(engine->config->hsm);
			engine->config->hsm = new_reps;
			engine->need_to_reload = 1;
			ods_printf(sockfd, "new repositories parsed successful.\n");
		}
		engine_start_workers(engine);
	lock_basic_unlock(&engine->signal_lock);
	/* kick daemon thread so it will reload the hsms */
	if (status) {
		lock_basic_alarm(&engine->signal_cond);
		/* as if nothing happend from daemon's POV */
		ods_printf(sockfd, "Notifying enforcer of new respositories.\n");
	}
	return status;
}

