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
#include "update_conf_task.h"

#include "config.h"
#include "daemon/cfg.h"
#include "parser/confparser.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/status.h"
#include "utils/kc_helper.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char *module_str = "update_repositorylist_task";

int perform_update_conf(int sockfd, engine_type* engine, 
	const char *cmd, ssize_t n)
{
	const char* cfgfile = ODS_SE_CFGFILE;
	char *kasp = NULL;
	char *zonelist = NULL;
	char **replist = NULL;
	int repcount, i;

	int cc_status = check_conf(cfgfile, &kasp, &zonelist, 
		&replist, &repcount, 0);
	free(kasp);
	free(zonelist);
	if (replist) {
		for (i = 0; i < repcount; i++) free(replist[i]);
	}
		
	if (cc_status) {
		ods_log_error_and_printf(sockfd, module_str,
			"Unable to validate '%s' consistency.", cfgfile);
		return 0;
	}
    engine->config->hsm = parse_conf_repositories(cfgfile);
	return 1;
}

