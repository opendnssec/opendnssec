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

#include <map>
#include <fcntl.h>
#include <utility>

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "shared/duration.h"
#include "daemon/clientpipe.h"
#include "libhsm.h"
#include "db/hsm_key.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include "hsmkey/hsmkey.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include "hsmkey/backup_hsmkeys_cmd.h"

static const char *module_str = "backup_hsmkeys_cmd";

enum {
	PREPARE,
	COMMIT,
	ROLLBACK,
	LIST,
};

static void
prepare(int sockfd, hsm_key_list_t *hsmkey_list, hsm_key_t *rw_hsmkey)
{
	const hsm_key_t *ro_hsmkey;
	hsm_key_backup_t backup;
	int keys_marked = 0;

	ro_hsmkey = hsm_key_list_begin(hsmkey_list);
	while (ro_hsmkey) {
		backup = hsm_key_backup(ro_hsmkey);
		if (backup == HSM_KEY_BACKUP_BACKUP_REQUIRED) {
			if (hsm_key_copy(rw_hsmkey, ro_hsmkey)) {
				ods_log_error("[%s] err4", module_str);
				break;
			}
			if (hsm_key_set_backup(rw_hsmkey, HSM_KEY_BACKUP_BACKUP_REQUESTED) ||
				hsm_key_update(rw_hsmkey))
			{
				ods_log_error("[%s] err5", module_str);
			}
			hsm_key_reset(rw_hsmkey);
		}
		ro_hsmkey = hsm_key_list_next(hsmkey_list);
	}
	client_printf(sockfd,"info: keys flagged for backup: %d\n", keys_marked);
}

static void
commit(int sockfd, hsm_key_list_t *hsmkey_list, hsm_key_t *rw_hsmkey)
{
	const hsm_key_t *ro_hsmkey;
	hsm_key_backup_t backup;
	int keys_marked = 0;

	ro_hsmkey = hsm_key_list_begin(hsmkey_list);
	while (ro_hsmkey) {
		backup = hsm_key_backup(ro_hsmkey);
		if (backup == HSM_KEY_BACKUP_BACKUP_REQUESTED) {
			if (hsm_key_copy(rw_hsmkey, ro_hsmkey)) {
				ods_log_error("[%s] err4", module_str);
				break;
			}
			if (hsm_key_set_backup(rw_hsmkey, HSM_KEY_BACKUP_BACKUP_DONE) ||
				hsm_key_update(rw_hsmkey))
			{
				ods_log_error("[%s] err5", module_str);
			}
			hsm_key_reset(rw_hsmkey);
		}
		ro_hsmkey = hsm_key_list_next(hsmkey_list);
	}
	client_printf(sockfd,"info: keys flagged for backup: %d\n", keys_marked);
}

static void
rollback(int sockfd, hsm_key_list_t *hsmkey_list, hsm_key_t *rw_hsmkey)
{
	const hsm_key_t *ro_hsmkey;
	hsm_key_backup_t backup;
	int keys_marked = 0;

	ro_hsmkey = hsm_key_list_begin(hsmkey_list);
	while (ro_hsmkey) {
		backup = hsm_key_backup(ro_hsmkey);
		if (backup == HSM_KEY_BACKUP_BACKUP_REQUESTED) {
			if (hsm_key_copy(rw_hsmkey, ro_hsmkey)) {
				ods_log_error("[%s] err4", module_str);
				break;
			}
			if (hsm_key_set_backup(rw_hsmkey, HSM_KEY_BACKUP_BACKUP_REQUIRED) ||
				hsm_key_update(rw_hsmkey))
			{
				ods_log_error("[%s] err5", module_str);
			}
			hsm_key_reset(rw_hsmkey);
		}
		ro_hsmkey = hsm_key_list_next(hsmkey_list);
	}
	client_printf(sockfd,"info: keys flagged for backup: %d\n", keys_marked);
}

static void
list(int sockfd, hsm_key_list_t *hsmkey_list)
{
	const hsm_key_t *ro_hsmkey;
	hsm_key_backup_t backup;
	int keys_marked = 0;

	ro_hsmkey = hsm_key_list_begin(hsmkey_list);
	while (ro_hsmkey) {
		/*  TODO  */
		ro_hsmkey = hsm_key_list_next(hsmkey_list);
	}
	client_printf(sockfd,"info: keys flagged for backup: %d\n", keys_marked);
}

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

const char *
get_repo_param(const char *cmd, ssize_t n, char *buf, size_t buflen)
{
	const int NARGV = 8;
	const char *argv[NARGV];
	int argc;
	const char *repository = NULL;

	strncpy(buf, cmd, buflen);
	argc = ods_str_explode(buf, NARGV, argv);
	buf[sizeof(buf)-1] = '\0';
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
			module_str,cmd);
		return NULL;
	}
	(void)ods_find_arg_and_param(&argc, argv, "repository", "r",
		&repository);
	return repository; /* ptr in buf */
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	char buf[ODS_SE_MAXLINE];
	int status;
	hsm_key_list_t *hsmkey_list;
	hsm_key_t *rw_hsmkey;
	const char *repository;

	if (!handles(cmd, n)) return -1;
	repository = get_repo_param(cmd, n, buf, ODS_SE_MAXLINE);

	/* iterate the keys */
	if (!(hsmkey_list = hsm_key_list_new(dbconn))) {
		ods_log_error("[%s] err1", module_str);
		return 1;
	}
	if (!(rw_hsmkey = hsm_key_new(dbconn))) {
		hsm_key_list_free(hsmkey_list);
		ods_log_error("[%s] err2", module_str);
		return 1;
	}
	if (repository)
		status = hsm_key_list_get_by_repository(hsmkey_list, repository);
	else
		status = hsm_key_list_get(hsmkey_list);
	if (status) {
		hsm_key_list_free(hsmkey_list);
		hsm_key_free(rw_hsmkey);
		ods_log_error("[%s] err3", module_str);
		return 1;
	}
	
	/* Find out what we need to do */
	if (ods_check_command(cmd,n,"backup prepare"))
			prepare(sockfd, hsmkey_list, rw_hsmkey);
	else if (ods_check_command(cmd,n,"backup commit"))
			commit(sockfd, hsmkey_list, rw_hsmkey);
	else if (ods_check_command(cmd,n,"backup rollback"))
			rollback(sockfd, hsmkey_list, rw_hsmkey);
	else if (ods_check_command(cmd,n,"backup list"))
			list(sockfd, hsmkey_list);

	hsm_key_free(rw_hsmkey);
	hsm_key_list_free(hsmkey_list);
	return 0;
}

static struct cmd_func_block funcblock = {
	"backup", &usage, NULL, &handles, &run
};

struct cmd_func_block*
backup_funcblock(void)
{
	return &funcblock;
}
