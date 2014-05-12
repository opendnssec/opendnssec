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
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "shared/duration.h"
#include "daemon/clientpipe.h"
#include "libhsm.h"
#include "db/hsm_key.h"

#include "hsmkey/backup_hsmkeys_cmd.h"

static const char *module_str = "backup_hsmkeys_cmd";

enum {
	PREPARE,
	COMMIT,
	ROLLBACK,
	LIST
};

static int
hsmkeys_from_to_state(db_connection_t *dbconn, db_clause_list_t* clause_list,
    hsm_key_backup_t from_state, hsm_key_backup_t to_state)
{
    hsm_key_list_t* hsmkey_list;
    hsm_key_t *hsmkey;
    int keys_marked = 0;

    if (!hsm_key_backup_clause(clause_list, from_state)
        || !(hsmkey_list = hsm_key_list_new_get_by_clauses(dbconn, clause_list)))
    {
        ods_log_error("[%s] database error", module_str);
        return -1;
    }

    while ((hsmkey = hsm_key_list_get_next(hsmkey_list))) {
        if (hsm_key_set_backup(hsmkey, to_state) ||
            hsm_key_update(hsmkey))
        {
            ods_log_error("[%s] database error", module_str);
            hsm_key_free(hsmkey);
            hsm_key_list_free(hsmkey_list);
            return -1;
        }
        keys_marked++;
        hsm_key_free(hsmkey);
    }
    hsm_key_free(hsmkey);
    hsm_key_list_free(hsmkey_list);

    return keys_marked;
}

static int
prepare(int sockfd, db_connection_t *dbconn, db_clause_list_t* clause_list)
{
    int keys_marked = hsmkeys_from_to_state(dbconn, clause_list,
        HSM_KEY_BACKUP_BACKUP_REQUIRED, HSM_KEY_BACKUP_BACKUP_REQUESTED);
    if (keys_marked < 0) {
        return 1;
    }
	client_printf(sockfd,"info: keys flagged for backup: %d\n", keys_marked);
	return 0;
}

static int
commit(int sockfd, db_connection_t *dbconn, db_clause_list_t* clause_list)
{
    int keys_marked = hsmkeys_from_to_state(dbconn, clause_list,
        HSM_KEY_BACKUP_BACKUP_REQUESTED, HSM_KEY_BACKUP_BACKUP_DONE);
    if (keys_marked < 0) {
        return 1;
    }
    client_printf(sockfd,"info: keys marked backup done: %d\n", keys_marked);
    return 0;
}

static int
rollback(int sockfd, db_connection_t *dbconn, db_clause_list_t* clause_list)
{
    int keys_marked = hsmkeys_from_to_state(dbconn, clause_list,
        HSM_KEY_BACKUP_BACKUP_REQUESTED, HSM_KEY_BACKUP_BACKUP_REQUIRED);
    if (keys_marked < 0) {
        return 1;
    }
    client_printf(sockfd,"info: keys unflagged for backup: %d\n", keys_marked);
    return 0;
}

static int
list(int sockfd, db_connection_t *dbconn, db_clause_list_t* clause_list)
{
    hsm_key_list_t* hsmkey_list;
    const hsm_key_t *hsmkey;

    if (!(hsmkey_list = hsm_key_list_new_get_by_clauses(dbconn, clause_list))) {
        ods_log_error("[%s] database error", module_str);
        return -1;
    }

    /* TODO: Header */
    for (hsmkey = hsm_key_list_next(hsmkey_list); hsmkey;
        hsmkey = hsm_key_list_next(hsmkey_list))
    {
        /* TODO: propper output */
        client_printf(sockfd, "%s\n", hsm_key_locator(hsmkey));
    }
    hsm_key_list_free(hsmkey_list);
	return 0;
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
	#define NARGV 8
	const char *argv[NARGV];
	int argc;
	const char *repository = NULL;
	(void)n;

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
	const char *repository;
	db_clause_list_t* clause_list;
	(void)engine;

	if (!handles(cmd, n)) return -1;
	repository = get_repo_param(cmd, n, buf, ODS_SE_MAXLINE);

	/* iterate the keys */
	if (!(clause_list = db_clause_list_new())) {
		ods_log_error("[%s] database error", module_str);
		return 1;
	}
	if (repository && !hsm_key_repository_clause(clause_list, repository)) {
	    db_clause_list_free(clause_list);
        ods_log_error("[%s] Could not get key list", module_str);
        return 1;
	}
	
	/* Find out what we need to do */
	if (ods_check_command(cmd,n,"backup prepare"))
		status = prepare(sockfd, dbconn, clause_list);
	else if (ods_check_command(cmd,n,"backup commit"))
		status = commit(sockfd, dbconn, clause_list);
	else if (ods_check_command(cmd,n,"backup rollback"))
		status = rollback(sockfd, dbconn, clause_list);
	else if (ods_check_command(cmd,n,"backup list"))
		status = list(sockfd, dbconn, clause_list);
	else
		status = -1;

    db_clause_list_free(clause_list);
	return status;
}

static struct cmd_func_block funcblock = {
	"backup", &usage, NULL, &handles, &run
};

struct cmd_func_block*
backup_funcblock(void)
{
	return &funcblock;
}
