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

#include<getopt.h>
#include "config.h"

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "duration.h"
#include "clientpipe.h"
#include "libhsm.h"
#include "db/hsm_key.h"
#include "db/hsm_key_ext.h"

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
    char const *fmt = "%-32s %-16s %-16s\n";

    if (!(hsmkey_list = hsm_key_list_new_get_by_clauses(dbconn, clause_list)))
    {
        ods_log_error("[%s] database error", module_str);
        return -1;
    }

    client_printf_err(sockfd, fmt, "Locator:", "Repository:", "Backup state:");
    for (hsmkey = hsm_key_list_next(hsmkey_list); hsmkey;
        hsmkey = hsm_key_list_next(hsmkey_list))
    {
        client_printf(sockfd, fmt, hsm_key_locator(hsmkey), hsm_key_repository(hsmkey), hsm_key_to_backup_state(hsmkey));
    }
    hsm_key_list_free(hsmkey_list);
    return 0;
}

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "backup [list|prepare|commit|rollback]\n"
        "   --repository <repository>                    aka -r\n");
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "If the <RequireBackup/> option is given for a <Repository> in "
        "conf.xml, OpenDNSSEC will not publish records using key material "
        "not marked as backed up. Backing up key material is "
        "be done repository wide and is a 2-step process. First the "
        "operator issues a 'prepare' and after backing up a 'commit'. "
        "This avoids race conditions where the operator and the enforcer "
        "disagree on which keys are actually backed up.\n\n"

        "NOTICE: OpenDNSSEC does not backup key material it self. It is "
        "the operators responsibility to do this. This merely keeps track "
        "of the state and acts as a safety net.\n\n"
        
        "backup list:\t Print backup status of keys.\n"
        "backup prepare:\t Flag the keys as 'to be backed up'.\n"
        "backup commit:\t Mark flagged keys as backed up.\n"
        "backup rollback: Cancel a 'backup prepare' action.\n"
        "\nOptions:\n"
        "-r <repository>:\t Limit operations to this repository only.\n\n");
}

static int
handles(const char *cmd)
{
    if (ods_check_command(cmd, "backup")) return 1;
    if (ods_check_command(cmd, "backup prepare")) return 1;
    if (ods_check_command(cmd, "backup commit")) return 1;
    if (ods_check_command(cmd, "backup rollback")) return 1;
    if (ods_check_command(cmd, "backup list")) return 1;
    return 0;
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
    #define NARGV 4
    const char *argv[NARGV];
    int argc = 0, long_index = 0, opt = 0;
    const char *repository = NULL;
    char buf[ODS_SE_MAXLINE];
    int status;
    db_clause_list_t* clause_list;
    db_connection_t* dbconn = getconnectioncontext(context);

    static struct option long_options[] = {
        {"repository", required_argument, 0, 'r'},
        {0, 0, 0, 0}
    };

    strncpy(buf, cmd, ODS_SE_MAXLINE);
    buf[sizeof(buf)-1] = '\0';

    argc = ods_str_explode(buf, NARGV, argv);
    if (argc == -1) {
        client_printf_err(sockfd, "too many arguments\n");
        ods_log_error("[%s] too many arguments for %s command",
                      module_str, backup_funcblock.cmdname);
        return -1;
    }

    optind = 0;
    while ((opt = getopt_long(argc, (char* const*)argv, "r:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'r':
                repository = optarg;
                break;
            default:
                client_printf_err(sockfd, "unknown arguments\n");
                ods_log_error("[%s] unknown arguments for %s command",
                               module_str, backup_funcblock.cmdname);
                return -1;
        }
    }

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
    if (ods_check_command(cmd,"backup prepare"))
        status = prepare(sockfd, dbconn, clause_list);
    else if (ods_check_command(cmd,"backup commit"))
        status = commit(sockfd, dbconn, clause_list);
    else if (ods_check_command(cmd,"backup rollback"))
        status = rollback(sockfd, dbconn, clause_list);
    else if (ods_check_command(cmd,"backup list"))
        status = list(sockfd, dbconn, clause_list);
    else
        status = -1;

    db_clause_list_free(clause_list);
    return status;
}

struct cmd_func_block backup_funcblock = {
    "backup", &usage, &help, &handles, &run
};
