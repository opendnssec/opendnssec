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

#include <getopt.h>
#include "config.h"

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "db/dbw.h"

#include "hsmkey/backup_hsmkeys_cmd.h"

static const char *module_str = "backup_hsmkeys_cmd";

static int
hsmkeys_from_to_state(db_connection_t *dbconn, char const *repository,
    int from_state, int to_state)
{
    struct dbw_list *hsmkeys = dbw_hsmkeys_by_repository(dbconn, repository);
    if (!hsmkeys) {
        ods_log_error("[%s] database error", module_str);
        return -1;
    }
    int keys_marked = 0;
    for (size_t h = 0; h < hsmkeys->n; h++) {
        struct dbw_hsmkey *hsmkey = (struct dbw_hsmkey *)hsmkeys->set[h];
        if (hsmkey->backup != from_state) continue;
        hsmkey->backup = to_state;
        hsmkey->dirty = DBW_UPDATE;
        keys_marked++;
    }
    int r = dbw_update(dbconn, hsmkeys, 1);
    dbw_list_free(hsmkeys);
    if (r) {
        ods_log_error("[%s] database error", module_str);
        return -1;
    }
    return keys_marked;
}

static int
prepare(int sockfd, db_connection_t *dbconn, char const *repository)
{
    int keys_marked = hsmkeys_from_to_state(dbconn, repository,
        HSM_KEY_BACKUP_BACKUP_REQUIRED, HSM_KEY_BACKUP_BACKUP_REQUESTED);
    if (keys_marked < 0) {
        return 1;
    }
    client_printf(sockfd,"info: keys flagged for backup: %d\n", keys_marked);
    return 0;
}

static int
commit(int sockfd, db_connection_t *dbconn, char const *repository)
{
    int keys_marked = hsmkeys_from_to_state(dbconn, repository,
        HSM_KEY_BACKUP_BACKUP_REQUESTED, HSM_KEY_BACKUP_BACKUP_DONE);
    if (keys_marked < 0) {
        return 1;
    }
    client_printf(sockfd,"info: keys marked backup done: %d\n", keys_marked);
    return 0;
}

static int
rollback(int sockfd, db_connection_t *dbconn, char const *repository)
{
    int keys_marked = hsmkeys_from_to_state(dbconn, repository,
        HSM_KEY_BACKUP_BACKUP_REQUESTED, HSM_KEY_BACKUP_BACKUP_REQUIRED);
    if (keys_marked < 0) {
        return 1;
    }
    client_printf(sockfd,"info: keys unflagged for backup: %d\n", keys_marked);
    return 0;
}

static int
list(int sockfd, db_connection_t *dbconn, char const *repository)
{
    struct dbw_list *hsmkeys = dbw_hsmkeys_by_repository(dbconn, repository);
    if (!hsmkeys) {
        ods_log_error("[%s] database error", module_str);
        return -1;
    }
    char const *fmt = "%-32s %-16s %-16s\n";
    client_printf_err(sockfd, fmt, "Locator:", "Repository:", "Backup state:");
    for (size_t h = 0; h < hsmkeys->n; h++) {
        struct dbw_hsmkey *hsmkey = (struct dbw_hsmkey *)hsmkeys->set[h];
        client_printf(sockfd, fmt, hsmkey->locator, hsmkey->repository,
                hsm_key_enum_set_backup[hsmkey->backup].text);
    }
    dbw_list_free(hsmkeys);
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
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
    #define NARGV 4
    const char *argv[NARGV];
    int argc = 0, long_index = 0, opt = 0;
    const char *repository = NULL;
    char buf[ODS_SE_MAXLINE];
    int status;
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

    /* Find out what we need to do */
    if (ods_check_command(cmd,"backup prepare"))
        status = prepare(sockfd, dbconn, repository);
    else if (ods_check_command(cmd,"backup commit"))
        status = commit(sockfd, dbconn, repository);
    else if (ods_check_command(cmd,"backup rollback"))
        status = rollback(sockfd, dbconn, repository);
    else if (ods_check_command(cmd,"backup list"))
        status = list(sockfd, dbconn, repository);
    else
        status = -1;

    return status;
}

struct cmd_func_block backup_funcblock = {
    "backup", &usage, &help, &handles, &run
};
