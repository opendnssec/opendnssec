/*
 * Copyright (c) 2017 Stichting NLnet Labs
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
#include <math.h>

#include "daemon/engine.h"
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "duration.h"

#include "hsmkey/hsmkey_list_cmd.h"

static void
usage(int sockfd)
{
    client_printf(sockfd,
        "List generated but unassigned keys per policy.\n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "List generated but unassigned keys per policy.\n"
    );
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
    db_connection_t* dbconn = getconnectioncontext(context);
    engine_type* engine = getglobalcontext(context);
    (void) cmd;

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return 1;

    for (size_t p = 0; p < db->policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)db->policies->set[p];
        for (size_t hk = 0; hk < policy->hsmkey_count; hk++) {
            struct dbw_hsmkey *hsmkey = policy->hsmkey[hk];
            if (hsmkey->state != DBW_HSMKEY_UNUSED) continue;
            client_printf(sockfd, "%s;%s;%s;%d;%d;%s\n", hsmkey->locator,
                    hsmkey->repository, policy->name, hsmkey->bits,
                    hsmkey->algorithm, dbw_enum2txt(dbw_key_role_txt, hsmkey->role));
        }
    }
    dbw_free(db);
    return 0;
}

struct cmd_func_block hsmkey_list_funcblock = {
    "hsmkey list", &usage, &help, NULL, &run
};
