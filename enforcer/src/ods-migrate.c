/*
 * Copyright (c) 2016 NLNet Labs. All rights reserved.
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

#include <getopt.h>
#include <libxml/parser.h>
#include <sqlite3.h>

#include "log.h"
#include "libhsm.h"
#include "daemon/cfg.h"
#include "libhsmdns.h"

int verbosity;
char* argv0;

static void
usage(void)
{
    fprintf(stderr, "%s [-h] [-v] [-c <alternate-configuration>]\n", argv0);
}

#ifdef HAVE_SQLITE3

const char* listQueryStr = "select keyData.id,keyData.algorithm,keyData.role,keyData.keytag,hsmKey.locator from keyData join hsmKey on keyData.hsmKeyId = hsmKey.id";
const char* updateQueryStr = "update keyData set keytag = ? where id = ?";

sqlite3 *sqliteDatabase;
int sqliteStatus;
char* sqliteMessage;

#define CHECKSQLITE(EX) do { sqliteMessage = NULL; if((sqliteStatus = (EX)) != SQLITE_OK) { fprintf(stderr, "%s: sql error: %s (%d)\n%s:%d: %s\n",argv0,(sqliteMessage?sqliteMessage:sqlite3_errmsg(sqliteDatabase)),sqliteStatus,__FILE__,__LINE__,#EX); if(sqliteMessage) sqlite3_free(sqliteMessage); } } while(0)

static int
callback(void *cargo, int argc, char **argv, char **names)
{
    int status;
    int id;
    char *locator;
    int algorithm;
    int ksk;
    uint16_t keytag;
    sqlite3_stmt* stmt;
    const char* queryEnd;

    (void)names;
    (void)cargo;
    (void)argc;
    
    id = atoi(argv[0]);
    algorithm = atoi(argv[1]);
    ksk = (atoi(argv[2]) == 1);
    keytag = atoi(argv[3]);
    locator = argv[4];
    hsm_keytag(locator, algorithm, ksk, &keytag);
    printf("computed %d for %d\n",(int)keytag,id);
    CHECKSQLITE(sqlite3_prepare_v2(sqliteDatabase, updateQueryStr, strlen(updateQueryStr)+1, &stmt, &queryEnd));
    CHECKSQLITE(sqlite3_reset(stmt));
    CHECKSQLITE(sqlite3_bind_int(stmt, 1, keytag));
    CHECKSQLITE(sqlite3_bind_int(stmt, 2, id));
    do {
        switch ((status = sqlite3_step(stmt))) {
            case SQLITE_ROW:
                break;
            case SQLITE_DONE:
                break;
            case SQLITE_BUSY:
                sleep(1);
                break;
            case SQLITE_ERROR:
            case SQLITE_MISUSE:
                fprintf(stderr, "%s: sql error: %s\n",argv0,sqlite3_errmsg(sqliteDatabase));
                break;
        }
    } while(status == SQLITE_BUSY);
    CHECKSQLITE(sqlite3_finalize(stmt));
    return SQLITE_OK;
}

#endif

int
main(int argc, char* argv[])
{
    ods_status status;
    engineconfig_type* cfg;
    int c;
    int options_index = 0;
    const char* cfgfile = ODS_SE_CFGFILE;
    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        { 0, 0, 0, 0}
    };

    argv0 = argv[0];

    /* parse the commandline */
    while ((c=getopt_long(argc, argv, "c:hv", long_options, &options_index)) != -1) {
        switch (c) {
            case 'c':
                cfgfile = optarg;
                break;
            case 'h':
                usage();
                exit(0);
            case 'v':
                ++verbosity;
                break;
            default:
                usage();
                exit(1);
        }
    }
    argc -= optind;
    argv += optind;
    if (argc != 0) {
        usage();
        exit(1);
    }

    ods_log_init("ods-migrate", 0, NULL, verbosity);

    xmlInitGlobals();
    xmlInitParser();
    xmlInitThreads();

    tzset(); /* for portability */

    /* Parse config file */
    cfg = engine_config(cfgfile, verbosity, NULL);
    cfg->verbosity = verbosity;
    /* does it make sense? */
    if (engine_config_check(cfg) != ODS_STATUS_OK) {
        abort(); /* TODO give some error, abort */
    }

    if (cfg->db_type == ENFORCER_DATABASE_TYPE_SQLITE) {
        /* config->datastore config->db_port*/
    } else if (cfg->db_type == ENFORCER_DATABASE_TYPE_MYSQL) {
        /* config->db_host config->db_port config->db_port config->db_username config->db_password */
    }

    status = hsm_open(cfgfile, hsm_prompt_pin);
    if (status != HSM_OK) {
        char* errorstr =  hsm_get_error(NULL);
        if (errorstr != NULL) {
            fprintf(stderr, "%s", errorstr);
            free(errorstr);
            abort(); /* FIXME */
        } else {
            fprintf(stderr,"error opening libhsm (errno %i)\n", status);
        }
        return 1;
    }

#ifdef HAVE_SQLITE3
    CHECKSQLITE(sqlite3_open(cfg->datastore, &sqliteDatabase));
    CHECKSQLITE(sqlite3_exec(sqliteDatabase, listQueryStr, callback, NULL, &sqliteMessage));
    sqlite3_close(sqliteDatabase);
#endif

    hsm_close();

    engine_config_cleanup(cfg);

    ods_log_close();

    xmlCleanupParser();
    xmlCleanupGlobals();
    xmlCleanupThreads();

    return 0;
}
