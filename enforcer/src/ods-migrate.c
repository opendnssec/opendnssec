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
#include <dlfcn.h>
#include <libxml/parser.h>

#ifdef HAVE_SQLITE3
#include <sqlite3.h>
#endif
#ifdef HAVE_MYSQL
#include <mysql/mysql.h>
#endif

#include "log.h"
#include "libhsm.h"
#include "daemon/cfg.h"
#include "libhsmdns.h"
#include "db/key_data.h"
extern hsm_repository_t* parse_conf_repositories(const char* cfgfile);

int verbosity;
char* argv0;

static void
usage(void)
{
    fprintf(stderr, "%s [-h] [-v] [-c <alternate-configuration>]\n", argv0);
}

typedef void (*functioncast_t)(void);
extern functioncast_t functioncast(void*generic);

functioncast_t
functioncast(void*generic) {
    functioncast_t* function = (functioncast_t*)&generic;
    return *function;
}

/****************************************************************************/

struct dblayer_struct {
    void (*foreach)(const char* listQueryStr, const char* updateQueryStr, int (*compute)(char**,int*,uint16_t*));
    void (*close)(void);
} dblayer;

#ifdef HAVE_SQLITE3

#define CHECKSQLITE(EX) do { dblayer_sqlite3.message = NULL; if((dblayer_sqlite3.status = (EX)) != SQLITE_OK) { fprintf(stderr, "%s: sql error: %s (%d)\n%s:%d: %s\n",argv0,(dblayer_sqlite3.message?dblayer_sqlite3.message:dblayer_sqlite3.sqlite3_errmsg(dblayer_sqlite3.handle)),dblayer_sqlite3.status,__FILE__,__LINE__,#EX); if(dblayer_sqlite3.message) dblayer_sqlite3.sqlite3_free(dblayer_sqlite3.message); } } while(0)

struct dblayer_sqlite3_struct {
    int status;
    char* message;
    void* library;
    sqlite3* handle;
    int (*sqlite3_prepare_v2)(sqlite3 *, const char *, int , sqlite3_stmt **, const char **);
    int (*sqlite3_reset)(sqlite3_stmt *pStmt);
    int (*sqlite3_bind_int)(sqlite3_stmt*, int, int);
    int (*sqlite3_finalize)(sqlite3_stmt *pStmt);
    int (*sqlite3_open)(const char *filename, sqlite3 **ppDb);
    int (*sqlite3_exec)(sqlite3*, const char *sql, int (*callback)(void*, int, char**, char**), void *, char **errmsg);
    int (*sqlite3_step)(sqlite3_stmt*);
    int (*sqlite3_close)(sqlite3*);
    const char* (*sqlite3_errmsg)(sqlite3*);
    int (*sqlite3_free)(void*);
};
struct dblayer_sqlite3_struct dblayer_sqlite3;

static void
dblayer_sqlite3_initialize(void)
{
    void *handle;
    char const *error;

    dlerror();
    handle = dlopen("libsqlite3.so.0", RTLD_NOW);
    if ((error = dlerror()) != NULL) {
          handle = dlopen("libsqlite3.so", RTLD_NOW); /* unversioned is a -devel package file on some distros */
          if ((error = dlerror()) != NULL) {
             printf("Failed to load sqlite3 library. dlerror(): %s\n", error);
             exit(1);
          }
    }

    dblayer_sqlite3.sqlite3_prepare_v2 = (int(*)(sqlite3*, const char*, int, sqlite3_stmt**, const char **))functioncast(dlsym(handle, "sqlite3_prepare_v2"));
    dblayer_sqlite3.sqlite3_reset = (int(*)(sqlite3_stmt*)) functioncast(dlsym(handle, "sqlite3_reset"));
    dblayer_sqlite3.sqlite3_bind_int = (int(*)(sqlite3_stmt*, int, int))functioncast(dlsym(handle, "sqlite3_bind_int"));
    dblayer_sqlite3.sqlite3_finalize = (int(*)(sqlite3_stmt*))functioncast(dlsym(handle, "sqlite3_finalize"));
    dblayer_sqlite3.sqlite3_open = (int(*)(const char*, sqlite3**)) functioncast(dlsym(handle, "sqlite3_open"));
    dblayer_sqlite3.sqlite3_exec = (int(*)(sqlite3*, const char*, int(*)(void*, int, char**, char**), void*, char **)) functioncast(dlsym(handle, "sqlite3_exec"));
    dblayer_sqlite3.sqlite3_step = (int(*)(sqlite3_stmt*)) functioncast(dlsym(handle, "sqlite3_step"));
    dblayer_sqlite3.sqlite3_close = (int(*)(sqlite3*)) functioncast(dlsym(handle, "sqlite3_close"));
    dblayer_sqlite3.sqlite3_errmsg = (const char*(*)(sqlite3*)) functioncast(dlsym(handle, "sqlite3_errmsg"));
    dblayer_sqlite3.sqlite3_free = (int(*)(void*)) functioncast(dlsym(handle, "sqlite3_free"));

    if (!dblayer_sqlite3.sqlite3_open) {
	    printf("Failed to load sqlite3 library.\n");
	    exit(1);
    }
}

static void
dblayer_sqlite3_close(void)
{
    dblayer_sqlite3.sqlite3_close(dblayer_sqlite3.handle);
}

struct callbackoperation {
    int (*compute)(char **argv, int* id, uint16_t *keytag);
    sqlite3_stmt* updateStmt;
};

static int
callback(void *cargo, int argc, char **argv, char **names)
{
    int status;
    int id;
    uint16_t keytag;
    struct callbackoperation* operation = (struct callbackoperation*) cargo;

    operation->compute(argv, &id, &keytag);
    
    CHECKSQLITE(dblayer_sqlite3.sqlite3_reset(operation->updateStmt));
    CHECKSQLITE(dblayer_sqlite3.sqlite3_bind_int(operation->updateStmt, 1, keytag));
    CHECKSQLITE(dblayer_sqlite3.sqlite3_bind_int(operation->updateStmt, 2, id));
    do {
        switch ((status = dblayer_sqlite3.sqlite3_step(operation->updateStmt))) {
            case SQLITE_ROW:
                break;
            case SQLITE_DONE:
                break;
            case SQLITE_BUSY:
                sleep(1);
                break;
            case SQLITE_ERROR:
            case SQLITE_MISUSE:
            default:
                fprintf(stderr, "%s: sql error: %s\n", argv0, dblayer_sqlite3.sqlite3_errmsg(dblayer_sqlite3.handle));
                break;
        }
    } while(status == SQLITE_BUSY);
    return SQLITE_OK;
}

static void
dblayer_sqlite3_foreach(const char* listQueryStr, const char* updateQueryStr, int (*compute)(char**,int*,uint16_t*))
{
    struct callbackoperation operation;
    const char* queryEnd;
    operation.compute = compute;
    CHECKSQLITE(dblayer_sqlite3.sqlite3_prepare_v2(dblayer_sqlite3.handle, updateQueryStr, strlen(updateQueryStr)+1, &operation.updateStmt, &queryEnd));
    CHECKSQLITE(dblayer_sqlite3.sqlite3_exec(dblayer_sqlite3.handle, listQueryStr, callback, &operation, &dblayer_sqlite3.message));
    CHECKSQLITE(dblayer_sqlite3.sqlite3_finalize(operation.updateStmt));
    dblayer_sqlite3.sqlite3_close(dblayer_sqlite3.handle);
}

static void
dblayer_sqlite3_open(const char *datastore) {
    CHECKSQLITE(dblayer_sqlite3.sqlite3_open(datastore, &dblayer_sqlite3.handle));
    dblayer.close = &dblayer_sqlite3_close;
    dblayer.foreach = &dblayer_sqlite3_foreach;
}

#endif

/****************************************************************************/

#ifdef HAVE_MYSQL

struct dblayer_mysql_struct {
    MYSQL* handle;
};
extern struct dblayer_mysql_struct dblayer_mysql;
struct dblayer_mysql_struct dblayer_mysql;


static void
dblayer_mysql_initialize(void) {
    if (mysql_library_init(0, NULL, NULL)) {
        fprintf(stderr, "could not initialize MySQL library\n");
        exit(1);
    }
}

static void
dblayer_mysql_close(void)
{
    if (dblayer_mysql.handle) {
        mysql_close(dblayer_mysql.handle);
        dblayer_mysql.handle = NULL;
    }
}

static void
dblayer_mysql_foreach(const char* listQueryStr, const char* updateQueryStr, int (*compute)(char**,int*,uint16_t*))
{
    int id;
    uint16_t keytag;
    MYSQL_BIND bind[2];
    MYSQL_STMT *updateStmt;
    MYSQL_RES* res;
    MYSQL_ROW row;
    updateStmt = mysql_stmt_init(dblayer_mysql.handle);
    mysql_stmt_prepare(updateStmt, updateQueryStr, strlen(updateQueryStr) + 1);
    mysql_query(dblayer_mysql.handle, listQueryStr);
    res = mysql_store_result(dblayer_mysql.handle);
    if (!res) {
        fprintf(stderr, "Failed to update db. Is it set correctly in conf.xml?\n");
        exit(1);
    }
    mysql_num_fields(res);
    while ((row = mysql_fetch_row(res))) {
        compute(row, &id, &keytag);
        memset(bind, 0, sizeof (bind));
        bind[0].buffer = &keytag;
        bind[0].buffer_length = sizeof(keytag);
        bind[0].buffer_type = MYSQL_TYPE_SHORT;
        bind[0].is_unsigned = 1;
        bind[1].buffer = &id;
        bind[1].buffer_length = sizeof(id);
        bind[1].buffer_type = MYSQL_TYPE_LONG;
        mysql_stmt_bind_param(updateStmt, bind);
        mysql_stmt_execute(updateStmt);
        mysql_stmt_affected_rows(updateStmt);
    }
    mysql_free_result(res);
    mysql_stmt_close(updateStmt);
}

static void
dblayer_mysql_open(const char* host, const char* user, const char* pass,
        const char *rsrc, unsigned int port, const char *unix_socket)
{
    dblayer_mysql.handle = mysql_init(NULL);
    if (!mysql_real_connect(dblayer_mysql.handle, host, user, pass, rsrc, port, NULL, 0)) {
	fprintf(stderr, "Failed to connect to database: Error: %s\n",
	    mysql_error(dblayer_mysql.handle)); 
	exit(1);
    }
    dblayer.close = &dblayer_mysql_close;
    dblayer.foreach = &dblayer_mysql_foreach;

}

#endif

/****************************************************************************/

static void
dblayer_initialize(void)
{
#ifdef HAVE_SQLITE3
    dblayer_sqlite3_initialize();
#endif
#ifdef HAVE_MYSQL
    dblayer_mysql_initialize();
#endif
}

static void
dblayer_close(void) {
    dblayer.close();
}

static void
dblayer_finalize(void) {
#ifdef HAVE_MYSQL
    mysql_library_end();
#endif
}

static void
dblayer_foreach(const char* listQueryStr, const char* updateQueryStr, int (*compute)(char**,int*,uint16_t*))
{
    dblayer.foreach(listQueryStr, updateQueryStr, compute);
}

/****************************************************************************/

const char* listQueryStr = "select keyData.id,keyData.algorithm,keyData.role,keyData.keytag,hsmKey.locator from keyData join hsmKey on keyData.hsmKeyId = hsmKey.id";
const char* updateQueryStr = "update keyData set keytag = ? where id = ?";

static int keytagcount;

static int
compute(char **argv, int* id, uint16_t* keytag)
{
    char *locator;
    int algorithm;
    int sep;

    *id = atoi(argv[0]);
    algorithm = atoi(argv[1]);
    sep = KEY_DATA_ROLE_SEP(atoi(argv[2]));
    *keytag = atoi(argv[3]);
    locator = argv[4];
    hsm_keytag(locator, algorithm, sep, keytag);
    keytagcount += 1;
    
    return 0;
}

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
    printf("Reading config file '%s'..\n", cfgfile);
    cfg = engine_config(cfgfile, verbosity, NULL);
    cfg->verbosity = verbosity;
    /* does it make sense? */
    if (engine_config_check(cfg) != ODS_STATUS_OK) {
        fprintf(stderr,"Configuration error.\n");
        exit(1);
    }

    printf("Connecting to HSM..\n");
    status = hsm_open2(parse_conf_repositories(cfgfile), hsm_prompt_pin);
    if (status != HSM_OK) {
        char* errorstr =  hsm_get_error(NULL);
        if (errorstr != NULL) {
            fprintf(stderr, "%s", errorstr);
            free(errorstr);
        } else {
            fprintf(stderr,"error opening libhsm (errno %i)\n", status);
        }
        return 1;
    }
    dblayer_initialize();

    printf("Connecting to database..\n");
    switch (cfg->db_type) {
        case ENFORCER_DATABASE_TYPE_SQLITE:
#ifdef HAVE_SQLITE3
            dblayer_sqlite3_open(cfg->datastore);
#else
            fprintf(stderr, "Database SQLite3 not available during compile-time.\n");
            exit(1);
#endif
            break;
        case ENFORCER_DATABASE_TYPE_MYSQL:
#ifdef HAVE_MYSQL
            dblayer_mysql_open(cfg->db_host, cfg->db_username, cfg->db_password, cfg->datastore, cfg->db_port, NULL);
#else
    fprintf(stderr, "Database MySQL not available during compile-time.\n");
    exit(1);
#endif
            break;
        case ENFORCER_DATABASE_TYPE_NONE:
        default:
            fprintf(stderr, "No database defined, possible mismatch build\n");
            fprintf(stderr, "and configuration for SQLite3 or MySQL.\n");
            exit(1);
    }

    keytagcount = 0;
    printf("Computing keytags, this could take a while.\n");
    dblayer_foreach(listQueryStr, updateQueryStr, &compute);
    printf("Added keytags for %d keys.\n", keytagcount);

    printf("Finishing..\n");
    hsm_close();

    engine_config_cleanup(cfg);
    /* dblayer_foreach for each frees something dblayer_close uses
     * We better just let it leak. */
    /* dblayer_close(); */
    dblayer_finalize();
    ods_log_close();

    xmlCleanupParser();
    xmlCleanupGlobals();

    return 0;
}
