/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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

/**
 * OpenDNSSEC enforcer database setup tool.
 */

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "daemon/engine.h"
#include "log.h"

#if defined(ENFORCER_DATABASE_SQLITE3)
#include <sqlite3.h>
#include "db/db_schema_sqlite.h"
#include "db/db_data_sqlite.h"

static const char** create = db_schema_sqlite_create;
static const char** drop = db_schema_sqlite_drop;
static const char** data = db_data_sqlite;
static sqlite3* db = NULL;
#elif defined(ENFORCER_DATABASE_MYSQL)
#include <mysql/mysql.h>
#include "db/db_schema_mysql.h"
#include "db/db_data_mysql.h"
static const char** create = db_schema_mysql_create;
static const char** drop = db_schema_mysql_drop;
static const char** data = db_data_mysql;
static MYSQL* db = NULL;
#endif

#define AUTHOR_NAME "Jerry Lundström"
#define COPYRIGHT_STR "Copyright (c) 2014 .SE (The Internet Infrastructure Foundation) OpenDNSSEC"

static void usage(FILE* out) {
    fprintf(out,
        "\nBSD licensed, see LICENSE in source package for details.\n"
        "Version %s. Report bugs to <%s>.\n",
        PACKAGE_VERSION,
        PACKAGE_BUGREPORT);
    fprintf(out, "--help,     -h: Print usage.\n");
    fprintf(out, "--version,  -V: Print version.\n");
    fprintf(out, "--force,    -f: Yes to all questions.\n");
}

static void version(FILE* out) {
    fprintf(out,
        "Database setup tool for %s version %s\n"
        "Written by %s.\n\n"
        "%s.  This is free software.\n"
        "See source files for more license information\n",
        PACKAGE_NAME,
        PACKAGE_VERSION,
        AUTHOR_NAME,
        COPYRIGHT_STR);
    exit(0);
}

static int connect_db(engineconfig_type* cfg) {
#if defined(ENFORCER_DATABASE_SQLITE3)
    if (!cfg->datastore) {
        return -1;
    }
    if (db) {
        return -1;
    }

    if (sqlite3_initialize() != SQLITE_OK) {
        return -1;
    }

    if (sqlite3_open_v2(cfg->datastore, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_CREATE,
        NULL) != SQLITE_OK)
    {
        return -1;
    }

    return 0;
#elif defined(ENFORCER_DATABASE_MYSQL)
    if (!cfg->datastore) {
        return -1;
    }
    if (db) {
        return -1;
    }

    if (mysql_library_init(0, NULL, NULL)) {
        return -1;
    }

    if (!(db = mysql_init(NULL))
        || !mysql_real_connect(db,
            cfg->db_host,
            cfg->db_username,
            cfg->db_password,
            cfg->datastore,
            cfg->db_port,
            NULL,
            0))
    {
        if (db) {
            mysql_close(db);
            db = NULL;
        }
        return -1;
    }

    return 0;
#else
    return -1;
#endif
}

static int disconnect_db() {
#if defined(ENFORCER_DATABASE_SQLITE3)
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }

    sqlite3_shutdown();

    return 0;
#elif defined(ENFORCER_DATABASE_MYSQL)
    if (db) {
        mysql_close(db);
        db = NULL;
    }

    mysql_library_end();

    return 0;
#else
    return -1;
#endif
}

static int db_do(const char *sql, size_t size) {
#if defined(ENFORCER_DATABASE_SQLITE3)
    sqlite3_stmt* stmt = NULL;

    if (!db) {
        return -1;
    }
    if (!sql) {
        return -1;
    }

    if (sqlite3_prepare_v2(db, sql, size, &stmt, NULL) != SQLITE_OK
        || sqlite3_step(stmt) != SQLITE_DONE)
    {
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return -1;
    }
    sqlite3_finalize(stmt);

    return 0;
#elif defined(ENFORCER_DATABASE_MYSQL)
    if (!db) {
        return -1;
    }
    if (!sql) {
        return -1;
    }

    if (mysql_real_query(db, sql, size)) {
        return -1;
    }

    return 0;
#else
    return -1;
#endif
}

static int db_do2(const char** strs) {
    char sql[4096];
    char *sqlp;
    int ret, left, i;

    for (i = 0; strs[i]; i++) {
        left = sizeof(sql);
        sqlp = sql;

        for (; strs[i]; i++) {
            if ((ret = snprintf(sqlp, left, "%s", strs[i])) >= left) {
                return -1;
            }
            sqlp += ret;
            left -= ret;
        }

        if (db_do(sql, sizeof(sql) - left)) {
            return -1;
        }
    }

    return 0;
}

static int empty_zones_file (const char* filename) {
    xmlDocPtr doc;
    xmlNodePtr root = NULL;
    char path[PATH_MAX];
    char* dirname, *dirlast;
    if (!filename)
        return -1;

    if (access(filename, W_OK)) {
        if (errno == ENOENT) {
            if ((dirname = strdup(filename))) {
                if ((dirlast = strrchr(dirname, '/'))) {
                    *dirlast = 0;
                    if (access(dirname, W_OK)) {
                        fprintf(stderr, "Write access to directory denied: %s\n", strerror(errno));
                        free(dirname);
                        return -1;
                    }
                }
                free(dirname);
            }
        }
        else {
            fprintf(stderr, "Write access to file denied: %s\n", strerror(errno));
            return -1;
        }
    }

    if (!(doc = xmlNewDoc((xmlChar*)"1.0"))
        || !(root = xmlNewNode(NULL, (xmlChar*)"ZoneList")))
    {
        fprintf(stderr, "Unable to create XML elements, memory allocation error!\n");
        if (doc) {
            xmlFreeDoc(doc);
        }
        return -1;
    }
    xmlDocSetRootElement(doc, root);

   if (snprintf(path, sizeof(path), "%s.new", filename) >= (int)sizeof(path)) {
        fprintf(stderr, "Unable to write zonelist, memory allocation error!\n");
        xmlFreeDoc(doc);
        return -1;
    }
    unlink(path);
    if (xmlSaveFormatFileEnc(path, doc, "UTF-8", 1) == -1) {
        fprintf(stderr, "Unable to write zonelist, LibXML error!\n");
        xmlFreeDoc(doc);
        return -1;
    }
    xmlFreeDoc(doc);
    if (rename(path, filename)) {
        fprintf(stderr, "Unable to write zonelist, rename failed!\n");
        unlink(path);
        return -1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    int c, options_index = 0;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {"force", no_argument, 0, 'f'},
        { 0, 0, 0, 0}
    };
    int user_certain;
    int force = 0;
    engineconfig_type* cfg;
    const char* cfgfile = ODS_SE_CFGFILE;
    char path[PATH_MAX];

    ods_log_init("ods-enforcerd", 0, NULL, 0);

    while ((c=getopt_long(argc, argv, "hVf",
        long_options, &options_index)) != -1) {
        switch (c) {
            case 'h':
                usage(stdout);
                exit(0);
            case 'V':
                version(stdout);
                exit(0);
	    case 'f':
		force = 1;
		break;
            default:
                exit(100);
        }
    }

    if (!force) {
        printf("*WARNING* This will erase all data in the database; "
	       "are you sure? [y/N] ");
        user_certain = getchar();
        if (user_certain != 'y' && user_certain != 'Y') {
            printf("Okay, quitting...\n");
            return 0;
        }
    }

    cfg = engine_config(cfgfile, 0, NULL);
    if (engine_config_check(cfg) != ODS_STATUS_OK) {
        engine_config_cleanup(cfg);
        fprintf(stderr, "Error: unable to load configuration!\n");
        return 1;
    }

    if (connect_db(cfg)) {
        engine_config_cleanup(cfg);
        fprintf(stderr, "Error: unable to connect to database!\n");
        return 2;
    }

    /*
     * Drop existing schema.
     */
    if (db_do2(drop)) {
        fprintf(stderr, "Error: unable to drop existing schema!\n");
        disconnect_db();
        return 3;
    }

    /*
     * Create new schema.
     */
    if (db_do2(create)) {
        fprintf(stderr, "Error: unable to create schema!\n");
        disconnect_db();
        return 4;
    }

    /*
     * Insert initial data.
     */
    if (db_do2(data)) {
        fprintf(stderr, "Error: unable to insert initial data!\n");
        disconnect_db();
        return 5;
    }

    if (snprintf(path, sizeof(path), "%s/%s", cfg->working_dir_enforcer, OPENDNSSEC_ENFORCER_ZONELIST) >= (int)sizeof(path)
            || empty_zones_file(path) != 0)
    {
        fprintf(stderr, "Unable to clear the internal zonelist %s!\n", path);
        return 6;
    } else {
        printf("Internal zonelist cleared successfully.\n");
    }

    engine_config_cleanup(cfg);
    printf("Database setup successfully.\n");
    return 0;
}
