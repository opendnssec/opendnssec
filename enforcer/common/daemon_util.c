/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

/* 
 * daemon_util.c code needed to get a daemon up and running
 *
 * edit the DAEMONCONFIG and cmlParse function
 * in daemon_util.[c|h] to add options specific
 * to your app
 *
 * gcc -o daemon daemon_util.c daemon.c
 *
 * Most of this is based on stuff I have seen in NSD
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h>
#include <signal.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

#include "daemon.h"
#include "daemon_util.h"

#include "ksm/database.h"
#include "ksm/datetime.h"

    int
permsDrop(DAEMONCONFIG* config)
{
    if (setgid(config->gid) != 0 || setuid(config->uid) !=0) {
        log_msg(config, LOG_ERR, "unable to drop user privileges: %s", strerror(errno));
        return -1;
    }
    return 0;
}

    void
log_msg(DAEMONCONFIG *config, int priority, const char *format, ...)
{
    /* TODO: if the variable arg list is bad then random errors can occur */ 
    va_list args;
    if (config && config->debug) priority = LOG_ERR;
    va_start(args, format);
    vsyslog(priority, format, args);
    va_end(args);
}


    static void
usage(void)
{
    fprintf(stderr, "Usage: ods_enf [OPTION]...\n");
    fprintf(stderr, "OpenDNSSEC Enforcer Daemon.\n\n");
    fprintf(stderr, "Supported options:\n");
    fprintf(stderr, "  -d          Debug.\n");
    fprintf(stderr, "  -u user     Change effective uid to the specified user.\n");
    fprintf(stderr, "  -P pidfile  Specify the PID file to write.\n");

    fprintf(stderr, "  -v          Print version.\n");
    fprintf(stderr, "  -?          This help.\n");
}

    static void
version(void)
{
    fprintf(stderr, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
    fprintf(stderr, "Written by %s.\n\n", AUTHOR_NAME);
    fprintf(stderr, "%s.  This is free software.\n", COPYRIGHT_STR);
    fprintf(stderr, "See source files for more license information\n");
    exit(0);
}

    int
write_data(DAEMONCONFIG *config, FILE *file, const void *data, size_t size)
{
    size_t result;

    if (size == 0)
        return 1;

    result = fwrite(data, 1, size, file);

    if (result == 0) {
        log_msg(config, LOG_ERR, "write failed: %s", strerror(errno));
        return 0;
    } else if (result < size) {
        log_msg(config, LOG_ERR, "short write (disk full?)");
        return 0;
    } else {
        return 1;
    }
}

    int
writepid (DAEMONCONFIG *config)
{
    FILE * fd;
    char pidbuf[32];

    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) config->pid);

    if ((fd = fopen(config->pidfile, "w")) ==  NULL ) {
        return -1;
    }

    if (!write_data(config, fd, pidbuf, strlen(pidbuf))) {
        fclose(fd);
        return -1;
    }
    fclose(fd);

    if (chown(config->pidfile, config->uid, config->gid) == -1) {
        log_msg(config, LOG_ERR, "cannot chown %u.%u %s: %s",
                (unsigned) config->uid, (unsigned) config->gid,
                config->pidfile, strerror(errno));
        return -1;
    }

    return 0;
}



    void
cmdlParse(DAEMONCONFIG* config, int *argc, char **argv)
{
    int c;

    /*
     * Read the command line
     */
    while ((c = getopt(*argc, argv, "dv?u:P:")) != -1) {
        switch (c) {
            case 'd':
                config->debug = true;
                break;
            case 'P':
                config->pidfile = optarg;
                break;
            case 'u':
                config->username = optarg;
                /* Parse the username into uid and gid */
                config->gid = getgid();
                config->uid = getuid();
                if (*config->username) {
                    struct passwd *pwd;
                    if (isdigit(*config->username)) {
                        char *t;
                        config->uid = strtol(config->username, &t, 10);
                        if (*t != 0) {
                            if (*t != '.' || !isdigit(*++t)) {
                                log_msg(config, LOG_ERR, "-u user or -u uid or -u uid.gid. exiting...");
                                exit(1);
                            }
                            config->gid = strtol(t, &t, 10);
                        } else {
                            /* Lookup the group id in /etc/passwd */
                            if ((pwd = getpwuid(config->uid)) == NULL) {
                                log_msg(config, LOG_ERR, "user id %u does not exist. exiting...", (unsigned) config->uid);
                                exit(1);
                            } else {
                                config->gid = pwd->pw_gid;
                            }
                            endpwent();
                        }
                    } else {
                        /* Lookup the user id in /etc/passwd */
                        if ((pwd = getpwnam(config->username)) == NULL) {
                            log_msg(config, LOG_ERR, "user '%s' does not exist. exiting...", config->username);
                            exit(1);
                        } else {
                            config->uid = pwd->pw_uid;
                            config->gid = pwd->pw_gid;
                        }
                        endpwent();
                    }
                }   
                break;
            case '?':
                usage();
                exit(0);
            case 'v':
                version();
                exit(0);
            default:
                usage();
                exit(0);
        }
    }
}

int
ReadConfig(DAEMONCONFIG *config)
{
    xmlDocPtr doc;
    xmlDocPtr rngdoc;
    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;
    xmlRelaxNGParserCtxtPtr rngpctx;
    xmlRelaxNGValidCtxtPtr rngctx;
    xmlRelaxNGPtr schema;
    xmlChar *ki_expr = (unsigned char*) "//Configuration/Enforcer/KeygenInterval";
    xmlChar *iv_expr = (unsigned char*) "//Configuration/Enforcer/Interval";
    xmlChar *bi_expr = (unsigned char*) "//Configuration/Enforcer/BackupDelay";
    xmlChar *litexpr = (unsigned char*) "//Configuration/Enforcer/Datastore/SQlite";
    xmlChar *mysql_host = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Host";
    xmlChar *mysql_port = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Host/@port";
    xmlChar *mysql_db = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Database";
    xmlChar *mysql_user = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Username";
    xmlChar *mysql_pass = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Password";

    int mysec = 0;
    int status;
    int db_found = 0;
    char* filename = CONFIGFILE;
    char* rngfilename = CONFIGRNG;

    log_msg(config, LOG_INFO, "Reading config \"%s\"\n", filename);

    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"\n", filename);
        return(-1);
    }

    /* Load rng document */
    log_msg(config, LOG_INFO, "Reading config schema \"%s\"\n", rngfilename);
    rngdoc = xmlParseFile(rngfilename);
    if (rngdoc == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"\n", rngfilename);
        return(-1);
    }

    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to create XML RelaxNGs parser context\n");
        return(-1);
    }

    /* parse a schema definition resource and build an internal XML Shema struture which can be used to validate instances. */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to parse a schema definition resource\n");
        return(-1);
    }

    /* Create an XML RelaxNGs validation context based on the given schema */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to create RelaxNGs validation context based on the schema\n");
        return(-1);
    }

    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    if (status != 0) {
        log_msg(config, LOG_ERR, "Error validating file \"%s\"\n", filename);
        return(-1);
    }

    /* Now parse a value out of the conf */
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        log_msg(config, LOG_ERR,"Error: unable to create new XPath context\n");
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Evaluate xpath expression for keygen interval */
    xpathObj = xmlXPathEvalExpression(ki_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s\n", ki_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    status = DtXMLIntervalSeconds((char *)xmlXPathCastToString(xpathObj), &mysec);
    if (status > 0) {
        log_msg(config, LOG_ERR, "Error: unable to convert interval %s to seconds, error: %i\n", xmlXPathCastToString(xpathObj), status);
        return status;
    }
    else if (status == -1) {
        log_msg(config, LOG_INFO, "Warning: converting %s to seconds may not give what you expect\n", xmlXPathCastToString(xpathObj));
    }
    config->keygeninterval = mysec;
    log_msg(config, LOG_INFO, "Key Generation Interval: %i\n", config->keygeninterval);

    /* Evaluate xpath expression for interval */
    /* TODO check that we can reuse xpathObj even if something has not worked */
    xpathObj = xmlXPathEvalExpression(iv_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s\n", iv_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    status = DtXMLIntervalSeconds((char *)xmlXPathCastToString(xpathObj), &mysec);
    if (status > 0) {
        log_msg(config, LOG_ERR, "Error: unable to convert interval %s to seconds, error: %i\n", xmlXPathCastToString(xpathObj), status);
        return status;
    }
    else if (status == -1) {
        log_msg(config, LOG_INFO, "Warning: converting %s to seconds may not give what you expect\n", xmlXPathCastToString(xpathObj));
    }
    config->interval = mysec;
    log_msg(config, LOG_INFO, "Communication Interval: %i\n", config->interval);

    /* Evaluate xpath expression for backup interval */
    xpathObj = xmlXPathEvalExpression(bi_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s\n", bi_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    status = DtXMLIntervalSeconds((char *)xmlXPathCastToString(xpathObj), &mysec);
    if (status > 0) {
        log_msg(config, LOG_ERR, "Error: unable to convert interval %s to seconds, error: %i\n", xmlXPathCastToString(xpathObj), status);
        return status;
    }
    else if (status == -1) {
        log_msg(config, LOG_INFO, "Warning: converting %s to seconds may not give what you expect\n", xmlXPathCastToString(xpathObj));
    }
    config->backupinterval = mysec;
    log_msg(config, LOG_INFO, "HSM Backup Interval: %i\n", config->backupinterval);

    /* Evaluate xpath expression for SQlite file location */
		
    xpathObj = xmlXPathEvalExpression(litexpr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s\n", litexpr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }
    if(*xmlXPathCastToString(xpathObj) != '\0') {
        db_found = SQLITE_DB;
		    config->schema = xmlXPathCastToString(xpathObj);
		    log_msg(config, LOG_INFO, "SQlite database set to: %s\n", config->schema);
    }

    if (db_found == 0) {
        /* Get all of the MySQL stuff read in too */
        /* HOST */
        xpathObj = xmlXPathEvalExpression(mysql_host, xpathCtx);
		    if(xpathObj == NULL) {
		        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s\n", mysql_host);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
		    if( *xmlXPathCastToString(xpathObj) != '\0') {
           db_found = MYSQL_DB;
        }
        config->host = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "MySQL database host set to: %s\n", config->host);

        /* PORT */
        xpathObj = xmlXPathEvalExpression(mysql_port, xpathCtx);
        if(xpathObj == NULL) {
		        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s\n", mysql_port);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
		    if( *xmlXPathCastToString(xpathObj) == '\0') {
            db_found = 0;
        }
        config->port = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "MySQL database port set to: %s\n", config->port);

        /* SCHEMA */
        xpathObj = xmlXPathEvalExpression(mysql_db, xpathCtx);
        if(xpathObj == NULL) {
		        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s\n", mysql_db);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
		    if( *xmlXPathCastToString(xpathObj) == '\0') {
            db_found = 0;
        }
        config->schema = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "MySQL database schema set to: %s\n", config->schema);

        /* DB USER */
        xpathObj = xmlXPathEvalExpression(mysql_user, xpathCtx);
        if(xpathObj == NULL) {
		        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s\n", mysql_user);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
		    if( *xmlXPathCastToString(xpathObj) == '\0') {
            db_found = 0;
        }
        config->user = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "MySQL database user set to: %s\n", config->user);

        /* DB PASSWORD */
        xpathObj = xmlXPathEvalExpression(mysql_pass, xpathCtx);
        if(xpathObj == NULL) {
		        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s\n", mysql_pass);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
		    /* password may be blank */
        
        config->password = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "MySQL database password set\n");

    }

    /* Check that we found one or the other database */
    if(db_found == 0) {
        log_msg(config, LOG_ERR, "Error: unable to find complete database connection expression\n");
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Check that we found the right database type */
    if (db_found != DbFlavour()) {
        log_msg(config, LOG_ERR, "Error: database in config file does not match libksm\n");
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Cleanup */
    /* TODO: some other frees are needed */
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(rngdoc);

    return(0);

}

