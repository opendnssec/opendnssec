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
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

#include "config.h"
#include "daemon.h"
#include "daemon_util.h"

#include "ksm/database.h"
#include "ksm/datetime.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"

    int
permsDrop(DAEMONCONFIG* config)
{
    int status = 0;

    xmlDocPtr doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;
    xmlChar *user_expr = (unsigned char*) "//Configuration/Enforcer/Privileges/User";
    xmlChar *group_expr = (unsigned char*) "//Configuration/Enforcer/Privileges/Group";

    char* filename = CONFIG_FILE;
    char* rngfilename = SCHEMA_DIR "/conf.rng";

    char* temp_char = NULL;
    struct passwd *pwd;
    struct group *grp;
    gid_t oldgid = getegid();
    uid_t olduid = geteuid();
    
    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"", filename);
        return(-1);
    }

    /* Load rng document */
    rngdoc = xmlParseFile(rngfilename);
    if (rngdoc == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"", rngfilename);
        return(-1);
    }

    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to create XML RelaxNGs parser context");
        return(-1);
    }

    /* parse a schema definition resource and build an internal XML Shema struture which can be used to validate instances. */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to parse a schema definition resource");
        return(-1);
    }

    /* Create an XML RelaxNGs validation context based on the given schema */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to create RelaxNGs validation context based on the schema");
        return(-1);
    }

    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    if (status != 0) {
        log_msg(config, LOG_ERR, "Error validating file \"%s\"", filename);
        return(-1);
    }

    /* Now parse a value out of the conf */
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        log_msg(config, LOG_ERR,"Error: unable to create new XPath context");
        xmlFreeDoc(doc);
        return(-1);
    }
   
    /* Set the group if specified; else just set the gid as the real one */
    xpathObj = xmlXPathEvalExpression(group_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", group_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }
    if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        temp_char = (char*) xmlXPathCastToString(xpathObj);
        StrAppend(&config->groupname, temp_char);
        StrFree(temp_char);
        xmlXPathFreeObject(xpathObj);

        /* Lookup the group id in /etc/groups */
        if ((grp = getgrnam(config->groupname)) == NULL) {
            log_msg(config, LOG_ERR, "group '%s' does not exist. exiting...", config->groupname);
            exit(1);
        } else {
            config->gid = grp->gr_gid;
        }

        /* If we are root then drop all groups other than the final one */
        if (!olduid) setgroups(1, &(grp->gr_gid));
        endgrent();

#if !defined(linux)
        setegid(config->gid);
        status = setgid(config->gid);
#else
        status = setregid(config->gid, config->gid);
#endif /* !defined(linux) */

        if (status != 0) {
            log_msg(config, LOG_ERR, "unable to drop group privileges: %s", strerror(errno));
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return -1;
        }
        log_msg(config, LOG_INFO, "group set to: %s(%d)", config->groupname, config->gid);
    } else {
        config->gid = oldgid;
    }

    /* Set the user to drop to if specified; else just set the uid as the real one */
    xpathObj = xmlXPathEvalExpression(user_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", user_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }
    if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        temp_char = (char*) xmlXPathCastToString(xpathObj);
        StrAppend(&config->username, temp_char);
        StrFree(temp_char);
        xmlXPathFreeObject(xpathObj);

        /* Lookup the user id in /etc/passwd */
        if ((pwd = getpwnam(config->username)) == NULL) {
            log_msg(config, LOG_ERR, "user '%s' does not exist. exiting...", config->username);
            exit(1);
        } else {
            config->uid = pwd->pw_uid;
        }
        endpwent();

#if defined(HAVE_SETRESUID) && !defined(BROKEN_SETRESUID)
        status = setresuid(config->uid, config->uid, config->uid);
#elif defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
        status = setreuid(config->uid, config->uid);
#else

# ifndef SETEUID_BREAKS_SETUID        
        seteuid(config->uid);
#endif  /* SETEUID_BREAKS_SETUID */

        status = setuid(config->uid);
#endif

        if (status != 0) {
            log_msg(config, LOG_ERR, "unable to drop user privileges: %s", strerror(errno));
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return -1;
        }
        log_msg(config, LOG_INFO, "user set to: %s(%d)", config->username, config->uid);
    } else {
        config->uid = olduid;
    }

    xmlXPathFreeContext(xpathCtx);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(doc);
    xmlFreeDoc(rngdoc);

    return 0;
}

/* Set up logging as per default (facility may be switched based on config file) */
void log_init(int facility, const char *program_name)
{
	openlog(program_name, 0, facility);
}

/* Switch log to new facility */
void log_switch(int facility, const char *facility_name, const char *program_name)
{
    closelog();
	openlog(program_name, 0, facility);
    log_msg(NULL, LOG_INFO, "Switched log facility to: %s", facility_name);
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

/*
 * log function suitable for libksm callback
 */
    void
ksm_log_msg(const char *format)
{
    syslog(LOG_ERR, "%s", format);
}

    static void
usage(const char* prog)
{
    fprintf(stderr, "Usage: %s [OPTION]...\n", prog);
    fprintf(stderr, "OpenDNSSEC Enforcer Daemon.\n\n");
    fprintf(stderr, "Supported options:\n");
    fprintf(stderr, "  -d          Debug.\n");
    fprintf(stderr, "  -1          Run once, then exit.\n");
/*    fprintf(stderr, "  -u user     Change effective uid to the specified user.\n");*/
    fprintf(stderr, "  -P pidfile  Specify the PID file to write.\n");

    fprintf(stderr, "  -v          Print version.\n");
    fprintf(stderr, "  -[?|h]      This help.\n");
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
    while ((c = getopt(*argc, argv, "1hdv?u:P:")) != -1) {
        switch (c) {
            case '1':
                config->once = true;
                break;
            case 'd':
                config->debug = true;
                break;
            case 'P':
                config->pidfile = optarg;
                break;
            case 'u':
                break; /* disable this feature */
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
            case 'h':
                usage(config->program);
                exit(0);
            case '?':
                usage(config->program);
                exit(0);
            case 'v':
                version();
                exit(0);
            default:
                usage(config->program);
                exit(0);
        }
    }
}

int
ReadConfig(DAEMONCONFIG *config)
{
    xmlDocPtr doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;
    xmlChar *ki_expr = (unsigned char*) "//Configuration/Enforcer/KeygenInterval";
    xmlChar *iv_expr = (unsigned char*) "//Configuration/Enforcer/Interval";
    xmlChar *bi_expr = (unsigned char*) "//Configuration/Enforcer/BackupDelay";
    xmlChar *rn_expr = (unsigned char*) "//Configuration/Enforcer/RolloverNotification";
    xmlChar *litexpr = (unsigned char*) "//Configuration/Enforcer/Datastore/SQLite";
    xmlChar *mysql_host = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Host";
    xmlChar *mysql_port = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Host/@port";
    xmlChar *mysql_db = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Database";
    xmlChar *mysql_user = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Username";
    xmlChar *mysql_pass = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Password";
    xmlChar *log_user_expr = (unsigned char*) "//Configuration/Common/Logging/Syslog/Facility";

    int mysec = 0;
    char *logFacilityName;
    int my_log_user = DEFAULT_LOG_FACILITY;
    int status;
    int db_found = 0;
    char* filename = CONFIG_FILE;
    char* rngfilename = SCHEMA_DIR "/conf.rng";

    char* temp_char = NULL;

    log_msg(config, LOG_INFO, "Reading config \"%s\"", filename);

    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"", filename);
        return(-1);
    }

    /* Load rng document */
    log_msg(config, LOG_INFO, "Reading config schema \"%s\"", rngfilename);
    rngdoc = xmlParseFile(rngfilename);
    if (rngdoc == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"", rngfilename);
        return(-1);
    }

    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to create XML RelaxNGs parser context");
        return(-1);
    }

    /* parse a schema definition resource and build an internal XML Shema struture which can be used to validate instances. */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to parse a schema definition resource");
        return(-1);
    }

    /* Create an XML RelaxNGs validation context based on the given schema */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to create RelaxNGs validation context based on the schema");
        return(-1);
    }

    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    if (status != 0) {
        log_msg(config, LOG_ERR, "Error validating file \"%s\"", filename);
        return(-1);
    }
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(rngdoc);

    /* Now parse a value out of the conf */
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        log_msg(config, LOG_ERR,"Error: unable to create new XPath context");
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Evaluate xpath expression for keygen interval */
    xpathObj = xmlXPathEvalExpression(ki_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", ki_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    temp_char = (char *)xmlXPathCastToString(xpathObj);
    status = DtXMLIntervalSeconds(temp_char, &mysec);
    if (status > 0) {
        log_msg(config, LOG_ERR, "Error: unable to convert interval %s to seconds, error: %i", temp_char, status);
        StrFree(temp_char);
        return status;
    }
    else if (status == -1) {
        log_msg(config, LOG_INFO, "Warning: converting %s to seconds may not give what you expect", temp_char);
    }
    config->keygeninterval = mysec;
    log_msg(config, LOG_INFO, "Key Generation Interval: %i", config->keygeninterval);
    StrFree(temp_char);
    xmlXPathFreeObject(xpathObj);

    /* Evaluate xpath expression for interval */
    /* TODO check that we can reuse xpathObj even if something has not worked */
    xpathObj = xmlXPathEvalExpression(iv_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", iv_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    temp_char = (char *)xmlXPathCastToString(xpathObj);
    status = DtXMLIntervalSeconds(temp_char, &mysec);
    if (status > 0) {
        log_msg(config, LOG_ERR, "Error: unable to convert interval %s to seconds, error: %i", temp_char, status);
        StrFree(temp_char);
        return status;
    }
    else if (status == -1) {
        log_msg(config, LOG_INFO, "Warning: converting %s to seconds may not give what you expect", temp_char);
    }
    config->interval = mysec;
    log_msg(config, LOG_INFO, "Communication Interval: %i", config->interval);
    StrFree(temp_char);
    xmlXPathFreeObject(xpathObj);

    /* Evaluate xpath expression for backup interval */
    xpathObj = xmlXPathEvalExpression(bi_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", bi_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    temp_char = (char *)xmlXPathCastToString(xpathObj);
    status = DtXMLIntervalSeconds(temp_char, &mysec);
    if (status > 0) {
        log_msg(config, LOG_ERR, "Error: unable to convert interval %s to seconds, error: %i", temp_char, status);
        StrFree(temp_char);
        return status;
    }
    else if (status == -1) {
        log_msg(config, LOG_INFO, "Warning: converting %s to seconds may not give what you expect", temp_char);
    }
    config->backupinterval = mysec;
    log_msg(config, LOG_INFO, "HSM Backup Interval: %i", config->backupinterval);
    StrFree(temp_char);
    xmlXPathFreeObject(xpathObj);

    /* Evaluate xpath expression for rollover notification interval */
    xpathObj = xmlXPathEvalExpression(rn_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", rn_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        /* Tag RolloverNotification is present; set rolloverNotify */
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        status = DtXMLIntervalSeconds(temp_char, &mysec);
        if (status > 0) {
            log_msg(config, LOG_ERR, "Error: unable to convert interval %s to seconds, error: %i", temp_char, status);
            StrFree(temp_char);
            return status;
        }
        else if (status == -1) {
            log_msg(config, LOG_INFO, "Warning: converting %s to seconds may not give what you expect", temp_char);
        }
        config->rolloverNotify = mysec;
        log_msg(config, LOG_INFO, "Rollover Notification Interval: %i", config->rolloverNotify);
        StrFree(temp_char);
        xmlXPathFreeObject(xpathObj);
    }
    else {
        /* Tag RolloverNotification absent, set rolloverNotify to -1 */
        config->rolloverNotify = -1;
    }

    /* Evaluate xpath expression for SQLite file location */
		
    xpathObj = xmlXPathEvalExpression(litexpr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", litexpr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }
    if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        db_found = SQLITE_DB;
        config->schema = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "SQLite database set to: %s", config->schema);
    }
    xmlXPathFreeObject(xpathObj);

    if (db_found == 0) {
        /* Get all of the MySQL stuff read in too */
        /* HOST */
        xpathObj = xmlXPathEvalExpression(mysql_host, xpathCtx);
		    if(xpathObj == NULL) {
		        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", mysql_host);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
            if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
           db_found = MYSQL_DB;
        }
        config->host = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "MySQL database host set to: %s", config->host);
        xmlXPathFreeObject(xpathObj);

        /* PORT */
        xpathObj = xmlXPathEvalExpression(mysql_port, xpathCtx);
        if(xpathObj == NULL) {
		        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", mysql_port);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
            if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
            db_found = 0;
        }
        config->port = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "MySQL database port set to: %s", config->port);
        xmlXPathFreeObject(xpathObj);

        /* SCHEMA */
        xpathObj = xmlXPathEvalExpression(mysql_db, xpathCtx);
        if(xpathObj == NULL) {
		        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", mysql_db);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
            if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
            db_found = 0;
        }
        config->schema = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "MySQL database schema set to: %s", config->schema);
        xmlXPathFreeObject(xpathObj);

        /* DB USER */
        xpathObj = xmlXPathEvalExpression(mysql_user, xpathCtx);
        if(xpathObj == NULL) {
		        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", mysql_user);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
            if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
            db_found = 0;
        }
        config->user = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "MySQL database user set to: %s", config->user);
        xmlXPathFreeObject(xpathObj);

        /* DB PASSWORD */
        xpathObj = xmlXPathEvalExpression(mysql_pass, xpathCtx);
        if(xpathObj == NULL) {
		        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", mysql_pass);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
		    /* password may be blank */
        
        config->password = xmlXPathCastToString(xpathObj);
        log_msg(config, LOG_INFO, "MySQL database password set");
        xmlXPathFreeObject(xpathObj);

    }

    /* Check that we found one or the other database */
    if(db_found == 0) {
        log_msg(config, LOG_ERR, "Error: unable to find complete database connection expression in %s", filename);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Check that we found the right database type */
    if (db_found != DbFlavour()) {
        log_msg(config, LOG_ERR, "Error: database in config file %s does not match libksm", filename);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Evaluate xpath expression for log facility (user) */
    xpathObj = xmlXPathEvalExpression(log_user_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", log_user_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    temp_char = (char *)xmlXPathCastToString(xpathObj);
    logFacilityName =  StrStrdup( temp_char );
    StrFree(temp_char);
    xmlXPathFreeObject(xpathObj);

    /* If nothing was found use the defaults, else set what we got */
    if (strlen(logFacilityName) == 0) {
        logFacilityName = StrStrdup( (char *)DEFAULT_LOG_FACILITY_STRING );
        config->log_user = DEFAULT_LOG_FACILITY;
        log_msg(config, LOG_INFO, "Using default log user: %s", logFacilityName);
    } else {
        status = get_log_user(logFacilityName, &my_log_user);
        if (status > 0) {
            log_msg(config, LOG_ERR, "Error: unable to set log user: %s, error: %i", logFacilityName, status);
            StrFree(logFacilityName);
            return status;
        }
        config->log_user = my_log_user;
        log_msg(config, LOG_INFO, "Log User set to: %s", logFacilityName);
    }

    log_switch(my_log_user, logFacilityName, config->program);

    /* Cleanup */
    /* TODO: some other frees are needed */
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
    StrFree(logFacilityName);

    return(0);

}

/* To overcome the potential differences in sqlite compile flags assume that it is not
   happy with multiple connections.

   The following 2 functions take out a lock and release it
*/

int get_lite_lock(char *lock_filename, FILE* lock_fd)
{
    struct flock fl;
    struct timeval tv;

    if (lock_fd == NULL) {
        log_msg(NULL, LOG_ERR, "%s could not be opened", lock_filename);
        return 1;
    }

    memset(&fl, 0, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_pid = getpid();
    
    while (fcntl(fileno(lock_fd), F_SETLK, &fl) == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            log_msg(NULL, LOG_INFO, "%s already locked, sleep", lock_filename);

            /* sleep for 10 seconds TODO make this configurable? */
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            select(0, NULL, NULL, NULL, &tv);

        } else {
            log_msg(NULL, LOG_INFO, "couldn't get lock on %s, %s", lock_filename, strerror(errno));
            return 1;
        }
    }

    return 0;

}

int release_lite_lock(FILE* lock_fd)
{
    struct flock fl;

    if (lock_fd == NULL) {
        return 1;
    }
    
    memset(&fl, 0, sizeof(struct flock));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fileno(lock_fd), F_SETLK, &fl) == -1) {
        return 1;
    }

    return 0;
}

/* convert the name of a log facility (user) into a number */
int get_log_user(const char* username, int* usernumber)
{
    char* case_username = NULL;

    if (username == NULL) {
        return 1;
    }
    /* Start with our default */
    *usernumber = DEFAULT_LOG_FACILITY;

    case_username = StrStrdup(username);
    (void) StrToUpper(case_username);

    /* POSIX only specifies LOG_USER and LOG_LOCAL[0 .. 7] */
    if (strncmp(case_username, "USER", 4) == 0) {
        *usernumber = LOG_USER;
    }
#ifdef LOG_KERN
    else if (strncmp(case_username, "KERN", 4) == 0) {
        *usernumber = LOG_KERN;
    }
#endif  /* LOG_KERN */
#ifdef LOG_MAIL
    else if (strncmp(case_username, "MAIL", 4) == 0) {
        *usernumber = LOG_MAIL;
    }
#endif  /* LOG_MAIL */
#ifdef LOG_DAEMON
    else if (strncmp(case_username, "DAEMON", 6) == 0) {
        *usernumber = LOG_DAEMON;
    }
#endif  /* LOG_DAEMON */
#ifdef LOG_AUTH
    else if (strncmp(case_username, "AUTH", 4) == 0) {
        *usernumber = LOG_AUTH;
    }
#endif  /* LOG_AUTH */
#ifdef LOG_SYSLOG
    else if (strncmp(case_username, "SYSLOG", 6) == 0) {
        *usernumber = LOG_SYSLOG;
    }
#endif  /* LOG_SYSLOG */
#ifdef LOG_LPR
    else if (strncmp(case_username, "LPR", 3) == 0) {
        *usernumber = LOG_LPR;
    }
#endif  /* LOG_LPR */
#ifdef LOG_NEWS
    else if (strncmp(case_username, "NEWS", 4) == 0) {
        *usernumber = LOG_NEWS;
    }
#endif  /* LOG_NEWS */
#ifdef LOG_UUCP
    else if (strncmp(case_username, "UUCP", 4) == 0) {
        *usernumber = LOG_UUCP;
    }
#endif  /* LOG_UUCP */
#ifdef LOG_AUDIT    /* Ubuntu at least doesn't want us to use LOG_AUDIT */
    else if (strncmp(case_username, "AUDIT", 5) == 0) {
        *usernumber = LOG_AUDIT;
    }
#endif  /* LOG_AUDIT */
#ifdef LOG_CRON
    else if (strncmp(case_username, "CRON", 4) == 0) {
        *usernumber = LOG_CRON;
    }
#endif  /* LOG_CRON */
    else if (strncmp(case_username, "LOCAL0", 6) == 0) {
        *usernumber = LOG_LOCAL0;
    }
    else if (strncmp(case_username, "LOCAL1", 6) == 0) {
        *usernumber = LOG_LOCAL1;
    }
    else if (strncmp(case_username, "LOCAL2", 6) == 0) {
        *usernumber = LOG_LOCAL2;
    }
    else if (strncmp(case_username, "LOCAL3", 6) == 0) {
        *usernumber = LOG_LOCAL3;
    }
    else if (strncmp(case_username, "LOCAL4", 6) == 0) {
        *usernumber = LOG_LOCAL4;
    }
    else if (strncmp(case_username, "LOCAL5", 6) == 0) {
        *usernumber = LOG_LOCAL5;
    }
    else if (strncmp(case_username, "LOCAL6", 6) == 0) {
        *usernumber = LOG_LOCAL6;
    }
    else if (strncmp(case_username, "LOCAL7", 6) == 0) {
        *usernumber = LOG_LOCAL7;
    }

    StrFree(case_username);

    return 0;

}

