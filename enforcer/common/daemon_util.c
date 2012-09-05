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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <syslog.h>

#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

#include "daemon.h"
#include "daemon_util.h"

#include "ksm/database.h"
#include "ksm/datetime.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"
#include "ksm/message.h"


/**
 * Use _r() functions on platforms that have. They are thread safe versions of
 * the normal syslog functions. Platforms without _r() usually have thread safe
 * normal functions.
 */
#if defined(HAVE_SYSLOG_R) && defined(HAVE_OPENLOG_R) && defined(HAVE_CLOSELOG_R) && defined(HAVE_VSYSLOG_R)
struct syslog_data sdata = SYSLOG_DATA_INIT;
#else
#undef HAVE_SYSLOG_R
#undef HAVE_OPENLOG_R
#undef HAVE_CLOSELOG_R
#undef HAVE_VSYSLOG_R
#endif

    int
getPermsForDrop(DAEMONCONFIG* config)
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

    char* filename = NULL;
    char* rngfilename = OPENDNSSEC_SCHEMA_DIR "/conf.rng";
    char* temp_char = NULL;

    struct passwd *pwd;
    struct group  *grp;

    FILE *file;

    if (config->configfile != NULL) {
        filename = StrStrdup(config->configfile);
    } else {
        filename = StrStrdup(OPENDNSSEC_CONFIG_FILE);
    }

    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        /* To get a better error message try to open the file */
        file = fopen(filename, "r");
        if (file == NULL) {
            log_msg(config, LOG_ERR, "Error: unable to open file \"%s\"", filename);
        } else {
            log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"", filename);
            fclose(file);
        }
        return(-1);
    }

    /* Load rng document */
    rngdoc = xmlParseFile(rngfilename);
    if (rngdoc == NULL) {
        /* To get a better error message try to open the file */
        file = fopen(rngfilename, "r");
        if (file == NULL) {
            log_msg(config, LOG_ERR, "Error: unable to open file \"%s\"", rngfilename);
        } else {
            log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"", rngfilename);
            fclose(file);
        }
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

    xmlRelaxNGSetValidErrors(rngctx,
		(xmlRelaxNGValidityErrorFunc) log_xml_error,
		(xmlRelaxNGValidityWarningFunc) log_xml_warn,
		NULL);

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

    /* Set the group if specified */
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
    } else {
        config->groupname = NULL;
    }

    /* Set the user to drop to if specified */
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
    } else {
        config->username = NULL;
    }

    /* Set uid and gid if required */
    if (config->username != NULL) {
        /* Lookup the user id in /etc/passwd */
        if ((pwd = getpwnam(config->username)) == NULL) {
#ifdef HAVE_SYSLOG_R
            syslog_r(LOG_ERR, &sdata, "user '%s' does not exist. exiting...\n", config->username);
#else
            syslog(LOG_ERR, "user '%s' does not exist. exiting...\n", config->username);
#endif
            exit(1);
        } else {
            config->uid = pwd->pw_uid;
        }
        endpwent();
    }
    if (config->groupname) {
        /* Lookup the group id in /etc/groups */
        if ((grp = getgrnam(config->groupname)) == NULL) {
#ifdef HAVE_SYSLOG_R
            syslog_r(LOG_ERR, &sdata, "group '%s' does not exist. exiting...\n", config->groupname);
#else
            syslog(LOG_ERR, "group '%s' does not exist. exiting...\n", config->groupname);
#endif
            exit(1);
        } else {
            config->gid = grp->gr_gid;
        }
        endgrent();
    }

    xmlXPathFreeContext(xpathCtx);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(doc);
    xmlFreeDoc(rngdoc);
    StrFree(filename);

    return 0;
}

/* Set up logging as per default (facility may be switched based on config file) */
void log_init(int facility, const char *program_name)
{
#ifdef HAVE_OPENLOG_R
	openlog_r(program_name, 0, facility, &sdata);
#else
	openlog(program_name, 0, facility);
#endif
}

/* Switch log to new facility */
void log_switch(int facility, const char *facility_name, const char *program_name, int verbose)
{
#ifdef HAVE_CLOSELOG_R
    closelog_r(&sdata);
#else
    closelog();
#endif
#ifdef HAVE_OPENLOG_R
	openlog_r(program_name, 0, facility, &sdata);
#else
	openlog(program_name, 0, facility);
#endif
    if (verbose) {
        log_msg(NULL, LOG_INFO, "Switched log facility to: %s", facility_name);
    }
}


void
log_msg(DAEMONCONFIG *config, int priority, const char *format, ...)
{
    /* If the variable arg list is bad then random errors can occur */ 
    va_list args;
#ifdef KSM_DB_USE_THREADS
    char *prefix;
#endif
    if (config && config->debug) priority = LOG_ERR;
    va_start(args, format);
#ifdef KSM_DB_USE_THREADS
    if ((prefix = MsgThreadGetPrefix())) {
        char buffer[4096];

        vsnprintf(buffer, 4096, format, args);
        va_end(args);

#ifdef HAVE_SYSLOG_R
        syslog_r(priority, &sdata, "%s%s", prefix, buffer);
#else
        syslog(priority, "%s%s", prefix, buffer);
#endif
    }
    else {
#endif
#ifdef HAVE_VSYSLOG_R
    vsyslog_r(priority, &sdata, format, args);
#else
    vsyslog(priority, format, args);
    va_end(args);
#endif
#ifdef KSM_DB_USE_THREADS
    }
#endif
}

/*
 * log function suitable for libksm callback
 */
    void
ksm_log_msg(const char *format)
{
    if (strncmp(format, "ERROR:", 6) == 0) {
#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_ERR, &sdata, "%s", format);
#else
        syslog(LOG_ERR, "%s", format);
#endif
    }
    else if (strncmp(format, "INFO:", 5) == 0) {
#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_INFO, &sdata, "%s", format);
#else
        syslog(LOG_INFO, "%s", format);
#endif
    }
    else if (strncmp(format, "WARNING:", 8) == 0) {
#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_WARNING, &sdata, "%s", format);
#else
        syslog(LOG_WARNING, "%s", format);
#endif
    }
    else if (strncmp(format, "DEBUG:", 6) == 0) {
#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_DEBUG, &sdata, "%s", format);
#else
        syslog(LOG_DEBUG, "%s", format);
#endif
    }
    else {
#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_ERR, &sdata, "%s", format);
#else
        syslog(LOG_ERR, "%s", format);
#endif
    }
}

/* XML Error Message */
    void
log_xml_error(void *ignore, const char *format, ...)
{
    va_list args;
#ifdef KSM_DB_USE_THREADS
    char *prefix;
#endif

    (void) ignore;

#ifdef KSM_DB_USE_THREADS
    if ((prefix = MsgThreadGetPrefix())) {
        char buffer[4096];

        vsnprintf(buffer, 4096, format, args);
        va_end(args);

#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_ERR, &sdata, "%s%s", prefix, buffer);
#else
        syslog(LOG_ERR, "%s%s", prefix, buffer);
#endif
    }
    else {
#endif
    /* If the variable arg list is bad then random errors can occur */ 
    va_start(args, format);
#ifdef HAVE_VSYSLOG_R
    vsyslog_r(LOG_ERR, &sdata, format, args);
#else
    vsyslog(LOG_ERR, format, args);
#endif
    va_end(args);
#ifdef KSM_DB_USE_THREADS
    }
#endif
}

/* XML Warning Message */
    void
log_xml_warn(void *ignore, const char *format, ...)
{
    va_list args;
#ifdef KSM_DB_USE_THREADS
    char *prefix;
#endif

    (void) ignore;

#ifdef KSM_DB_USE_THREADS
    if ((prefix = MsgThreadGetPrefix())) {
        char buffer[4096];

        vsnprintf(buffer, 4096, format, args);
        va_end(args);

#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_INFO, &sdata, "%s%s", prefix, buffer);
#else
        syslog(LOG_INFO, "%s%s", prefix, buffer);
#endif
    }
    else {
#endif
    /* If the variable arg list is bad then random errors can occur */ 
    va_start(args, format);
#ifdef HAVE_VSYSLOG_R
    vsyslog_r(LOG_INFO, &sdata, format, args);
#else
    vsyslog(LOG_INFO, format, args);
#endif
    va_end(args);
#ifdef KSM_DB_USE_THREADS
    }
#endif
}

    static void
usage(const char* prog)
{
    fprintf(stderr, "Usage: %s [OPTION]...\n", prog);
    fprintf(stderr, "OpenDNSSEC Enforcer version %s\n\n", VERSION);
    fprintf(stderr, "Supported options:\n");
    fprintf(stderr, "  -c <file>   Use alternate conf.xml.\n");
    fprintf(stderr, "  -d          Debug.\n");
    fprintf(stderr, "  -1          Run once, then exit.\n");
/*    fprintf(stderr, "  -u user     Change effective uid to the specified user.\n");*/
    fprintf(stderr, "  -P pidfile  Specify the PID file to write.\n");

    fprintf(stderr, "  -V          Print version.\n");
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

    static pid_t
readpid(const char *file)
{
    int fd;
    pid_t pid;
    char pidbuf[32];
    char *t;
    int l;

    if ((fd = open(file, O_RDONLY)) == -1) {
        return -1;
    }
    if (((l = read(fd, pidbuf, sizeof(pidbuf)))) == -1) {
        close(fd);
        return -1;
    }
    close(fd);
    /* Empty pidfile means no pidfile... */
    if (l == 0) {
        errno = ENOENT;
        return -1;
    }
    pid = strtol(pidbuf, &t, 10);

    if (*t && *t != '\n') {
        return -1;
    }
    return pid;
}

    int
writepid (DAEMONCONFIG *config)
{
    FILE * fd;
    char pidbuf[32];
    struct stat stat_ret;
    pid_t oldpid;

    /* If the file exists then either we didn't shutdown cleanly or an enforcer is
     * already running; in either case shutdown */
    if (stat(config->pidfile, &stat_ret) != 0) {

        if (errno != ENOENT) {
            log_msg(config, LOG_ERR, "cannot stat pidfile %s: %s",
                    config->pidfile, strerror(errno));
            return -1;
        }
    } else {
        if (S_ISREG(stat_ret.st_mode)) {
            /* The file exists already */
            if ((oldpid = readpid(config->pidfile)) == -1) {
                /* consider stale pidfile */
                if (errno != ENOENT) {
                    log_msg(config, LOG_ERR, "cannot read pidfile %s: %s",
                        config->pidfile, strerror(errno));
                }
            } else {
                if (kill(oldpid, 0) == 0 || errno == EPERM) {
                    log_msg(config, LOG_ERR, "pidfile %s already exists, "
                        "a process with pid %u is already running. "
                        "If no ods-enforcerd process is running, a previous "
                        "instance didn't shutdown cleanly, please remove this "
                        "file and try again.", config->pidfile, oldpid);
                    exit(1);
                } else {
                    log_msg(config, LOG_WARNING, "pidfile %s already exists, "
                        "but no process with pid %u is running. "
                        "A previous instance didn't shutdown cleanly, this "
                        "pidfile is stale.", config->pidfile, oldpid);
                }
            }
        }
    }

    /* All good, carry on */
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
        log_msg(config, LOG_ERR, "cannot chown(%u,%u) %s: %s",
                (unsigned) config->uid, (unsigned) config->gid,
                config->pidfile, strerror(errno));
        return -1;
    }

    /* Mark this our pidfile so exit_function unlink's it */
    daemon_our_pidfile = 1;
    return 0;
}

    int
createPidDir (DAEMONCONFIG *config)
{
    char* directory = NULL;
    char* slash;
    struct stat stat_ret;
    char *path = getenv("PWD");

    /* Find the directory part of the (fully qualified) pidfile */
    if (*config->pidfile != '/') {
        StrAppend(&directory, path);
        StrAppend(&directory, "/");
        StrAppend(&directory, config->pidfile);
    } else {
        directory = StrStrdup(config->pidfile);
    }
    slash = strrchr(directory, '/');
    *slash = 0;

    /* Check that it exists */
    if (stat(directory, &stat_ret) != 0) {

        if (errno != ENOENT) {
            log_msg(config, LOG_ERR, "cannot stat directory %s: %s",
                    directory, strerror(errno));
            return -1;
        }
    }

    if (S_ISDIR(stat_ret.st_mode)) {
        /* Do nothing, the directory exists already */
    } else {
        /* try to create it */
        if (make_directory(config, directory) != 0) {
            StrFree(directory);
            return -1;
        }
    }
    StrFree(directory);

    return 0;
}

int make_directory(DAEMONCONFIG* config, const char* path) {

    char* parent;
    char* slash;
    struct stat stat_ret;

    parent = StrStrdup(path);
    slash = strrchr(parent, '/');

    *slash = 0;

    stat(parent, &stat_ret);

    if (!S_ISDIR(stat_ret.st_mode)) {

        make_directory(config, parent);

    }

    StrFree(parent);

    if (mkdir(path, (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) != 0) {
        log_msg(NULL, LOG_ERR, "cannot create directory %s: %s\n",
                path, strerror(errno));
        return 1;
    }
    

    if (chown(path, config->uid, config->gid) == -1) {
        log_msg(config, LOG_ERR, "cannot chown(%u,%u) %s: %s",
                (unsigned) config->uid, (unsigned) config->gid,
                path, strerror(errno));
        return 1;
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
    while ((c = getopt(*argc, argv, "1c:hdV?u:P:")) != -1) {
        switch (c) {
            case '1':
                config->once = true;
                break;
            case 'c':
                config->configfile = optarg;
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
            case 'V':
                version();
                exit(0);
            default:
                usage(config->program);
                exit(0);
        }
    }
}

/*
 * Returns 0 if the the config file could be read and non-zero if it could not.
 *
 * Any function calling this should exit on a non-zero return.
 */
int
ReadConfig(DAEMONCONFIG *config, int verbose)
{
    xmlDocPtr doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;
    xmlChar *iv_expr = (unsigned char*) "//Configuration/Enforcer/Interval";
    xmlChar *mk_expr = (unsigned char*) "//Configuration/Enforcer/ManualKeyGeneration";
    xmlChar *rn_expr = (unsigned char*) "//Configuration/Enforcer/RolloverNotification";
    xmlChar *ds_expr = (unsigned char*) "//Configuration/Enforcer/DelegationSignerSubmitCommand";
    xmlChar *litexpr = (unsigned char*) "//Configuration/Enforcer/Datastore/SQLite";
    xmlChar *mysql_host = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Host";
    xmlChar *mysql_port = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Host/@port";
    xmlChar *mysql_db = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Database";
    xmlChar *mysql_user = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Username";
    xmlChar *mysql_pass = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Password";
    xmlChar *log_user_expr = (unsigned char*) "//Configuration/Common/Logging/Syslog/Facility";
#ifdef ENFORCER_USE_WORKERS
    xmlChar *ew_expr = (unsigned char*) "//Configuration/Enforcer/WorkerThreads";
#endif

    int mysec = 0;
    char *logFacilityName;
    int my_log_user = DEFAULT_LOG_FACILITY;
    int status;
    int db_found = 0;
    char* filename = NULL;
    char* rngfilename = OPENDNSSEC_SCHEMA_DIR "/conf.rng";

    char* temp_char = NULL;
    char* str = NULL; /* used to split DSSub command */

    FILE *file;

    /* Change the config file location if one was provided on the command line */
    if (config->configfile != NULL) {
        filename = StrStrdup(config->configfile);
    } else {
        filename = StrStrdup(OPENDNSSEC_CONFIG_FILE);
    }

    if (verbose) {
        log_msg(config, LOG_INFO, "Reading config \"%s\"", filename);
    }

    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        /* To get a better error message try to open the file */
        file = fopen(filename, "r");
        if (file == NULL) {
            log_msg(config, LOG_ERR, "Error: unable to open file \"%s\"", filename);
        } else {
            log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"", filename);
            fclose(file);
        }
        return(-1);
    }

    /* Load rng document */
    if (verbose) {
        log_msg(config, LOG_INFO, "Reading config schema \"%s\"", rngfilename);
    }
    rngdoc = xmlParseFile(rngfilename);
    if (rngdoc == NULL) {
        /* To get a better error message try to open the file */
        file = fopen(rngfilename, "r");
        if (file == NULL) {
            log_msg(config, LOG_ERR, "Error: unable to open file \"%s\"", rngfilename);
        } else {
            log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"", rngfilename);
            fclose(file);
        }
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

    xmlRelaxNGSetValidErrors(rngctx,
		(xmlRelaxNGValidityErrorFunc) log_xml_error,
		(xmlRelaxNGValidityWarningFunc) log_xml_warn,
		NULL);

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

#ifdef ENFORCER_USE_WORKERS
    xpathObj = xmlXPathEvalExpression(ew_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", ew_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }
    config->enforcer_workers = ENFORCER_WORKER_THREADS;
    if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        config->enforcer_workers = (int)xmlXPathCastToNumber(xpathObj);
    }
    if (verbose) {
#ifdef USE_MYSQL
        log_msg(config, LOG_INFO, "Using %d enforcer workers", config->enforcer_workers);
#else
        log_msg(config, LOG_INFO, "Wrong database backend for enforcer workers, forcing single thread operation");
        config->enforcer_workers = 1;
#endif
    }
    xmlXPathFreeObject(xpathObj);
#endif

    /* Evaluate xpath expression for interval */
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
        log_msg(config, LOG_ERR, "Error: unable to convert Interval %s to seconds, error: %i", temp_char, status);
        StrFree(temp_char);
        return status;
    }
    else if (status == -1) {
        log_msg(config, LOG_INFO, "Info: converting %s to seconds; M interpreted as 31 days, Y interpreted as 365 days", temp_char);
    }
    config->interval = mysec;
    if (verbose) {
        log_msg(config, LOG_INFO, "Communication Interval: %i", config->interval);
    }
    StrFree(temp_char);
    xmlXPathFreeObject(xpathObj);

    /* Evaluate xpath expression for Manual key generation */
    xpathObj = xmlXPathEvalExpression(mk_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", mk_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        /* Manual key generation tag is present */
        config->manualKeyGeneration = 1;
    }
    else {
        /* Tag absent */
        config->manualKeyGeneration = 0;
    }
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
            log_msg(config, LOG_ERR, "Error: unable to convert RolloverNotification %s to seconds, error: %i", temp_char, status);
            StrFree(temp_char);
            return status;
        }
        else if (status == -1) {
        log_msg(config, LOG_INFO, "Info: converting %s to seconds; M interpreted as 31 days, Y interpreted as 365 days", temp_char);
        }
        config->rolloverNotify = mysec;
        if (verbose) {
            log_msg(config, LOG_INFO, "Rollover Notification Interval: %i", config->rolloverNotify);
        }
        StrFree(temp_char);
        xmlXPathFreeObject(xpathObj);
    }
    else {
        /* Tag RolloverNotification absent, set rolloverNotify to -1 */
        config->rolloverNotify = -1;
    }

    /* Evaluate xpath expression for DelegationSignerSubmitCommand */
    xpathObj = xmlXPathEvalExpression(ds_expr, xpathCtx);
    if(xpathObj == NULL) {
        log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s", ds_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }
    if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        /* Tag DelegationSignerSubmitCommand is present; set DSSubmitCmd */
        if (config->DSSubmitCmd != NULL) {
            StrFree(config->DSSubmitCmd);
        }
        config->DSSubmitCmd = (char *)xmlXPathCastToString(xpathObj);

		/* If the string ends " --cka_id" strip that off and set flag */
		str = strstr(config->DSSubmitCmd, " --cka_id");
		if (str) {
			config->DSSubCKA_ID = 1;
			*str = 0;
		} else {
			config->DSSubCKA_ID = 0;
		}

        if (verbose) {
            log_msg(config, LOG_INFO, "Using command: %s to submit DS records", config->DSSubmitCmd);
        }
        xmlXPathFreeObject(xpathObj);
    } else {
        if (verbose) {
            log_msg(config, LOG_INFO, "No DS Submit command supplied");
        }
        config->DSSubmitCmd[0] = '\0';
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
        if (config->schema != NULL) {
            StrFree(config->schema);
        }
        config->schema = xmlXPathCastToString(xpathObj);
        if (verbose) {
            log_msg(config, LOG_INFO, "SQLite database set to: %s", config->schema);
        }
    }
    xmlXPathFreeObject(xpathObj);

    if (db_found == 0) {
        db_found = MYSQL_DB;

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
            if (config->host != NULL) {
                StrFree(config->host);
            }
            config->host = xmlXPathCastToString(xpathObj);
            if (verbose) {
                log_msg(config, LOG_INFO, "MySQL database host set to: %s", config->host);
            }
        }
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
            if (config->port != NULL) {
                StrFree(config->port);
            }
            config->port = xmlXPathCastToString(xpathObj);
            if (verbose) {
                log_msg(config, LOG_INFO, "MySQL database port set to: %s", config->port);
            }
        }
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
            if (config->schema != NULL) {
                StrFree(config->schema);
            }
            config->schema = xmlXPathCastToString(xpathObj);
            if (verbose) {
                log_msg(config, LOG_INFO, "MySQL database schema set to: %s", config->schema);
            }
        } else {
            db_found = 0;
        }
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
            if (config->user != NULL) {
                StrFree(config->user);
            }
            config->user = xmlXPathCastToString(xpathObj);
            if (verbose) {
                log_msg(config, LOG_INFO, "MySQL database user set to: %s", config->user);
            }
        } else {
            db_found = 0;
        }
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
        
        if (config->password != NULL) {
            StrFree(config->password);
        }
        config->password = xmlXPathCastToString(xpathObj);
        if (verbose) {
            log_msg(config, LOG_INFO, "MySQL database password set");
        }
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
        log_msg(config, LOG_ERR, "Error: Config file %s specifies database type %s but system is compiled to use %s", filename, (db_found==1) ? "MySQL" : "sqlite3", (db_found==2) ? "MySQL" : "sqlite3");
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

    if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        /* tag present */
        logFacilityName = (char *)xmlXPathCastToString(xpathObj);

        status = get_log_user(logFacilityName, &my_log_user);
        if (status > 0) {
            log_msg(config, LOG_ERR, "Error: unable to set log user: %s, error: %i", logFacilityName, status);
            StrFree(logFacilityName);
            return status;
        }
        config->log_user = my_log_user;
        if (verbose) {
            log_msg(config, LOG_INFO, "Log User set to: %s", logFacilityName);
        }

    } else {
        /* tag _not_ present, use default */
        logFacilityName = StrStrdup( (char *)DEFAULT_LOG_FACILITY_STRING );
        config->log_user = DEFAULT_LOG_FACILITY;
        if (verbose) {
            log_msg(config, LOG_INFO, "Using default log user: %s", logFacilityName);
        }
    }

    xmlXPathFreeObject(xpathObj);

    log_switch(my_log_user, logFacilityName, config->program, verbose);

    /* Cleanup */
    /* TODO: some other frees are needed */
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
    StrFree(logFacilityName);
    StrFree(filename);

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

