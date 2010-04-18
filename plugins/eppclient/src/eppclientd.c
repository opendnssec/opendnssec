/*
 * $Id$
 *
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation).
 * All rights reserved.
 *
 * Written by Björn Stenberg <bjorn@haxx.se> for .SE
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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>
#include <sqlite3.h>
#include <errno.h>
#include <ctype.h>
#include <ldns/ldns.h>

#include "eppconfig.h"
#include "epp.h"

void usage()
{
    printf("OpenDNSSEC EPP plugin\n");
    printf("Usage: eppclientd [OPTIONS]\n");
    printf("Options:\n");
    printf("  -h                Show this help screen.\n");
    printf("  --help            Show this help screen.\n");
    printf("  -v                Show version info.\n");
    printf("  --version         Show version info.\n");
    printf("\n");
    printf("\n");
    printf("eppclientd is a daemon used by the eppclient plugin for the OpenDNSSEC software.\n");
    printf("It performs key updates to registries using the EPP protocol.\n");
    printf("\n");
    printf("More information is available in the corresponding man page.\n");
}

enum {
    OPT_HELP = 0x100,
    OPT_VERSION
};

static const struct option long_options[] = {
    { "help",            0, NULL, OPT_HELP },
    { "version",         0, NULL, OPT_VERSION },
    { NULL,              0, NULL, 0 }
};

#define MAX_KEY_COUNT 100 /* max # of keys per update */

static sqlite3* db = NULL;

void signal_handler(int sig)
{
    switch(sig) {
	case SIGHUP:
            syslog(LOG_INFO, "got SIGHUP");
            break;

	case SIGTERM:
            syslog(LOG_INFO, "killed. exiting.");
            unlink(config_value("/eppclient/pipe"));
            unlink(config_value("/eppclient/pidfile"));
            exit(0);
            break;
    }
}

void init_sqlite(void)
{
    /* prepare sqlite */
    const char* dbname = config_value("/eppclient/database");
    int rc = sqlite3_open(dbname, &db);
    if (rc) {
        syslog(LOG_ERR, "Can't open %s: %s", dbname, sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }
}

int init()
{
    openlog("eppclientd", 0, LOG_USER);

    int i;
#ifndef DEBUG
    i = fork();
    if (i<0) {
        syslog(LOG_ERR, "fork error");
        exit(1); /* fork error */
    }
    if (i>0)
        exit(0); /* parent exits */
#endif
    /* child (daemon) continues */
    setsid(); /* obtain a new process group */
    for (i=sysconf(_SC_OPEN_MAX)-1; i>=0; --i)
        close(i); /* close all descriptors */
    /* open dummy stdin/-out/-err */
    i=open("/dev/null",O_RDWR);
    if (i < 0) {
        syslog(LOG_ERR, "Failed opening /dev/null");
        exit(1);
    }
    dup(i);
    dup(i); /* handle standard I/O */

    umask(027); /* set newly created file permissions */
#ifndef DEBUG
    chdir("/"); /* change running directory */
#endif
    read_config();

    char* pidfile = config_value("/eppclient/pidfile");
    int fd = open(pidfile, O_RDONLY);
    if (fd >= 0) {
        char buf[10] = {0};
        read(fd, buf, sizeof buf);
        int pid = atoi(buf);
        if (pid)
            if (kill(pid, 0) == ESRCH)
                unlink(pidfile);
        close(fd);
    }
    fd = open(pidfile, O_RDWR|O_CREAT, 0640);
    if (fd < 0) {
        syslog(LOG_ERR, "Pidfile %s: %s", pidfile, strerror(errno));
        exit(1); /* can not open */
    }
    if (lockf(fd,F_TLOCK,0) < 0) {
        syslog(LOG_ERR, "Daemon already running");
        exit(0); /* can not lock */
    }
    char str[10];
    snprintf(str,sizeof str,"%d\n",(unsigned int) getpid());
    int len = strlen(str);
    /* record pid to lockfile */
    if (write(fd,str,len) < len) {
        syslog(LOG_ERR, "Failed writing pid: errno %d", errno);
        exit(1);
    }
    fsync(fd);

    signal(SIGCHLD,SIG_IGN); /* ignore child */
    signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGHUP,signal_handler); /* catch hangup signal */
    signal(SIGTERM,signal_handler); /* catch kill signal */

    /* prepare sqlite */
    init_sqlite();

    /* ensure database has the necessary tables */
    int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", 0,0,0);
    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS jobs (job INTEGER PRIMARY KEY, zone TEXT, firsttry INTEGER);",0,0,0);
    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS keys (job NUMERIC, key TEXT);",0,0,0);
    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS registries (registry TEXT UNIQUE, lasttry INTEGER);",0,0,0);
    rc = sqlite3_exec(db, "END TRANSACTION;",0,0,0);

    char* pipename = config_value("/eppclient/pipe");
    unlink(pipename);
    if (mkfifo(pipename, 0660)) {
        syslog(LOG_ERR, "%s: %s", pipename, strerror(errno));
        exit(1);
    }

    int pipe = open(pipename, O_RDWR | O_NONBLOCK);
    if (pipe < 0) {
        syslog(LOG_ERR, "%s: %s", pipename, strerror(errno));
        exit(1);
    }
    fchmod(pipe, 0660); /* let group write to pipe */

    syslog(LOG_INFO, "started");
    return pipe;
}

void cleanup(int pipe)
{
    close(pipe);
    sqlite3_close(db);
}

int count_jobs(void)
{
    sqlite3_stmt* sth;
    int rc = sqlite3_prepare_v2(db, "SELECT count(*) FROM jobs",
                                -1, &sth, NULL);
    int count = -1;
    while (1) {
        rc = sqlite3_step(sth);
        switch (rc) {
            case 100: /* row */
                count = sqlite3_column_int(sth, 0);
                break;

            case 101: /* done */
                sqlite3_finalize(sth);
                return count;
                
            default:
                syslog(LOG_ERR, "%d: step() gave error: %d", __LINE__, rc);
                return -1;
        }
    }

    return -1;
}

static int delete_job(int job)
{
    int rc;
    char buf[80];
    syslog(LOG_DEBUG, "Deleting job %d", job);
    snprintf(buf, sizeof buf, "DELETE FROM keys WHERE job = %d;", job);
    rc = sqlite3_exec(db, buf, 0,0,0);
    snprintf(buf, sizeof buf, "DELETE FROM jobs WHERE job = %d;", job);
    rc = sqlite3_exec(db, buf, 0,0,0);

    return rc;
}

static void ack_server(char* zone)
{
    char* ack = config_value("/eppclient/ackcommand");
    if (ack) {
        char cmdline[256];
        snprintf(cmdline, sizeof cmdline, ack, zone);
        system(cmdline);
        syslog(LOG_DEBUG, "Executing '%s'", cmdline);
    }
}

static time_t get_registry_time(char* registry)
{
    sqlite3_stmt* sth;
    char sql[160];
    snprintf(sql, sizeof sql,
             "SELECT lasttry FROM registries WHERE registry = \"%s\"", registry);
    sqlite3_prepare_v2(db, sql, -1, &sth, NULL);
    int rc = sqlite3_step(sth);
    if (rc < 100) {
        syslog(LOG_ERR, "%d:sqlite says %s",
               __LINE__, sqlite3_errmsg(db));
        sqlite3_finalize(sth);
        return 0;
    }
    int lasttry = sqlite3_column_int(sth, 0);
    sqlite3_finalize(sth);

    return lasttry;
}

static void set_registry_time(char* registry, time_t value)
{
    sqlite3_stmt* sth;
    char sql[80];
    snprintf(sql, sizeof sql, "INSERT OR REPLACE INTO registries(registry, lasttry) VALUES ('%s', %d)",
             registry, (int)value);
    sqlite3_prepare_v2(db, sql, -1, &sth, NULL);
    sqlite3_step(sth);
    sqlite3_finalize(sth);
}

static void set_job_time(int job, time_t value)
{
    sqlite3_stmt* sth;
    char sql[80];
    snprintf(sql, sizeof sql, "UPDATE jobs SET firsttry = %d WHERE job = %d",
             (int)value, job);
    sqlite3_prepare_v2(db, sql, -1, &sth, NULL);
    sqlite3_step(sth);
    sqlite3_finalize(sth);
}

static void send_keys(void)
{
    sqlite3_stmt* sth;

    /* get first job */
    sqlite3_prepare_v2(db,
                       "SELECT job,zone,firsttry FROM jobs ORDER BY job LIMIT 1",
                       -1, &sth, NULL);
    int rc = sqlite3_step(sth);
    if (rc < 100) {
        syslog(LOG_ERR, "%d:sqlite says %s",
               __LINE__, sqlite3_errmsg(db));
        sqlite3_finalize(sth);
        return;
    }
    int job = sqlite3_column_int(sth, 0);
    char* zone = (char*)sqlite3_column_text(sth, 1);
    time_t firsttry = sqlite3_column_int(sth, 2);

    /* get keys */
    char sql[80];
    char* keys[MAX_KEY_COUNT];
    int count = 0;
    snprintf(sql, sizeof sql, "SELECT key FROM keys WHERE job = %d", job);
    sqlite3_prepare_v2(db, sql, -1, &sth, NULL);
    while ((rc = sqlite3_step(sth))) {
        if (rc == 101)
            break;

        if (rc < 100) {
            syslog(LOG_ERR, "%d:sqlite says %s",
                   __LINE__, sqlite3_errmsg(db));
            sqlite3_finalize(sth);
            return;
        }

        const unsigned char* ptr = sqlite3_column_text(sth, 0);
        if (ptr)
            keys[count++] = strdup((char*)ptr);
        else
            break;
    }

    /* find which registry to send keys to */
    char* registry;
    int i = 1;
    while (1) {
        char xpath[40];
        snprintf(xpath, sizeof xpath, "/eppclient/registry[%d]/suffix", i);
        registry = config_value(xpath);
        if (!registry[0])
            break;

        int rlen = strlen(registry);
        int zlen = strlen(zone);
        if (zlen < rlen) {
            syslog(LOG_ERR, "Invalid zone name '%s'", zone);
            registry[0] = 0;
            break;
        }

        if (!strcmp(zone + zlen - rlen, registry)) {
            registry = strdup(registry);
            break;
        }

        i++;
    }

    if (!registry[0]) {
        syslog(LOG_WARNING, "Found no registry for zone '%s'", zone);
        goto end;
    }

    time_t lasttry = get_registry_time(registry);
    time_t now = time(NULL);

    if (firsttry) {
        /* don't do more than 'maxrate' calls per hour */
        int maxrate = atoi(config_registry_value(registry, "maxrate"));
        if (maxrate && ((now - lasttry) < (3600/maxrate)))
            goto end;
            
        int expiry = atoi(config_registry_value(registry, "expirytime"));
        if (now - firsttry > expiry) {
            syslog(LOG_INFO, "Keys for %s expired after %d seconds",
                   zone, (int)(now - firsttry));
            delete_job(job);
            goto end;
        }
    }

    syslog(LOG_DEBUG, "Connecting to registry %s for zone %s",
           registry, zone);
    if (!epp_login(registry)) {
        if (!epp_change_key(zone, keys, count)) {
            epp_logout();
            if (!delete_job(job))
                ack_server(zone);
        }
    }
    epp_cleanup();

    if (!firsttry)
        set_job_time(job, now);
    set_registry_time(registry, now);

  end:
    free(registry);
    for (int i=0; i<count; i++)
        free((void*)keys[i]);
}

int store_key(char* line, int linenum)
{
    static int job;

    ldns_rr* rr;
    ldns_status rc = ldns_rr_new_frm_str(&rr, line, 0, NULL, NULL);
    if (rc != LDNS_STATUS_OK) {
        syslog(LOG_ERR, "parse error: %s", ldns_get_errorstr_by_id(rc));
        return -1;
    }

    /* extract zone name */
    char zone[256];
    ldns_rdf* owner = ldns_rr_owner(rr);
    ldns_buffer* obuf = ldns_buffer_new(256);
    ldns_rdf2buffer_str(obuf, owner);
    memset(zone, 0, sizeof zone);
    memcpy(zone, obuf->_data, obuf->_position);
    if (zone[strlen(zone) - 1] == '.')
        zone[strlen(zone) - 1] = 0;
    ldns_buffer_free(obuf);

    sqlite3_stmt* sth;

    /* the first line defines the zone */
    if (linenum == 1) {
        /* delete pending jobs for this zone */
        rc = sqlite3_prepare_v2(db, "SELECT job FROM jobs WHERE zone=?",
                                -1, &sth, NULL);
        sqlite3_bind_text(sth, 1, zone, strlen(zone), SQLITE_STATIC);
        while (sqlite3_step(sth) == 100) {
            int job = sqlite3_column_int(sth, 0);
            rc = delete_job(job);
        }
        sqlite3_finalize(sth);
    
        /* store zone */
        rc = sqlite3_prepare_v2(db, "INSERT INTO jobs (zone) VALUES (?)",
                                -1, &sth, NULL);
        sqlite3_bind_text(sth, 1, zone, strlen(zone), SQLITE_STATIC);
        sqlite3_step(sth);

        job = sqlite3_last_insert_rowid(db);
    }

    /* create key string */
    ldns_buffer* rdata = ldns_buffer_new(1024);
    for (size_t i=0; i < rr->_rd_count; i++) {
        ldns_rdf2buffer_str(rdata, rr->_rdata_fields[i]);
        ldns_buffer_printf(rdata, " ");
    }
    char* keybuf = ldns_buffer2str(rdata);
    ldns_buffer_free(rdata);
    if (!keybuf) {
        syslog(LOG_ERR, "ldns_buffer2str() returned NULL");
        ldns_rr_free(rr);
        return -1;
    }

    /* store key */
    rc = sqlite3_prepare_v2(db, "INSERT INTO keys (job, key) VALUES (?,?)",
                            -1, &sth, NULL);
    sqlite3_bind_int(sth, 1, job);
    sqlite3_bind_text(sth, 2, keybuf, strlen(keybuf), SQLITE_STATIC);
    sqlite3_step(sth);
    free(keybuf);
    ldns_rr_free(rr);

    sqlite3_finalize(sth);

    return 0;
}

void read_client_pipe(int pipe)
{
    static int bufsize = 1024;
    static char* buf;
    static int pos = 0;

    if (!buf) {
        buf = malloc(bufsize);
        if (!buf) {
            syslog(LOG_CRIT, "malloc(%d) failed", bufsize);
            return;
        }
    }

    /* read byte by byte to only grab the first line */
    char c;
    if (read(pipe, &c, 1) == 1) {
        /* wrap everything in a transaction */
        sqlite3_exec(db, "BEGIN TRANSACTION;", 0,0,0);

        int linenum = 1;
        bool success = true;
        do {
            if (pos > bufsize-2) {
                bufsize *= 2;
                buf = realloc(buf, bufsize);
                if (!buf) {
                    syslog(LOG_CRIT, "realloc(%d) failed", bufsize);
                    success = false;
                    break;
                }
            }

            buf[pos++] = c;

            if (c == '\n') {
                buf[pos] = 0;
                if (store_key(buf, linenum)) {
                    success = false;
                    break;
                }
                pos = 0;
                linenum++;
            }
        } while (read(pipe, &c, 1) == 1);

        if (success)
            sqlite3_exec(db, "COMMIT TRANSACTION;", 0,0,0);
        else {
            sqlite3_exec(db, "ROLLBACK TRANSACTION;", 0,0,0);

            /* clear the pipe */
            while (read(pipe, &c, 1) == 1);
        }
    }
}

int main(int argc, char *argv[])
{
    int opt;
    int option_index = 0;
            
    while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1) {
        switch (opt) {
            case OPT_VERSION:
            case 'v':
                printf("%s\n", PACKAGE_VERSION);
                exit(0);
                break;
            case OPT_HELP:
            case 'h':
            default:
                usage();
                exit(0);
                break;
        }
    }

    int pipe = init();
    
    while (1) {
        read_client_pipe(pipe);

        int count = count_jobs();
        if (count)
            send_keys();
        sleep(1);
    }

    cleanup(pipe);

    return 0;
}
