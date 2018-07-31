/*
 * Copyright (c) 2009-2018 NLNet Labs.
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
 */

#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>
#include <libxml/parser.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include "janitor.h"
#include "logging.h"
#include "locks.h"
#include "file.h"
#include "confparser.h"
#include "daemon/engine.h"
#include "daemon/signercommands.h"
#include "utilities.h"
#include "daemon/signertasks.h"
#include "daemon/metastorage.h"
#include "views/httpd.h"
#include "adapter/adutil.h"

#include "comparezone.h"

char* argv0;
static char* workdir;
static engine_type* engine;
static janitor_threadclass_t debugthreadclass;
static janitor_thread_t debugthread;

#pragma GCC optimize ("O0")

static void
initialize(int argc, char* argv[])
{
    /* this initialization should happen only once */
    if (argv[0][0] != '/') {
        char *path = getcwd(NULL, 0);
        asprintf(&argv0, "%s/%s", path, argv[0]);
        free(path);
    } else {
        argv0 = strdup(argv[0]);
    }

    if (argc > 1) {
        workdir = argv[1];
    }

    ods_janitor_initialize(argv0);

    /* initialize */
    xmlInitGlobals();
    xmlInitParser();
    xmlInitThreads();

    janitor_threadclass_create(&debugthreadclass, "debug");
    janitor_threadclass_setautorun(debugthreadclass);
    janitor_threadclass_setblockedsignals(debugthreadclass);
}

static void
enginerunner(void* engine)
{
    engine_start(engine);
}

static void
enginethreadingstart(void)
{
    int i;
    char*name = NULL;
    CHECKALLOC(engine->workers = (worker_type**) malloc(engine->config->num_signer_threads * sizeof(worker_type*)));
    for (i=0; i < engine->config->num_signer_threads; i++) {
        asprintf(&name, "drudger[%d]", i+1);
        engine->workers[i] = worker_create(name, engine->taskq);
    }
    for (i=0; i < engine->config->num_signer_threads; i++) {
        engine->workers[i]->need_to_exit = 0;
        janitor_thread_create(&engine->workers[i]->thread_id, workerthreadclass, (janitor_runfn_t)drudge, engine->workers[i]);
    }
}

static void
enginethreadingstop(void)
{
    int i;
    for (i=0; i < engine->config->num_signer_threads; i++) {
        engine->workers[i]->need_to_exit = 1;
    }
    schedule_release_all(engine->taskq);
    for (i=0; i < engine->config->num_signer_threads; i++) {
        janitor_thread_join(engine->workers[i]->thread_id);
        free(engine->workers[i]->context);
        worker_cleanup(engine->workers[i]);
    }
    free(engine->workers);
    engine->workers = NULL;
}

static void
setUp(void)
{
    int linkfd, status;

    ods_log_init(argv0, 0, NULL, 3);
    logger_initialize(argv0);

    if (workdir != NULL)
        chdir(workdir);

    unlink("zones.xml");
    unlink("signer.pid");
    unlink("signer.db");
    unlink("example.com.state");

    engine = engine_create();
    if((status = engine_setup_config(engine, "conf.xml", 3, 0)) != ODS_STATUS_OK ||
       (status = engine_setup_initialize(engine, &linkfd)) != ODS_STATUS_OK ||
       (status = engine_setup_finish(engine, linkfd)) != ODS_STATUS_OK) {
        ods_log_error("Unable to start signer daemon: %s", ods_status2str(status));
    }
    enginethreadingstart();
    hsm_open2(engine->config->repositories, hsm_check_pin);
    //janitor_thread_create(&debugthread, debugthreadclass, enginerunner, engine);
}

static void
tearDown(void)
{
    //command_stop(engine);
    //janitor_thread_join(debugthread);
    enginethreadingstop();
    engine_cleanup(engine);
    engine = NULL;

    unlink("zones.xml");
    unlink("signed.zone");
    unlink("unsigned.zone");
    unlink("signconf.xml");
    unlink("signer.db");
    unlink("signer.pid");
    unlink("example.com.state");
}

static void
finalize(void)
{
    janitor_threadclass_destroy(debugthreadclass);
    xmlCleanupParser();
    xmlCleanupGlobals();
    ods_log_close();
    free(argv0);
}

static void
producefile(const char* inputfile, const char* outputfile, const char* program, ...)
{
    int input;
    int output;
    int status, i, argc;
    pid_t group;
    pid_t child;
    char** argv;
    va_list ap;
    group = getpgid(0);
    if(!(child = fork())) {
        setpgid(0, group);
        input = open(inputfile,O_RDONLY);
        if(input < 0) {
            fprintf(stderr,"%s: failed to open input file \"%s\": %s (%d)\n",argv0,inputfile,strerror(errno),errno);
            exit(1);
        } else if(input != 0) {
            dup2(input, 0);
            close(input);
        }
        output = open(outputfile, O_WRONLY|O_CREAT, 0666);
        if(output < 0) {
            fprintf(stderr,"%s: failed to open output file \"%s\": %s (%d)\n",argv0,outputfile,strerror(errno),errno);
            exit(1);
        } else if(output != 1) {
            dup2(output, 1);
            close(output);
        }
        va_start(ap, program);
        for(argc=0; va_arg(ap, const char*); ++argc)
            ;
        va_end(ap);
        argv = malloc(sizeof(const char*)*(argc+1));
        va_start(ap, program);
        for(i=0; i<argc; i++)
            argv[i] = va_arg(ap, char*);
        argv[argc] = NULL;
        va_end(ap);
        execvp(program, argv);
    } else {
        if(child > 0) {
            waitpid(child, &status, 0);
        }
    }
}

static void
usefile(const char* basename, const char* specific)
{
    struct timespec curtime;
    struct timespec newtime[2];
    struct stat filestat;
    int basefd = AT_FDCWD;

    unlinkat(basefd, basename, 0);    
    if (specific != NULL) {
        if (strlen(specific)>strlen(".gz") && !strcmp(&specific[strlen(specific)-strlen(".gz")],".gz")) {
            producefile(specific,basename,"gzip","-c","-d",NULL);
        } else {
            linkat(basefd, specific, basefd, basename, 0);
        }
        fstatat(basefd, basename, &filestat, 0);
        clock_gettime(CLOCK_REALTIME_COARSE, &curtime);
        newtime[0] = filestat.st_atim;
        newtime[1] = curtime;
        utimensat(basefd, basename, newtime, 0);
    }
}

static void
validatezone(zone_type* zone)
{
    names_viewvalidate(zone->baseview);
    names_viewvalidate(zone->inputview);
    names_viewvalidate(zone->prepareview);
    names_viewvalidate(zone->neighview);
    names_viewvalidate(zone->signview);
    names_viewvalidate(zone->outputview);
    names_viewvalidate(zone->changesview);
}

static void
disposezone(zone_type* zone)
{
    zonelist_del_zone(engine->zonelist, zone);
    names_viewreset(zone->baseview);
    names_viewdestroy(zone->inputview);
    names_viewdestroy(zone->prepareview);
    names_viewdestroy(zone->neighview);
    names_viewdestroy(zone->signview);
    names_viewdestroy(zone->outputview);
    names_viewdestroy(zone->changesview);
    names_viewdestroy(zone->baseview);
    zone_cleanup(zone);
}

static void
outputzone(zone_type* zone)
{
    task_type* task;
    struct worker_context context;
    context.engine = engine;
    context.worker = worker_create(strdup("mock"), NULL);
    context.signq = NULL;
    context.zone = zone;
    context.clock_in = time_now();
    context.view = zone->outputview;
    task = task_create(strdup(zone->name), TASK_CLASS_SIGNER, TASK_WRITE, do_writezone, zone, NULL, 0);
    task->callback(task, zone->name, zone, &context);
    task_destroy(task);
    worker_cleanup(context.worker);
}

static void
signzone(zone_type* zone)
{
    task_type* task;
    struct worker_context context;
    context.engine = engine;
    context.worker = worker_create(strdup("mock"), NULL);
    context.signq = NULL;
    context.zone = zone;
    context.clock_in = time_now();
    context.view = zone->inputview;
    task = task_create(strdup(zone->name), TASK_CLASS_SIGNER, TASK_SIGNCONF, do_readsignconf, zone, NULL, 0);
    task->callback(task, zone->name, zone, &context);
    task_destroy(task);
    context.clock_in = time_now();
    context.view = zone->inputview;
    task = task_create(strdup(zone->name), TASK_CLASS_SIGNER, TASK_READ, do_readzone, zone, NULL, 0);
    task->callback(task, zone->name, zone, &context);
    task_destroy(task);
    context.clock_in = time_now();
    context.view = zone->signview;
    task = task_create(strdup(zone->name), TASK_CLASS_SIGNER, TASK_SIGN, do_signzone, zone, NULL, 0);
    task->callback(task, zone->name, zone, &context);
    task_destroy(task);
    context.clock_in = time_now();
    context.view = zone->outputview;
    task = task_create(strdup(zone->name), TASK_CLASS_SIGNER, TASK_WRITE, do_writezone, zone, NULL, 0);
    task->callback(task, zone->name, zone, &context);
    task_destroy(task);
    worker_cleanup(context.worker);
}

static void
resignzone(zone_type* zone)
{
    task_type* task;
    struct worker_context context;
    context.engine = engine;
    context.worker = worker_create(strdup("mock"), NULL);
    context.signq = NULL;
    context.zone = zone;
    context.clock_in = time_now();
    context.view = zone->inputview;
    task = task_create(strdup(zone->name), TASK_CLASS_SIGNER, TASK_SIGNCONF, do_readsignconf, zone, NULL, 0);
    task->callback(task, zone->name, zone, &context);
    task_destroy(task);
    context.clock_in = time_now();
    context.view = zone->signview;
    task = task_create(strdup(zone->name), TASK_CLASS_SIGNER, TASK_SIGN, do_signzone, zone, NULL, 0);
    task->callback(task, zone->name, zone, &context);
    task_destroy(task);
    context.clock_in = time_now();
    context.view = zone->outputview;
    task = task_create(strdup(zone->name), TASK_CLASS_SIGNER, TASK_WRITE, do_writezone, zone, NULL, 0);
    task->callback(task, zone->name, zone, &context);
    task_destroy(task);
    worker_cleanup(context.worker);
}

static void
reresignzone(zone_type* zone)
{
    task_type* task;
    struct worker_context context;
    context.engine = engine;
    context.worker = worker_create(strdup("mock"), NULL);
    context.signq = NULL;
    context.zone = zone;
    context.clock_in = time_now();
    context.view = zone->signview;
    task = task_create(strdup(zone->name), TASK_CLASS_SIGNER, TASK_SIGN, do_signzone, zone, NULL, 0);
    task->callback(task, zone->name, zone, &context);
    task_destroy(task);
    worker_cleanup(context.worker);
}

static struct rpc*
makecall(char* zone, const char* delegation, ...)
{
    va_list ap;
    const char* str;
    int i, count;
    ldns_rdf* origin = NULL;
    struct rpc* rpc = malloc(sizeof(struct rpc));
    rpc->opc = RPC_CHANGE_DELEGATION;
    rpc->zone = strdup(zone);
    rpc->version = strdup("1");
    rpc->detail_version = strdup("20170620");
    rpc->correlation = NULL;
    rpc->delegation_point = strdup(delegation);
    va_start(ap,delegation);
    count = 0;
    while((str=va_arg(ap,const char*))!=NULL)
        ++count;
    va_end(ap);
    rpc->rr_count = count;
    rpc->rr = malloc(sizeof(ldns_rr*)*count);
    va_start(ap,delegation);
    for(i=0; i<count; i++) {
        str = va_arg(ap,const char*);
        ldns_rr_new_frm_str(&rpc->rr[i], str, 0, origin, NULL);
    }
    va_end(ap);
    rpc->rr_count = count;
    rpc->status = RPC_OK;
    return rpc;
}

extern void testNothing(void);
extern void testIterator(void);
extern void testAnnotate(void);
extern void testStatefile(void);
extern void testTransferfile(void);
extern void testBasic(void);
extern void testSignNSEC(void);
extern void testSignNSEC3(void);
extern void testSignNSECNL(void);
extern void testSignFast(void);


void
testNothing(void)
{
}


void
testIterator(void)
{
    names_iterator iter;
    ldns_rr_type rrtype;
    ldns_rr* rr;
    ldns_rdf* prev;
    uint32_t ttl;
    ldns_rdf* origin;
    const char* name;
    recordset_type record;
    prev = NULL;
    ttl = 60;
    name = "example.com";
    record = names_recordcreate((char**)&name);
    origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "example.com.");
    ldns_rr_new_frm_str(&rr, "example.com. 86400 IN SOA ns1.example.com. postmaster.example.com. 2009060301 10800 3600 604800 86400", ttl, origin, &prev);
    names_recordadddata(record, rr);
    iter = names_recordalltypes(record);
    if(names_iterate(&iter,&rrtype))
        names_end(&iter);
}


static void
testAnnotateItem(const char* name, const char* expected)
{
    struct names_view_zone zonedata = { NULL, "example.com", NULL };
    recordset_type record;
    const char* denial;
    record = names_recordcreatetemp(name);
    names_recordannotate(record, &zonedata);
    denial = names_recordgetdenial(record);
    CU_ASSERT_STRING_EQUAL(expected, denial);
    names_recorddispose(record);
}

void
testAnnotate(void)
{
    testAnnotateItem("www.test.example.com", "com~example~test~www");
    testAnnotateItem("www.example.com", "com~example~www");
    testAnnotateItem("example.com", "com~example");
    testAnnotateItem("com", "com");
}


void
testMarshalling(void)
{
    int fd;
    marshall_handle h;
    ldns_rdf* origin;
    ldns_rr* rr1;
    ldns_rr* rr2;
    ldns_rr* rr3;
    ldns_rr* rrsig;
    ldns_rdf* rrprev = NULL;
    recordset_type record;
    signconf_type* signconf = NULL;
    struct names_view_zone zone = { NULL, "example.com.", &signconf };

    zone.signconf = NULL;
    record = names_recordcreatetemp("testrecord");
    names_recordannotate(record, &zone);
    origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "example.com.");
    assert(origin);
    ldns_rr_new_frm_str(&rr1, "domain.example.com. A 127.0.0.1", 60, origin, &rrprev);
    ldns_rr_new_frm_str(&rr2, "domain.example.com. A 172.0.0.1", 60, origin, &rrprev);
    ldns_rr_new_frm_str(&rr3, "domain.example.com. NS domain.example.com.", 60, origin, &rrprev);
    assert(rr1);
    assert(rr2);
    assert(rr3);
    names_recordadddata(record, rr1);
    names_recordadddata(record, rr2);
    names_recordadddata(record, rr3);
    ldns_rr_new_frm_str(&rrsig, "domain.example.com. RRSIG A 7 3 86400 20180525135557 20180525125459 55490 example.com. FV0gZ8FAaqlFnJ6jFuBj4DSImeftLaRdOXhjGxUZuZe29PkkuZP9u2cb9n4SSXRSn88rEHoSff8nPKwYKCOzOxlgHx7q4FZwmGrLrmV7Sfjp41O7DI4P8F/APVwfuc4d63uQq3C2opXgFv76L0CQ/+9mIOxthjL7hVy00UDPzWM=", 60, origin, &rrprev);
    names_recordaddsignature(record,LDNS_RR_TYPE_A, rrsig, "locateme", 0);
    names_recordsetexpiry(record, 111);
    names_recordsetvalidfrom(record, 222);
    names_recordsetvalidupto(record, 333);

    fd = open("test.dmp", O_WRONLY|O_TRUNC|O_CREAT,0666);
    h = marshallcreate(marshall_OUTPUT, fd);
    names_recordmarshall(&record,h);
    marshallclose(h);
    close(fd);

    record = NULL;
    fd = open("test.dmp", O_RDONLY, 0666);
    h = marshallcreate(marshall_INPUT, fd);
    names_recordmarshall(&record,h);
    // names_dumprecord(stderr,record); In case this test fails enable this to investigate
    marshallclose(h);
    close(fd);
    
    unlink("test.dmp");
}


void
testStatefile(void)
{
    zone_type zone1;
    zone_type zone2;
    zone_type zone3;
    zone_type zone4;
    zone_type zone5;
    zone_type zone6;
    unlink("signer.db");
    memset(&zone1,0xFF,sizeof(zone_type));
    memset(&zone2,0xFF,sizeof(zone_type));
    memset(&zone3,0xFF,sizeof(zone_type));
    memset(&zone4,0xFF,sizeof(zone_type));
    memset(&zone5,0xFF,sizeof(zone_type));
    memset(&zone6,0xFF,sizeof(zone_type));

    zone1.name = "example.com";
    zone1.inboundserial = malloc(sizeof(int));
    *zone1.inboundserial = 111;
    zone1.outboundserial = NULL;
    zone1.nextserial = NULL;
    metastorageput(&zone1);

    metastorageget("example.com",&zone2);
    CU_ASSERT_PTR_NOT_NULL(zone2.name);
    CU_ASSERT_PTR_NOT_NULL(zone2.inboundserial);
    CU_ASSERT_PTR_NULL(zone2.outboundserial);
    CU_ASSERT_PTR_NULL(zone2.nextserial);
    CU_ASSERT_STRING_EQUAL(zone2.name, "example.com");
    CU_ASSERT_EQUAL(*zone2.inboundserial, 111);

    zone3.name = "example.org";
    zone3.outboundserial = malloc(sizeof(int));
    *zone3.outboundserial = 222;
    zone3.inboundserial = NULL;
    zone3.nextserial = NULL;
    metastorageput(&zone3);

    zone4.name = "example.com";
    zone4.nextserial = malloc(sizeof(int));
    *zone4.nextserial = 333;
    zone4.inboundserial = NULL;
    zone4.outboundserial = NULL;
    metastorageput(&zone4);

    metastorageget("example.org",&zone5);
    CU_ASSERT_PTR_NOT_NULL(zone5.name);
    CU_ASSERT_PTR_NULL(zone5.inboundserial);
    CU_ASSERT_PTR_NOT_NULL(zone5.outboundserial);
    CU_ASSERT_PTR_NULL(zone5.nextserial);
    CU_ASSERT_STRING_EQUAL(zone5.name, "example.org");
    CU_ASSERT_EQUAL(*zone5.outboundserial, 222);

    metastorageget("example.com",&zone6);
    CU_ASSERT_PTR_NOT_NULL(zone6.name);
    CU_ASSERT_PTR_NULL(zone6.inboundserial);
    CU_ASSERT_PTR_NULL(zone6.outboundserial);
    CU_ASSERT_PTR_NOT_NULL(zone6.nextserial);
    CU_ASSERT_STRING_EQUAL(zone6.name, "example.com");
    CU_ASSERT_EQUAL(*zone6.nextserial, 333);
}


void
testTransferfile(void)
{
    FILE* fp;
    int status;
    char line[1024];
    zone_type* zone;
    usefile("example.com.xfr", NULL);
    usefile("example.com.state", NULL);
    usefile("signer.db", NULL);
    usefile("example.com.state", NULL);
    usefile("zones.xml", "zones.xml.example");
    usefile("unsigned.zone", "unsigned.zone.testing");
    usefile("signconf.xml", "signconf.xml.nsec");
    zonelist_update(engine->zonelist, engine->config->zonelist_filename_signer);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "example.com", LDNS_RR_CLASS_IN);

    signzone(zone);
    status = httpd_dispatch(zone->inputview, makecall(zone->name, "domain.example.com.", NULL));
    CU_ASSERT_EQUAL(status, 0);
    status = names_viewcommit(zone->inputview);
    CU_ASSERT_EQUAL(status,0);
    reresignzone(zone);

    names_viewreset(zone->outputview);
    names_viewreset(zone->changesview);
    time_t serial = 2;
    fp = getxfr(zone, ".xfr", &serial);
    CU_ASSERT_NOT_EQUAL(unlink("example.com.xfr"), 0);
    CU_ASSERT_EQUAL(errno, ENOENT);

    while(!feof(fp)) {
        if(fgets(line,sizeof(line)-2,fp)) {
            line[sizeof(line)-1] = '\0';
            printf("%s",line);
        }
    }

    fclose(fp);
    disposezone(zone);

    usefile("test.xfr", NULL);
    usefile("example.com.state", NULL);
    usefile("signer.db", NULL);
    usefile("example.com.state", NULL);
    usefile("zones.xml", NULL);
    usefile("unsigned.zone", NULL);
    usefile("signconf.xml", NULL);
}

void
testBasic(void)
{
    command_update(engine, NULL, NULL, NULL, NULL);
}


void
testSignNSEC(void)
{
    zone_type* zone;
    usefile("example.com.state", NULL);
    usefile("signer.db", NULL);
    usefile("example.org.state", NULL);

    usefile("example.com.state", NULL);
    usefile("zones.xml", "zones.xml.example");
    usefile("unsigned.zone", "unsigned.zone.example");
    usefile("signconf.xml", "signconf.xml.nsec");
    zonelist_update(engine->zonelist, engine->config->zonelist_filename_signer);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "example.com", LDNS_RR_CLASS_IN);
    signzone(zone);
    disposezone(zone);
    CU_ASSERT_EQUAL((comparezone("unsigned.zone","signed.zone",0)), 0);
    CU_ASSERT_EQUAL((system("ldns-verify-zone signed.zone")), 0);
}


void
testSignNSEC3(void)
{
    zone_type* zone;
    logger_mark_performance("setup files");
    usefile("example.com.state", NULL);
    usefile("zones.xml", "zones.xml.example");
    usefile("unsigned.zone", "unsigned.zone.example");
    usefile("signconf.xml", "signconf.xml.nsec3");
    logger_mark_performance("setup zone");
    zonelist_update(engine->zonelist, engine->config->zonelist_filename_signer);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "example.com", LDNS_RR_CLASS_IN);
    logger_mark_performance("sign");
    signzone(zone);
    disposezone(zone);
    CU_ASSERT_EQUAL((comparezone("unsigned.zone","signed.zone",0)), 0);
    CU_ASSERT_EQUAL((system("ldns-verify-zone signed.zone")), 0);
}


void
testSignResign(void)
{
    int basefd = AT_FDCWD;
    zone_type* zone;
    logger_mark_performance("setup files");
    usefile("signer.db", NULL);
    usefile("example.com.state", NULL);
    usefile("zones.xml", "zones.xml.example");
    usefile("unsigned.zone", "unsigned.zone.testing");
    usefile("signconf.xml", "signconf.xml.nsec");
    logger_mark_performance("setup zone");
    zonelist_update(engine->zonelist, engine->config->zonelist_filename_signer);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "example.com", LDNS_RR_CLASS_IN);
    logger_mark_performance("sign");
    signzone(zone);
    validatezone(zone);
    resignzone(zone);

    char* filename = ods_build_path(zone->name, ".state", 0, 1);
    names_viewpersist(zone->baseview, basefd, filename);
    free(filename);

    disposezone(zone);
    engine->zonelist->last_modified = 0; /* force update */
    zonelist_update(engine->zonelist, engine->config->zonelist_filename_signer);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "example.com", LDNS_RR_CLASS_IN);
    resignzone(zone);
    reresignzone(zone);
    reresignzone(zone);
    outputzone(zone);
    disposezone(zone);
}


void
testSignNL(void)
{
    zone_type* zone;
    logger_mark_performance("setup files");
    usefile("nl.state", NULL);
    usefile("zones.xml", "zones.xml.nl");
    usefile("unsigned.zone", "unsigned.zone.nl.gz");
    usefile("signconf.xml", "signconf.xml.nl");
    logger_mark_performance("setup zone");
    zonelist_update(engine->zonelist, engine->config->zonelist_filename_signer);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "nl", LDNS_RR_CLASS_IN);
    logger_mark_performance("sign");
    signzone(zone);
    disposezone(zone);
    //CU_ASSERT_EQUAL((c = comparezone("unsigned.zone","signed.zone")), 0);
}


void
testSignFast(void)
{
    int status;
    zone_type* zone;
    logger_mark_performance("setup files");
    usefile("example.com.state", NULL);
    usefile("signer.db", NULL);
    usefile("zones.xml", "zones.xml.example");
    usefile("unsigned.zone", "unsigned.zone.testing");
    usefile("signconf.xml", "signconf.xml.nsec");
    zonelist_update(engine->zonelist, engine->config->zonelist_filename_signer);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "example.com", LDNS_RR_CLASS_IN);
    signzone(zone);
    status = names_viewcommit(zone->signview);
    CU_ASSERT_EQUAL(status,0);
    names_viewreset(zone->inputview);
    status = httpd_dispatch(zone->inputview, makecall(zone->name, "domain.example.com.", NULL));
    CU_ASSERT_EQUAL(status, 0);
    status = names_viewcommit(zone->inputview);
    CU_ASSERT_EQUAL(status,0);
    reresignzone(zone);
    outputzone(zone);
    disposezone(zone);
    CU_ASSERT_EQUAL((status = comparezone("gold.zone","signed.zone",comparezone_INCL_SOA)), 0);
}


struct test_struct {
    const char* suite;
    const char* name;
    const char* description;
    CU_TestFunc pTestFunc;
    CU_pSuite pSuite;
    CU_pTest pTest;
} tests[] = {
    { "signer", "testNothing",       "test nothing" },
    { "signer", "testIterator",      "test of iterator" },
    { "signer", "testAnnotate",      "test of denial annotation" },
    { "signer", "testMarshalling",   "test marshalling" },
    { "signer", "testStatefile",     "test statefile usage" },
    { "signer", "testTransferfile",  "test transferfile usage" },
    { "signer", "testBasic",         "test of start stop" },
    { "signer", "testSignNSEC",      "test NSEC signing" },
    { "signer", "testSignNSEC3",     "test NSEC3 signing" },
    { "signer", "testSignResign",    "test resigning restart" },
    { "signer", "testSignFast",      "test fast updates" },
    { "signer", "-testSignNL",       "test NL signing" },
    { NULL, NULL, NULL }
};

int
main(int argc, char* argv[])
{
    int i, j, status = 0;
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    for(i=0; tests[i].name; i++) {
        for(j=0; j<i; j++)
            if(!strcmp(tests[i].suite,tests[j].suite))
                break;
        if(j<i) {
            tests[i].pSuite = tests[j].pSuite;
        } else {
            tests[i].pSuite = CU_add_suite_with_setup_and_teardown(tests[i].suite, NULL, NULL, setUp, tearDown);
        }
    }
    for(i=0; tests[i].name; i++) {
        tests[i].pTestFunc = functioncast(dlsym(NULL, (tests[i].name[0]=='-' ? &tests[i].name[1] : tests[i].name)));
        if(tests[i].name[0]!='-') {
            if(tests[i].pTestFunc != NULL) {
                tests[i].pTest = CU_add_test(tests[i].pSuite, tests[i].description, tests[i].pTestFunc);
                if(!tests[i].pTest) {
                    CU_cleanup_registry();
                    return CU_get_error();
                }
            } else {
                fprintf(stderr,"%s: unable to register test %s.%s\n",argv0,tests[i].suite,tests[i].name);
            }
        } else {
            tests[i].name = &(tests[i].name[1]);
            tests[i].pTest = NULL;
        }
    }

    initialize(argc, argv);
    if(argc > 1) {
        --argc;
        ++argv;
    }

    CU_list_tests_to_file();
    if (argc > 1) {
        for(i=1; i<argc; i++) {
            printf("TEST %s\n",argv[i]);
            for(j=0; tests[j].name; j++) {
                if(!strcmp(argv[i],tests[j].suite))
                    break;
            }
            if(tests[j].name == NULL) {
                for(j=0; tests[j].name; j++) {
                    if(!strcmp(argv[i],tests[j].name))
                        break;
                }
            }
            if(tests[j].name == NULL) {
                for(j=0; tests[j].name; j++) {
                    if(!strncmp(argv[i],tests[j].suite,strlen(tests[j].suite)) &&
                       argv[i][strlen(tests[j].suite)]=='.' &&
                       !strcmp(&argv[i][strlen(tests[j].suite)+1],tests[j].name))
                        break;
                }
            }
            if(tests[j].name != NULL) {
                if(tests[j].pTest == NULL)
                    tests[j].pTest = CU_add_test(tests[j].pSuite, tests[j].description, tests[j].pTestFunc);
                CU_basic_run_test(tests[j].pSuite, tests[j].pTest);
            } else {
                fprintf(stderr,"%s: test %s not found\n",argv0,argv[i]);
                status = 1;
            }
        }
    } else {
        CU_automated_run_tests();
    }
    if (CU_get_number_of_tests_failed() != 0)
        status = 1;
    CU_cleanup_registry();

    finalize();
    return status;
}
