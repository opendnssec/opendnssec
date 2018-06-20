/*
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
#include "parser/confparser.h"
#include "daemon/engine.h"
#include "daemon/signercommands.h"
#include "views/utilities.h"
#include "daemon/signertasks.h"

int comparezone(const char* fname1, const char* fname2);

char* argv0;
static char* workdir;
static engine_type* engine;
static janitor_threadclass_t debugthreadclass;
static janitor_thread_t debugthread;

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
    
    if(strlen(specific)>strlen(".gz") && !strcmp(&specific[strlen(specific)-strlen(".gz")],".gz")) {
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

extern void testNothing(void);
extern void testIterator(void);
extern void testAnnotate(void);
extern void testBasic(void);
extern void testSignNSEC(void);
extern void testSignNSEC3(void);
extern void testSignNSECNL(void);

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
    rrset_add_rr(record, rr);
    iter = names_recordalltypes(record);
    if(names_iterate(&iter,&rrtype))
        names_end(&iter);
}

void
testAnnotateItem(const char* name, const char* expected)
{
    struct names_view_zone zonedata = { NULL, "example.com", NULL };
    recordset_type record;
    const char* denial;
    record = names_recordcreatetemp(name);
    names_recordannotate(record, &zonedata);
    denial = names_recordgetid(record, "denialname");
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
testBasic(void)
{
    command_update(engine, NULL, NULL, NULL, NULL);
}

void
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

void
testSignNSEC(void)
{
    int c;
    zone_type* zone;
    usefile("zones.xml", "zones.xml.example");
    usefile("unsigned.zone", "unsigned.zone.example");
    usefile("signconf.xml", "signconf.xml.nsec");
    zonelist_update(engine->zonelist, engine->config->zonelist_filename);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "example.com", LDNS_RR_CLASS_IN);
    signzone(zone);
    zonelist_del_zone(engine->zonelist, zone);
    names_viewreset(zone->baseview);
    names_viewdestroy(zone->inputview);
    names_viewdestroy(zone->prepareview);
    names_viewdestroy(zone->neighview);
    names_viewdestroy(zone->signview);
    names_viewdestroy(zone->outputview);
    names_viewdestroy(zone->baseview);
    zone_cleanup(zone);
    CU_ASSERT_EQUAL((c = comparezone("unsigned.zone","signed.zone")), 0);
    CU_ASSERT_EQUAL((c = system("ldns-verify-zone signed.zone")), 0);
    // TODO: test contains NSEC
}

void
testSignNSEC3(void)
{
    int c;
    zone_type* zone;
    logger_mark_performance("setup files");
    usefile("zones.xml", "zones.xml.example");
    usefile("unsigned.zone", "unsigned.zone.example");
    usefile("signconf.xml", "signconf.xml.nsec3");
    logger_mark_performance("setup zone");
    zonelist_update(engine->zonelist, engine->config->zonelist_filename);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "example.com", LDNS_RR_CLASS_IN);
    logger_mark_performance("sign");
    signzone(zone);
    zonelist_del_zone(engine->zonelist, zone);
    names_viewreset(zone->baseview);
    names_viewdestroy(zone->inputview);
    names_viewdestroy(zone->prepareview);
    names_viewdestroy(zone->neighview);
    names_viewdestroy(zone->signview);
    names_viewdestroy(zone->outputview);
    names_viewdestroy(zone->baseview);
    zone_cleanup(zone);
    CU_ASSERT_EQUAL((c = comparezone("unsigned.zone","signed.zone")), 0);
    CU_ASSERT_EQUAL((c = system("ldns-verify-zone signed.zone")), 0);
    // TODO: test contains NSEC3
}

void
testSignNL(void)
{
    int c;
    zone_type* zone;
    logger_mark_performance("setup files");
    usefile("zones.xml", "zones.xml.nl");
    usefile("unsigned.zone", "unsigned.zone.nl.gz");
    usefile("signconf.xml", "signconf.xml.nl");
    logger_mark_performance("setup zone");
    zonelist_update(engine->zonelist, engine->config->zonelist_filename);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "nl", LDNS_RR_CLASS_IN);
    logger_mark_performance("sign");
    signzone(zone);
    CU_ASSERT_EQUAL((c = comparezone("unsigned.zone","signed.zone")), 0);
    CU_ASSERT_EQUAL((c = system("ldns-verify-zone signed.zone")), 0);
    // TODO: test contains NSEC3
}

void
testSignOld(void)
{
    usefile("zones.xml", "zones.xml.1");
    command_update(engine, NULL, NULL, NULL, NULL);
    pthread_mutex_lock(&engine->zonelist->zl_lock);
    CU_ASSERT_EQUAL(engine->zonelist->zones->count, 0);
    ods_log_error("checking %lu",engine->zonelist->zones->count);
    pthread_mutex_unlock(&engine->zonelist->zl_lock);
    sleep(1);

    usefile("zones.xml", "zones.xml.2");
    command_update(engine, NULL, NULL, NULL, NULL);
    pthread_mutex_lock(&engine->zonelist->zl_lock);
    CU_ASSERT_EQUAL(engine->zonelist->zones->count, 1);
    ods_log_error("checking %lu",engine->zonelist->zones->count);
    pthread_mutex_unlock(&engine->zonelist->zl_lock);
    sleep(10);
}


struct test_struct {
    const char* suite;
    const char* name;
    const char* description;
    CU_TestFunc pTestFunc;
    CU_pSuite pSuite;
    CU_pTest pTest;
} tests[] = {
    { "signer", "testNothing",    "test nothing" },
    { "signer", "testIterator",   "test of iterator" },
    { "signer", "testAnnotate",   "test of denial annotation" },
    { "signer", "testBasic",      "test of start stop" },
    { "signer", "testSignNSEC",   "test NSEC signing" },
    { "signer", "testSignNSEC3",  "test NSEC3 signing" },
    { "signer", "-testSignNL",    "test NL signing" },
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
