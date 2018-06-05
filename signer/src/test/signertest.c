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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <libxml/parser.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include "janitor.h"
#include "locks.h"
#include "parser/confparser.h"
#include "daemon/engine.h"
#include "daemon/signercommands.h"
#include "views/utilities.h"
#include "daemon/signertasks.h"

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
setUp(void)
{
    int linkfd, status;

    ods_log_init("test", 0, NULL, 3);

    if (workdir != NULL)
        chdir(workdir);

    unlink("zones.xml");
    
    engine = engine_create();
    if((status = engine_setup_config(engine, "conf.xml", 3, 0)) != ODS_STATUS_OK ||
       (status = engine_setup_initialize(engine, &linkfd)) != ODS_STATUS_OK ||
       (status = engine_setup_finish(engine, linkfd)) != ODS_STATUS_OK) {
        ods_log_error("Unable to start signer daemon: %s", ods_status2str(status));
    }
    hsm_open2(engine->config->repositories, hsm_check_pin);
}

static void
tearDown(void)
{
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
usefile(const char* basename, const char* specific)
{
    struct timespec curtime;
    struct timespec newtime[2];
    struct stat filestat;
    int basefd = AT_FDCWD;
    unlinkat(basefd, basename, 0);
    linkat(basefd, specific, basefd, basename, 0);
    fstatat(basefd, "zones.xml", &filestat, 0);
    clock_gettime(CLOCK_REALTIME_COARSE, &curtime);
    newtime[0] = filestat.st_atim;
    newtime[1] = curtime;
    utimensat(basefd, "zones.xml", newtime, 0);
}

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
    dictionary record;
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

static void
testAnnotateItem(const char* name, const char* expected)
{
    struct names_view_zone zonedata = { NULL, "example.com", NULL };
    dictionary record;
    const char* denial;
    record = names_recordcreatetemp(name);
    names_recordannotate(record, &zonedata);
    denial = names_recordgetid(record, "denialname");
    names_recorddestroy(record);
    CU_ASSERT_STRING_EQUAL(expected, denial);
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
testSign(void)
{
    zone_type* zone;
    task_type* task;
    struct worker_context context;
    context.engine = engine;
    context.worker = worker_create("mock", NULL);
    context.signq = NULL;
    context.zone = zone;
    usefile("zones.xml", "zones.xml.2");
    zonelist_update(engine->zonelist, engine->config->zonelist_filename);
    zone = zonelist_lookup_zone_by_name(engine->zonelist, "example.com", LDNS_RR_CLASS_IN);
    assert(zone->inputview);
    assert(zone->prepareview);
    assert(zone->neighview);
    assert(zone->signview);
    assert(zone->outputview);
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
    system("cat signed.zone");
}

int
main(int argc, char* argv[])
{
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* add a suite to the registry */
    if (!(pSuite = CU_add_suite_with_setup_and_teardown("signer", NULL, NULL, setUp, tearDown))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if (!(CU_add_test(pSuite, "test nothing", testNothing)) ||
        !(CU_add_test(pSuite, "test of iterator", testIterator)) ||
        !(CU_add_test(pSuite, "test of denial annotation", testAnnotate)) ||
        !(CU_add_test(pSuite, "test of start stop", testBasic)) ||
        !(CU_add_test(pSuite, "test of start sign stop", testSign))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    initialize(argc, argv);

    CU_list_tests_to_file();
    CU_automated_run_tests();
    CU_cleanup_registry();

    finalize();

    return CU_get_error();
}
