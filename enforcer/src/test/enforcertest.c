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
#include "locks.h"
#include "file.h"
#include "daemon/engine.h"
#include "duration.h"

char* argv0;
static char* workdir;
static engine_type* engine;
static cmdhandler_ctx_type* ctx;
static db_connection_t* dbconn;
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
    // logger_initialize(argv0);

    /* initialize */
    xmlInitGlobals();
    xmlInitParser();
    xmlInitThreads();

    janitor_threadclass_create(&debugthreadclass, "debug");
    janitor_threadclass_setautorun(debugthreadclass);
    janitor_threadclass_setblockedsignals(debugthreadclass);
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
        linkat(basefd, specific, basefd, basename, 0);
        fstatat(basefd, basename, &filestat, 0);
        clock_gettime(CLOCK_REALTIME_COARSE, &curtime);
        newtime[0] = filestat.st_atim;
        newtime[1] = curtime;
        utimensat(basefd, basename, newtime, 0);
    }
}

static void
setUp(void)
{
    int linkfd, status;

    ods_log_init(argv0, 0, NULL, 3);
    // logger_initialize(argv0); 

    if (workdir != NULL)
        chdir(workdir);

    unlink("enforcer.pid");

    engine = engine_alloc();
    assert(engine->config);
    engine_init(engine, 0);
    engine->config = engine_config("conf.xml", 0, engine->config);
    //setup_database(engine);
    set_time_now(0);
    assert(engine->config);
    assert(engine->config->repositories);
    hsm_open2(engine->config->repositories, hsm_check_pin);
    engine_setup_database(engine);
    dbconn = get_database_connection(engine);
    assert(dbconn);
    assert(engine);
    ctx = malloc(sizeof(cmdhandler_ctx_type));
    ctx->cmdhandler = NULL;
    ctx->sockfd = 2;
    ctx->globalcontext = engine;
    //ctx->localcontext = ctx->cmdhandler->createlocalcontext(ctx->globalcontext);
    ctx->localcontext = dbconn;
    assert(ctx->localcontext);
    set_time_now(time_now());
}

static void
tearDown(void)
{
    free(ctx);
    db_connection_free(dbconn);
    //command_stop(engine);
    //janitor_thread_join(debugthread);
    engine_dealloc(engine);
    engine = NULL;
    unlink("enforcer.pid");
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

#include "keystate/zone_add_cmd.h"
#include "keystate/zone_del_cmd.h"
#include "policy/policy_import_cmd.h""

void
testNothing(void)
{
}

void
testProcedure(void)
{
    int count;
    task_type* task;
    policy_import_funcblock.run(2, ctx, "policy import");
    zone_add_funcblock.run(2, ctx, "zone add -z ods");
    // num iteration
    // specific time
    // elapse of time
    // num of actions
    // num of steps of specific time
    //   return of
    count = 0;
    do {
        task = schedule_pop_first_task(engine->taskq);
        if(task->due_date > time_now())
            set_time_now(task->due_date);
        task_perform(engine->taskq, task, dbconn);
        //
        if(count++ > 10)
            break;
    } while(task);
    zone_del_funcblock.run(2, ctx, "zone delete -z ods");
    //  (void)hsm_key_factory_generate_policy(engine, dbconn, policy, 0);
    // (void)schedule_task(engine->taskq, enforce_task(engine, zone->name), 1, 0);
}

extern void testNothing(void);
extern void testProcedure(void);

struct test_struct {
    const char* suite;
    const char* name;
    const char* description;
    CU_TestFunc pTestFunc;
    CU_pSuite pSuite;
    CU_pTest pTest;
} tests[] = {
    { "enforcer", "testNothing",         "test nothing" },
    { "enforcer", "testProcedure",       "test basic enforce procedure" },
    { "enforcer", "testContinue",       "test continue" },
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
                break;
        if(j<i) {
            tests[i].pSuite = tests[j].pSuite;
        } else {
            tests[i].pSuite = CU_add_suite_with_setup_and_teardown(tests[i].suite, NULL, NULL, setUp, tearDown);
        }
    }
    for(i=0; tests[i].name; i++) {
        tests[i].pTestFunc = dlsym(NULL, (tests[i].name[0]=='-' ? &tests[i].name[1] : tests[i].name));
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
    if (argc == 2 && !strcmp(argv[1],"-")) {
        for(i=0; tests[i].name; i++) {
            if(tests[i].name != NULL) {
                printf("TEST %s\n",tests[i].name);
                if(tests[i].pTest == NULL)
                    tests[i].pTest = CU_add_test(tests[i].pSuite, tests[i].description, tests[i].pTestFunc);
                CU_basic_run_test(tests[i].pSuite, tests[i].pTest);
            }
        }
    } else if (argc > 1) {
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
