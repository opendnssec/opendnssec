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

#ifndef TEST_ROUTINES_H
#define TEST_ROUTINES_H

/*+
 * Filename: test.h
 *
 * Description:
 *      Definitions of structures and routines for the CUnit-based module
 *      tests.
-*/

#include <pthread.h>
#include <unistd.h>

#include "system_includes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Structure due to define tests in a suite */

struct test_testdef {
    const char* title;          /* Test title - must be unique within a suite */
    void        (*function)();  /* Function executing the test */
};

/* Structure for creating background threads */

struct test_thread_data {
    const char** lines;     /* Pointer to the data to be written */
    unsigned int* lengths;  /* Pointer to data lengths */
    int fd;                 /* File descriptor */
    int first_delay;        /* First delay */
    int subsequent_delay;   /* Subsequent delay */
};

/* Common test routines */

void TestInitialize(int argc, char** argv);

/* Option access routines */

int TestGetAutomatic(void);
int TestGetBasic(void);
int TestGetCurses(void);
int TestGetConsole(void);
int TestGetList(void);
const char* TestGetFilename(void);

/* CUnuit test routines */

void TcuInitialize(void);
void TcuExecute(void);
int TcuCreateSuite(const char* title, int (*init)(), int (*teardown)(),
    struct test_testdef* tests);

/* Database access */

const char* TdbUsername(void);
const char* TdbPassword(void);
const char* TdbHost(void);
const char* TdbName(void);

int TdbSetup(void);
int TdbTeardown(void);

#ifdef __cplusplus
}
#endif

#endif
