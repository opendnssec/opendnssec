#ifndef TEST_ROUTINES_H
#define TEST_ROUTINES_H

/*+
 * Filename: test.h
 *
 * Description:
 *      Definitions of structures and routines for the CUnit-based module
 *      tests.
 *
 *
 * Copyright:
 *      Copyright 2008 Nominet
 *      
 * Licence:
 *      Licensed under the Apache Licence, Version 2.0 (the "Licence");
 *      you may not use this file except in compliance with the Licence.
 *      You may obtain a copy of the Licence at
 *      
 *          http://www.apache.org/licenses/LICENSE-2.0
 *      
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the Licence is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the Licence for the specific language governing permissions and
 *      limitations under the Licence.
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
