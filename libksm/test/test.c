/*+
 * Filename: test.c
 *
 * Description:
 *      Main routine for the running of the various test programs.
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

#include <assert.h>
#include <stdio.h>

#include "CUnit/Basic.h"

#include "test_routines.h"

/* Define the external test routines (each of these creates a suite) */

/* Database files */
int TestDb(void);
int TestDds(void);
int TestDis(void);
int TestDqs(void);
int TestDus(void);
int TestDt(void);

/* Utility files */
int TestKeyword(void);
int TestMsg(void);
int TestStr(void);
int TestStr2(void);

/* The KSM files */
/*int KsmInitRundown(void);*/
/*int KsmKeyword(void); - tested in TestKeyword above */
int TestKsmPurge(void);
int TestKsmKey(void);
int TestKsmParameter(void);
int TestKsmRequest(void);
int TestKsmKeyDelete(void);
/*int TestKsmParameterValue(void);*/
int TestKsmUpdate(void);
int TestKsmPolicy(void);
int TestKsmZone(void);

/*
 * main() - Main Testing Routine
 *
 * Description:
 *      Runs the tests and prints success or failre.
 *
 * Arguments:
 *      -m  Print messages from routines in "util".
 *
 * Returns:
 *      int
 *          0 on success
 *          CUnit error code on failure.
 */

int main(int argc, char **argv)
{
    TestInitialize(argc, argv);
    TcuInitialize();

    /*
     * Add the test suites to the registry (with the ones that take the shortest
     * amount of time first).
     */

    if (
        (! TestDb()) &&
        (! TestDds()) &&
        (! TestDis()) &&
        (! TestDqs()) &&
        (! TestDus()) &&
        (! TestDt()) &&
        (! TestKeyword()) &&
		(! TestMsg()) &&
        (! TestStr()) &&
/*        (! TestStr2()) &&	*/
        (! TestKsmPurge()) &&
        (! TestKsmKey()) &&
        (! TestKsmParameter()) &&
        (! TestKsmRequest()) &&
        (! TestKsmKeyDelete()) &&
        (! TestKsmUpdate()) &&
        (! TestKsmPolicy()) &&
        (! TestKsmZone()) 
        ) {

        /* Run all the tests */

        TcuExecute();
    }

    return CU_get_error();
}
