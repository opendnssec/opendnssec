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

/*+
 * Filename: test.c
 *
 * Description:
 *      Main routine for the running of the various test programs.
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
