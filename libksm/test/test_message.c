/*+
 * Filename: test_message.c - Test message Module
 *
 * Description:
 *      This is a short test module to check the functions in the message
 *      module. 
 *      
 *      The test program makes use of the CUnit framework, as described in
 *      http://cunit.sourceforge.net
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "CUnit/Basic.h"

#include "message.h"
#include "test_routines.h"


/*+
 * Output - Output Function 
 *
 * Description:
 * 		Used where a an output function is required, this just copies its
 * 		output message into a global buffer for later examination.
-*/

static char output_buffer[4096];

static void Output(const char* text)
{
	strncpy(output_buffer, text, sizeof(output_buffer));
	output_buffer[sizeof(output_buffer) - 1] = '\0';

	return;
}



/*+
 * TestMsgInitRundown - Test MsgInit, MsgRundown (and MsgFindCodeBlock)
 *
 * Description:
 * 		Registers a set of messages, checks that they are there, runs the
 * 		module down, then checks that the messages can't be found.
-*/

static void TestMsgInitRundown(void)
{
	int BLOCK0_LOW = 10240;
	int BLOCK0_HIGH  = 10245;
	const char* BLOCK0_MESSAGES[] = {
		"ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON", "ZETA"
	};

	MsgInit();

	/* No match after initialization */

	CU_ASSERT_EQUAL(MsgFindCodeBlock(BLOCK0_LOW), -1);

	/* Register a message block and check again */

	MsgRegister(BLOCK0_LOW, BLOCK0_HIGH, BLOCK0_MESSAGES, MsgNoOutput);
	CU_ASSERT_NOT_EQUAL(MsgFindCodeBlock(BLOCK0_LOW), -1);

	/* Rundown the module and check again */

	MsgRundown();
	CU_ASSERT_EQUAL(MsgFindCodeBlock(BLOCK0_LOW), -1);

	return;
}



/*+
 * TestMsgRegisterText - Test MsgRegsiter and MsgText Functions
 *
 * Description:
 *      Registers multiple sets of messages and checks that the message can be
 *      retrieved.
-*/

static void TestMsgRegisterText(void)
{
	int i;

	int BLOCK1_LOW = 20480;
	int BLOCK1_HIGH  = 20485;
	const char* BLOCK1_MESSAGES[] = {
		"ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON", "ZETA"
	};

	int BLOCK2_LOW = 30720;
	int BLOCK2_HIGH  = 30725;
	const char* BLOCK2_MESSAGES[] = {
		"ALEPH", "BETH", "GIMMEL", "DALET", "HEY", "VAV"
	};

	MsgInit();

	/* Register two blocks of messages with a null output function */

	MsgRegister(BLOCK1_LOW, BLOCK1_HIGH, BLOCK1_MESSAGES, MsgNoOutput);
	MsgRegister(BLOCK2_LOW, BLOCK2_HIGH, BLOCK2_MESSAGES, MsgNoOutput);

	/* Now check the text */

	for (i = BLOCK1_LOW; i <= BLOCK1_HIGH; ++i) {
		CU_ASSERT_STRING_EQUAL(MsgText(i), BLOCK1_MESSAGES[i - BLOCK1_LOW]);
	}

	for (i = BLOCK2_LOW; i <= BLOCK2_HIGH; ++i) {
		CU_ASSERT_STRING_EQUAL(MsgText(i), BLOCK2_MESSAGES[i - BLOCK2_LOW]);
	}

	MsgRundown();

	return;
}


/*+
 * TestMsgGetSetOutput - Test MsgGetOutput and MsgSetOutput
 *
 * Description:
 * 		Sets and gets the output function for a block of messages.
-*/

static void TestMsgGetSetOutput(void)
{
	int BLOCK3_LOW = 40960;
	int BLOCK3_HIGH  = 40965;
	const char* BLOCK3_MESSAGES[] = {
		"A", "B", "C", "D", "E", "F"
	};

	MsgInit();

	/*
	 * Register the above block of messages and check that we can obtain
	 * the output function.  Note that MsgGetOutput only requires the number
	 * of a code in the range, so any value in the range will do.
	 */

	MsgRegister(BLOCK3_LOW, BLOCK3_HIGH, BLOCK3_MESSAGES, MsgNoOutput);
	CU_ASSERT_PTR_EQUAL((void*) MsgGetOutput(BLOCK3_LOW), (void*) MsgNoOutput);

	/* Change the output function and check again */

	MsgSetOutput(BLOCK3_HIGH, MsgDefaultOutput);
	CU_ASSERT_PTR_EQUAL((void*) MsgGetOutput(BLOCK3_LOW), (void*) MsgDefaultOutput);

	MsgRundown();

	return;
}


/*+
 * TestMsgLog - Test MsgLog Function
 *
 * Description:
 * 		Checks that MsgLog correctly handles the substitution of arguments.
-*/

static void TestMsgLog(void)
{
	int BLOCK4_LOW = 51200;
	int BLOCK4_HIGH  = 51201;
	const char* BLOCK4_MESSAGES[] = {
		"There are %d %ss in the store",
		"%d %ss a %s"
	};
	int status;		/* Status return */

	MsgInit();

	MsgRegister(BLOCK4_LOW, BLOCK4_HIGH, BLOCK4_MESSAGES, Output);

	status = MsgLog(BLOCK4_LOW, 15, "orange");
	CU_ASSERT_EQUAL(status, BLOCK4_LOW);
	CU_ASSERT_STRING_EQUAL(output_buffer, "There are 15 oranges in the store");

	status = MsgLog(BLOCK4_HIGH, 10, "lord", "leaping");
	CU_ASSERT_EQUAL(status, BLOCK4_HIGH);
	CU_ASSERT_STRING_EQUAL(output_buffer, "10 lords a leaping");

	MsgRundown();

	return;
}


/*+
 * TestMessage  - Create Test Suite
 *
 * Description:
 *      Adds the test suite to the CUnit test registry and adds all the tests
 *      to it.
 *
 * Arguments:
 *      None.
 *
 * Returns:
 *      int
 *          Return status.  0 => Success.
 */

int TestMsg(void);	/* Declaration */
int TestMsg(void)
{
    struct test_testdef tests[] = {
        {"TestMsgInitRundown",		TestMsgInitRundown},
        {"TestMsgRegisterText",		TestMsgRegisterText},
        {"TestMsgGetSetOutput",		TestMsgGetSetOutput},
        {"TestMsgLog",    			TestMsgLog},
        {NULL,                      NULL}
    };

    return TcuCreateSuite("Msg", NULL, NULL, tests);
}
