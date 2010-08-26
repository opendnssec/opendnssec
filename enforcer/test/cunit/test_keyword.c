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
 * Filename: test_keyword.c - Test Keyword Module
 *
 * Description:
 *      This is a short test module to check the functions in the keyword
 *      module.
 *
 *      The test program makes use of the CUnit framework, as described in
 *      http://cunit.sourceforge.net
-*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "CUnit/Basic.h"

#include "ksm/ksm.h"
#include "test_routines.h"


/*+
 * Test<type>KeywordConvert - Test Keyword Conversion Code
 *
 * Description:
 *      Tests the translation between the keywords and the values
 *      for the different keyword sets.
-*/

static void TestAlgorithmKeywordConvert(void)
{
    /* Name to value */

    CU_ASSERT_EQUAL(KSM_ALGORITHM_RSAMD5, KsmKeywordAlgorithmNameToValue("rsamd5"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_RSAMD5, KsmKeywordAlgorithmNameToValue("rsamd"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_RSAMD5, KsmKeywordAlgorithmNameToValue("rsam"));
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue("rsa"));
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue("rs"));
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue("r"));

    CU_ASSERT_EQUAL(KSM_ALGORITHM_DH, KsmKeywordAlgorithmNameToValue("dh"));
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue("d"));

    CU_ASSERT_EQUAL(KSM_ALGORITHM_DSASHA1, KsmKeywordAlgorithmNameToValue("dsa"));
    /*CU_ASSERT_EQUAL(KSM_ALGORITHM_DSASHA1, KsmKeywordAlgorithmNameToValue("ds"));*/
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue("d"));

    CU_ASSERT_EQUAL(KSM_ALGORITHM_RSASHA1, KsmKeywordAlgorithmNameToValue("rsasha1"));
    /*CU_ASSERT_EQUAL(KSM_ALGORITHM_RSASHA1, KsmKeywordAlgorithmNameToValue("rsasha"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_RSASHA1, KsmKeywordAlgorithmNameToValue("rsash"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_RSASHA1, KsmKeywordAlgorithmNameToValue("rsas"));*/
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue("rsa"));
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue("rs"));
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue("r"));

    /* add tests for dsa-nsec3-sha1, rsasha1-nsec3-sha1, rsasha256, rsasha512 */

    CU_ASSERT_EQUAL(KSM_ALGORITHM_INDIRECT, KsmKeywordAlgorithmNameToValue("indirect"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_INDIRECT, KsmKeywordAlgorithmNameToValue("indirec"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_INDIRECT, KsmKeywordAlgorithmNameToValue("indire"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_INDIRECT, KsmKeywordAlgorithmNameToValue("indir"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_INDIRECT, KsmKeywordAlgorithmNameToValue("indi"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_INDIRECT, KsmKeywordAlgorithmNameToValue("ind"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_INDIRECT, KsmKeywordAlgorithmNameToValue("in"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_INDIRECT, KsmKeywordAlgorithmNameToValue("i"));

    CU_ASSERT_EQUAL(KSM_ALGORITHM_PRIVDOM, KsmKeywordAlgorithmNameToValue("domain"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_PRIVDOM, KsmKeywordAlgorithmNameToValue("domai"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_PRIVDOM, KsmKeywordAlgorithmNameToValue("doma"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_PRIVDOM, KsmKeywordAlgorithmNameToValue("dom"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_PRIVDOM, KsmKeywordAlgorithmNameToValue("do"));
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue("d"));

    CU_ASSERT_EQUAL(KSM_ALGORITHM_PRIVOID, KsmKeywordAlgorithmNameToValue("oid"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_PRIVOID, KsmKeywordAlgorithmNameToValue("oi"));
    CU_ASSERT_EQUAL(KSM_ALGORITHM_PRIVOID, KsmKeywordAlgorithmNameToValue("o"));

    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue("xyz"));
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue(""));
    CU_ASSERT_EQUAL(0, KsmKeywordAlgorithmNameToValue(NULL));

    /* ... and the reverse */

    CU_ASSERT_STRING_EQUAL("rsamd5", KsmKeywordAlgorithmValueToName(KSM_ALGORITHM_RSAMD5));
    CU_ASSERT_STRING_EQUAL("dh", KsmKeywordAlgorithmValueToName(KSM_ALGORITHM_DH));
    CU_ASSERT_STRING_EQUAL("dsa", KsmKeywordAlgorithmValueToName(KSM_ALGORITHM_DSASHA1));
    CU_ASSERT_STRING_EQUAL("rsasha1", KsmKeywordAlgorithmValueToName(KSM_ALGORITHM_RSASHA1));
    CU_ASSERT_STRING_EQUAL("indirect", KsmKeywordAlgorithmValueToName(KSM_ALGORITHM_INDIRECT));
    CU_ASSERT_STRING_EQUAL("domain", KsmKeywordAlgorithmValueToName(KSM_ALGORITHM_PRIVDOM));
    CU_ASSERT_STRING_EQUAL("oid", KsmKeywordAlgorithmValueToName(KSM_ALGORITHM_PRIVOID));

    return;
}

static void TestFormatKeywordConvert(void)
{
    /* Name to value */

    CU_ASSERT_EQUAL(KSM_FORMAT_FILE, KsmKeywordFormatNameToValue("file"));
    CU_ASSERT_EQUAL(KSM_FORMAT_FILE, KsmKeywordFormatNameToValue("fil"));
    CU_ASSERT_EQUAL(KSM_FORMAT_FILE, KsmKeywordFormatNameToValue("fi"));
    CU_ASSERT_EQUAL(KSM_FORMAT_FILE, KsmKeywordFormatNameToValue("f"));

    CU_ASSERT_EQUAL(KSM_FORMAT_HSM, KsmKeywordFormatNameToValue("hsm"));
    CU_ASSERT_EQUAL(KSM_FORMAT_HSM, KsmKeywordFormatNameToValue("hs"));
    CU_ASSERT_EQUAL(KSM_FORMAT_HSM, KsmKeywordFormatNameToValue("h"));

    CU_ASSERT_EQUAL(KSM_FORMAT_URI, KsmKeywordFormatNameToValue("uri"));
    CU_ASSERT_EQUAL(KSM_FORMAT_URI, KsmKeywordFormatNameToValue("ur"));
    CU_ASSERT_EQUAL(KSM_FORMAT_URI, KsmKeywordFormatNameToValue("u"));

    CU_ASSERT_EQUAL(0, KsmKeywordFormatNameToValue("xyz"));
    CU_ASSERT_EQUAL(0, KsmKeywordFormatNameToValue(""));
    CU_ASSERT_EQUAL(0, KsmKeywordFormatNameToValue(NULL));

    /* ... and the reverse */

    CU_ASSERT_STRING_EQUAL("file", KsmKeywordFormatValueToName(KSM_FORMAT_FILE));
    CU_ASSERT_STRING_EQUAL("hsm", KsmKeywordFormatValueToName(KSM_FORMAT_HSM));
    CU_ASSERT_STRING_EQUAL("uri", KsmKeywordFormatValueToName(KSM_FORMAT_URI));

    return;
}

static void TestStateKeywordConvert(void)
{
    CU_ASSERT_EQUAL(KSM_STATE_GENERATE, KsmKeywordStateNameToValue("generate"));
    CU_ASSERT_EQUAL(KSM_STATE_GENERATE, KsmKeywordStateNameToValue("generat"));
    CU_ASSERT_EQUAL(KSM_STATE_GENERATE, KsmKeywordStateNameToValue("genera"));
    CU_ASSERT_EQUAL(KSM_STATE_GENERATE, KsmKeywordStateNameToValue("gener"));
    CU_ASSERT_EQUAL(KSM_STATE_GENERATE, KsmKeywordStateNameToValue("gene"));
    CU_ASSERT_EQUAL(KSM_STATE_GENERATE, KsmKeywordStateNameToValue("gen"));
    CU_ASSERT_EQUAL(KSM_STATE_GENERATE, KsmKeywordStateNameToValue("ge"));
    CU_ASSERT_EQUAL(KSM_STATE_GENERATE, KsmKeywordStateNameToValue("g"));

    CU_ASSERT_EQUAL(KSM_STATE_PUBLISH, KsmKeywordStateNameToValue("publish"));
    CU_ASSERT_EQUAL(KSM_STATE_PUBLISH, KsmKeywordStateNameToValue("publis"));
    CU_ASSERT_EQUAL(KSM_STATE_PUBLISH, KsmKeywordStateNameToValue("publi"));
    CU_ASSERT_EQUAL(KSM_STATE_PUBLISH, KsmKeywordStateNameToValue("publ"));
    CU_ASSERT_EQUAL(KSM_STATE_PUBLISH, KsmKeywordStateNameToValue("pub"));
    CU_ASSERT_EQUAL(KSM_STATE_PUBLISH, KsmKeywordStateNameToValue("pu"));
    CU_ASSERT_EQUAL(KSM_STATE_PUBLISH, KsmKeywordStateNameToValue("p"));

    CU_ASSERT_EQUAL(KSM_STATE_READY, KsmKeywordStateNameToValue("ready"));
    CU_ASSERT_EQUAL(KSM_STATE_READY, KsmKeywordStateNameToValue("read"));
    CU_ASSERT_EQUAL(KSM_STATE_READY, KsmKeywordStateNameToValue("rea"));
    CU_ASSERT_EQUAL(0, KsmKeywordStateNameToValue("re"));       /* Confused with "retired" */
    CU_ASSERT_EQUAL(0, KsmKeywordStateNameToValue("r"));        /* Confused with "retired" */

    CU_ASSERT_EQUAL(KSM_STATE_ACTIVE, KsmKeywordStateNameToValue("active"));
    CU_ASSERT_EQUAL(KSM_STATE_ACTIVE, KsmKeywordStateNameToValue("activ"));
    CU_ASSERT_EQUAL(KSM_STATE_ACTIVE, KsmKeywordStateNameToValue("acti"));
    CU_ASSERT_EQUAL(KSM_STATE_ACTIVE, KsmKeywordStateNameToValue("act"));
    CU_ASSERT_EQUAL(KSM_STATE_ACTIVE, KsmKeywordStateNameToValue("ac"));
    CU_ASSERT_EQUAL(KSM_STATE_ACTIVE, KsmKeywordStateNameToValue("a"));

    CU_ASSERT_EQUAL(KSM_STATE_RETIRE, KsmKeywordStateNameToValue("retire"));
    CU_ASSERT_EQUAL(KSM_STATE_RETIRE, KsmKeywordStateNameToValue("retir"));
    CU_ASSERT_EQUAL(KSM_STATE_RETIRE, KsmKeywordStateNameToValue("reti"));
    CU_ASSERT_EQUAL(KSM_STATE_RETIRE, KsmKeywordStateNameToValue("ret"));
    CU_ASSERT_EQUAL(0, KsmKeywordStateNameToValue("re"));       /* Confused with "ready" */
    CU_ASSERT_EQUAL(0, KsmKeywordStateNameToValue("r"));        /* Confused with "ready" */

    CU_ASSERT_EQUAL(KSM_STATE_DEAD, KsmKeywordStateNameToValue("dead"));
    CU_ASSERT_EQUAL(KSM_STATE_DEAD, KsmKeywordStateNameToValue("dea"));
    CU_ASSERT_EQUAL(KSM_STATE_DEAD, KsmKeywordStateNameToValue("de"));
    CU_ASSERT_EQUAL(0, KsmKeywordStateNameToValue("d"));

    /* ... and the reverse */

    CU_ASSERT_STRING_EQUAL("generate", KsmKeywordStateValueToName(KSM_STATE_GENERATE));
    CU_ASSERT_STRING_EQUAL("publish", KsmKeywordStateValueToName(KSM_STATE_PUBLISH));
    CU_ASSERT_STRING_EQUAL("ready",     KsmKeywordStateValueToName(KSM_STATE_READY));
    CU_ASSERT_STRING_EQUAL("active",    KsmKeywordStateValueToName(KSM_STATE_ACTIVE));
    CU_ASSERT_STRING_EQUAL("retire",   KsmKeywordStateValueToName(KSM_STATE_RETIRE));
    CU_ASSERT_STRING_EQUAL("dead",      KsmKeywordStateValueToName(KSM_STATE_DEAD));

    return;
}

static void TestTypeKeywordConvert(void)
{
    CU_ASSERT_EQUAL(KSM_TYPE_KSK, KsmKeywordTypeNameToValue("ksk"));
    CU_ASSERT_EQUAL(KSM_TYPE_KSK, KsmKeywordTypeNameToValue("ks"));
    CU_ASSERT_EQUAL(KSM_TYPE_KSK, KsmKeywordTypeNameToValue("k"));

    CU_ASSERT_EQUAL(KSM_TYPE_ZSK, KsmKeywordTypeNameToValue("zsk"));
    CU_ASSERT_EQUAL(KSM_TYPE_ZSK, KsmKeywordTypeNameToValue("zs"));
    CU_ASSERT_EQUAL(KSM_TYPE_ZSK, KsmKeywordTypeNameToValue("z"));

    /* ... and the reverse */

    CU_ASSERT_STRING_EQUAL("ksk", KsmKeywordTypeValueToName(KSM_TYPE_KSK));
    CU_ASSERT_STRING_EQUAL("zsk", KsmKeywordTypeValueToName(KSM_TYPE_ZSK));

    return;
}



/*
 * TestKeyword - Create Test Suite
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

int TestKeyword(void);	/* Declaration */
int TestKeyword(void)
{
    struct test_testdef tests[] = {
        {"AlgorithmKeywordConvert", TestAlgorithmKeywordConvert},
        {"FormatKeywordConvert",    TestFormatKeywordConvert},
        {"StateKeywordConvert",     TestStateKeywordConvert},
        {"TypeKeywordConvert",      TestTypeKeywordConvert},
        {NULL,                      NULL}
    };

    return TcuCreateSuite("Keyword", NULL, NULL, tests);
}
