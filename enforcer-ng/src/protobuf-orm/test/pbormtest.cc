/*
 * Copyright (c) 2010 SURFnet bv
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

/*****************************************************************************
 pbormtest.cpp

 The main test executor for tests on the protocol buffers ORM extension.
 *****************************************************************************/

#include "config.h"

#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TextTestProgressListener.h>
#include <cppunit/BriefTestProgressListener.h>
#include "timecollector.h"

#include "pbormtest.h"

void __setup_conn(OrmConn &conn)
{
	if (OrmDatastoreSQLite3()) {
		OrmConnectSQLite3("./", "sample_db", conn);
		CPPUNIT_ASSERT_MESSAGE("OrmConnectSQLite3", conn);
	}
	else if(OrmDatastoreMySQL()) {
		OrmConnectMySQL(ENFORCER_DB_HOST,
				ENFORCER_DB_PORT,
				ENFORCER_DB_USERNAME,
				ENFORCER_DB_PASSWORD,
				ENFORCER_DB_DATABASE,
				"UTF-8",
				conn);
		CPPUNIT_ASSERT_MESSAGE("OrmConnectMySQL", conn);
	}

	CPPUNIT_ASSERT_MESSAGE("No database connection", conn);
}

void __setup_conn(OrmConnRef &conn)
{
	if (OrmDatastoreSQLite3()) {
		OrmConnectSQLite3("./", "sample_db", conn);
		CPPUNIT_ASSERT_MESSAGE("OrmConnectSQLite3", &conn);
	}
	else if(OrmDatastoreMySQL()) {
		OrmConnectMySQL(ENFORCER_DB_HOST,
				ENFORCER_DB_PORT,
				ENFORCER_DB_USERNAME,
				ENFORCER_DB_PASSWORD,
				ENFORCER_DB_DATABASE,
				"UTF-8",
				conn);
		CPPUNIT_ASSERT_MESSAGE("OrmConnectMySQL", &conn);
	}

	CPPUNIT_ASSERT_MESSAGE("No database connection", &conn);
}

int main(int argc, char* argv[])
{
	CppUnit::TextUi::TestRunner runner;
	CppUnit::TestFactoryRegistry &registry = CppUnit::TestFactoryRegistry::getRegistry();

	CppUnit::TestResult controller;
	CppUnit::TestResultCollector result;
	CppUnit::TextTestProgressListener progress;
	CppUnit::BriefTestProgressListener status;

	controller.addListener( &result );
	controller.addListener( &progress );
	controller.addListener( &status );

	runner.addTest(registry.makeTest());
	runner.run(controller);

	PrintCollectedTimings();
	return !result.wasSuccessful();
}
