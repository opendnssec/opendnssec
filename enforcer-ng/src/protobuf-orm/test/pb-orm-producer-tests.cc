/* $Id$ */

/*
 * Copyright (c) 2011 SURFnet bv
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
 pb-orm-producer-tests.cc

 Contains test cases to test messages from producer.proto
 We test a producer with multiple consumers that use transactions to 
 synchronize via the database using multiple threads.
 *****************************************************************************/


#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <fcntl.h>

#include "pb-orm-producer-tests.h"

#include "product.pb.h"

#include "timecollector.h"

CPPUNIT_TEST_SUITE_REGISTRATION(ProducerTests);

static void pb_orm_initialize()
{
#ifdef USE_CLIENT_LIB_DBI
	OrmInitialize("/usr/local/lib/dbd");
#elif USE_CLIENT_LIB_SQLITE3
	OrmInitialize();
#else
#error no database client library selected
#endif
	
//	OrmSetLogErrorHandler(NULL);
}

static bool pb_orm_connect(OrmConn &conn)
{
	conn = NULL;
#ifdef USE_DB_MYSQL	
	if (!OrmConnectMySQL("localhost", "root", "", "sample_db", "UTF-8", conn))
		return false;
#elif USE_DB_SQLITE3
	if (!OrmConnectSQLite3("/Users/rene/sqlite3", "sample_db", conn))
		return false;
#else
#error no database type selected
#endif
	return true;
}

void ProducerTests::setUp()
{
	Stopwatch swatch("ProducerTests::setUp");
	pb_orm_initialize();
	if (pb_orm_connect(conn)) {
		OrmCreateTable(conn,::pb_orm_test::Product::descriptor());
	}
}

void ProducerTests::tearDown()
{
	Stopwatch swatch("ProducerTests::tearDown");

    if (conn) {
		OrmDropTable(conn,::pb_orm_test::Product::descriptor());
		OrmConnClose(conn);
    }
    OrmShutdown();
}

const size_t NUM_CONSUMERS = 32;
const size_t NUM_TO_CONSUME = 50;
const size_t NUM_TO_PRODUCE = NUM_CONSUMERS * NUM_TO_CONSUME;

void * const THREAD_OK = ((void*)1);
const size_t SPINLOCK_CONSUMER = NUM_TO_CONSUME;
const size_t SPINLOCK_PRODUCER = NUM_TO_PRODUCE;
const size_t SPINLOCK_COMMIT = 1;

static void *consumer(void *param)
{
	pb::uint64 index = (pb::uint64)param;
	try {
		OrmConnRef conn;
		CPPUNIT_ASSERT(pb_orm_connect(conn));
		
		pb::uint32 loopcount = 0;
		for (int eat=0; eat<NUM_TO_CONSUME; ) {
			// terminate the loop after looping a large number of times.
			CPPUNIT_ASSERT(loopcount < SPINLOCK_CONSUMER);
			++loopcount;
			
			OrmTransactionRW transaction(conn);
			if (!transaction.started())
				continue;
			{
				// put this inside a block to make sure all
				// database resources referenced by OrmResultRef and OrmContextRef
				// objects are released before a transaction rollback is performed.
				::pb_orm_test::Product product;
				OrmResultRef rows;
				if (!(OrmMessageEnumWhere(conn, product, rows, "inception IS NULL")))
					continue;
				
				if ( OrmFirst(rows) ) {
				
					OrmContextRef ctx;
					if (OrmGetMessage(rows, product, true, ctx)) {
						
						product.set_inception(time(NULL));
						product.set_index(index);
						
						if (OrmMessageUpdate(ctx)) {
							
							// Before committing make sure all the 
							// db resources are released first.
							rows.release();
							ctx.release();
						
							// commit in a spinlock when the database was updated
							for (int j=1; j<SPINLOCK_COMMIT+1; ++j) {
								if (transaction.commit()) {
									++eat; // managed to consume 1
//									printf("\nCONSUMER TRANSACTION %d SUCCESS AFTER %d TRIES",eat,j);
									break;
								}
							}
						}
					}
				} else {
					// query empty !
					--loopcount;
				}
			}
		}
		
	} catch (CppUnit::Exception e) {
		printf("ERROR: %s\n",e.what());
		return NULL;
	}
	return THREAD_OK;
}

static void *producer(void *param)
{
	try {
		OrmConnRef conn;
		CPPUNIT_ASSERT(pb_orm_connect(conn));

		::pb_orm_test::Product product;
		product.set_payload("payload !");
		pb::uint32 loopcount = 0;
		for (int i=1; i<(NUM_TO_PRODUCE+1); ) {
			// terminate the loop after looping a large number of times.
			CPPUNIT_ASSERT(loopcount < SPINLOCK_PRODUCER);
			++loopcount;

			OrmTransactionRW transaction(conn);
			if (transaction.started()) {
				pb::uint64 productid;
				product.set_index(i);
				if (OrmMessageInsert(conn, product, productid)) {
					// commit in a spinlock
					for (int j=1; j<SPINLOCK_COMMIT+1; ++j) { 
						if (transaction.commit()) {
							++i;
//							printf("\nPRODUCER TRANSACTION %d SUCCESS AFTER %d TRIES",i,j);
							break;
						}
					}
				}
			}
		}

	} catch (CppUnit::Exception e) {
//		printf("ERROR: %s\n",e.what());
		return NULL;
	}
	return THREAD_OK;
}

void ProducerTests::testProducerTransactions()
{	
	Stopwatch swatch("ProducerTests::testProducerTransactions");

	pthread_t prod, cons[NUM_CONSUMERS];
	void *prod_status = NULL;
	void *cons_status[NUM_CONSUMERS] = {NULL};

	// start the producer
	pthread_create(&prod, NULL, producer, NULL);

	// start multiple consumers
	for (int i=0; i<GOOGLE_ARRAYSIZE(cons); ++i) {
		pthread_create(&cons[i], NULL, consumer, (void*)i);
	}

	// collect results from producers and consumers
	pthread_join(prod, &prod_status);
	for (int i=0; i<GOOGLE_ARRAYSIZE(cons); ++i) {
		pthread_join(cons[i],&cons_status[i]);
	}

	CPPUNIT_ASSERT(prod_status == THREAD_OK);
	for (int i=0; i<GOOGLE_ARRAYSIZE(cons_status); ++i) {
		char buf[32];
		sprintf(buf, "i == %d", i);
		CPPUNIT_ASSERT_MESSAGE(buf,cons_status[i] == THREAD_OK);
	}
}
