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

#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>

#include "pb-orm-producer-tests.h"
#include "timecollector.h"
#include "pbormtest.h"

#include "product.pb.h"

CPPUNIT_TEST_SUITE_REGISTRATION(ProducerTests);

void ProducerTests::setUp()
{
	Stopwatch swatch("ProducerTests::setUp");

	conn = NULL;

	OrmInitialize();

	__setup_conn(conn);

	OrmDropTable(conn,::pb_orm_test::Product::descriptor());

	CPPUNIT_ASSERT(OrmCreateTable(conn,::pb_orm_test::Product::descriptor()));
}

void ProducerTests::tearDown()
{
	Stopwatch swatch("ProducerTests::tearDown");

    if (conn) {
    	CPPUNIT_ASSERT(OrmDropTable(conn,::pb_orm_test::Product::descriptor()));
		OrmConnClose(conn);
    }
    OrmShutdown();
}

const size_t NUM_CONSUMERS = 4;
const size_t NUM_TO_CONSUME = 50;
const size_t NUM_TO_PRODUCE = NUM_CONSUMERS * NUM_TO_CONSUME;

void * const THREAD_OK = ((void*)1);
const size_t SPINLOCK_CONSUMER = NUM_TO_CONSUME;
const size_t SPINLOCK_PRODUCER = NUM_TO_PRODUCE;
const size_t SPINLOCK_COMMIT = 1;

int NUM_RUNNING = 0;
pthread_mutex_t NUM_RUNNING_MUTEX = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t NUM_RUNNING_COND = PTHREAD_COND_INITIALIZER;

static void *consumer(void *param)
{
	pb::uint64 index = (pb::uint64)param;
	try {
		OrmConnRef conn;
		
		__setup_conn(conn);

		pb::uint32 loopcount = 0;
		for (int eat=0; eat<NUM_TO_CONSUME; ) {
			// terminate the loop after looping a large number of times.
			CPPUNIT_ASSERT(loopcount < SPINLOCK_CONSUMER);
			++loopcount;
			
			double start = clock();
			OrmTransactionRW transaction(conn);
			if (!transaction.started())
				continue;
			{
				// put this inside a block to make sure all
				// database resources referenced by OrmResultRef and OrmContextRef
				// objects are released before a transaction rollback is performed.
				::pb_orm_test::Product product;
				OrmResultRef rows;
				if (!(OrmMessageEnumWhere(conn, product.descriptor(), rows, "inception IS NULL")))
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
									loopcount = 0;
									//printf("CONSUMER TRANSACTION %d SUCCESS AFTER %d TRIES IN %.0f us\n", eat, j, (clock() - start) / (CLOCKS_PER_SEC / 1000000));
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
		std::string str = "Exception in consumer: ";
		str += e.what();
		CPPUNIT_FAIL(str.c_str());
		NUM_RUNNING--;
		pthread_cond_signal(&NUM_RUNNING_COND);
		return NULL;
	}
	NUM_RUNNING--;
	pthread_cond_signal(&NUM_RUNNING_COND);
	return THREAD_OK;
}

static void *producer(void *param)
{
	try {
		OrmConnRef conn;

		__setup_conn(conn);

		::pb_orm_test::Product product;
		product.set_payload("payload !");
		pb::uint32 loopcount = 0;
		for (int i=1; i<(NUM_TO_PRODUCE+1); ) {
			// terminate the loop after looping a large number of times.
			CPPUNIT_ASSERT(loopcount < SPINLOCK_PRODUCER);
			++loopcount;

			double start = clock();
			OrmTransactionRW transaction(conn);
			if (transaction.started()) {
				pb::uint64 productid;
				product.set_index(i);
				if (OrmMessageInsert(conn, product, productid)) {
					// commit in a spinlock
					for (int j=1; j<SPINLOCK_COMMIT+1; ++j) { 
						if (transaction.commit()) {
							//printf("PRODUCER TRANSACTION %d SUCCESS AFTER %d TRIES IN %.0f us\n", i, j, (clock() - start) / (CLOCKS_PER_SEC / 1000000));
							++i;
							break;
						}
					}
				}
			}
		}

	} catch (CppUnit::Exception e) {
		std::string str = "Exception in producer: ";
		str += e.what();
		CPPUNIT_FAIL(str.c_str());
		NUM_RUNNING--;
		pthread_cond_signal(&NUM_RUNNING_COND);
		return NULL;
	}
	NUM_RUNNING--;
	pthread_cond_signal(&NUM_RUNNING_COND);
	return THREAD_OK;
}

void ProducerTests::testProducerTransactions()
{	
	Stopwatch swatch("ProducerTests::testProducerTransactions");

	pthread_t prod, cons[NUM_CONSUMERS];
	void *prod_status = NULL;
	void *cons_status[NUM_CONSUMERS] = {NULL};
	struct timeval tv;
	struct timespec ts;

	//printf("\n");

	NUM_RUNNING = 1 + NUM_CONSUMERS;

	if (pthread_mutex_lock(&NUM_RUNNING_MUTEX)) {
		CPPUNIT_FAIL("Unable to lock mutex for cond");
		return;
	}

	// start the producer
	pthread_create(&prod, NULL, producer, NULL);

	// start multiple consumers
	for (int i=0; i<GOOGLE_ARRAYSIZE(cons); ++i) {
		pthread_create(&cons[i], NULL, consumer, (void*)i);
	}

	// wait for threads to finish or timeout
	gettimeofday(&tv, NULL);
	ts.tv_sec = tv.tv_sec + 60;
	ts.tv_nsec = 0;
	while (NUM_RUNNING > 0) {
		if (pthread_cond_timedwait(&NUM_RUNNING_COND, &NUM_RUNNING_MUTEX, &ts)) {
			// timed out or failed, cancel all thread and report error
			pthread_cancel(prod);
			for (int i=0; i<GOOGLE_ARRAYSIZE(cons); ++i) {
				pthread_cancel(cons[i]);
			}

			CPPUNIT_FAIL("Timed out or error waiting for producer/consumer to finish");
		}
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
