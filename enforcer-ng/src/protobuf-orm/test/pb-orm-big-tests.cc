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
 pb-orm-big-tests.cc

 Contains test cases to test with messages defined in the zone.proto file
 *****************************************************************************/

#include <time.h>

#include "pb-orm-big-tests.h"
#include "timecollector.h"
#include "pbormtest.h"

#include "big.pb.h"

CPPUNIT_TEST_SUITE_REGISTRATION(BigTests);

void BigTests::setUp()
{
	Stopwatch swatch("BigTests::setUp");

	conn = NULL;

	OrmInitialize();

	__setup_conn(conn);

	OrmDropTable(conn,::pb_orm_test::BigMessageRepeated::descriptor());
	OrmDropTable(conn,::pb_orm_test::BigMessage::descriptor());

	CPPUNIT_ASSERT(OrmCreateTable(conn,::pb_orm_test::BigMessage::descriptor()));
	CPPUNIT_ASSERT(OrmCreateTable(conn,::pb_orm_test::BigMessageRepeated::descriptor()));
}

void BigTests::tearDown()
{
	Stopwatch swatch("BigTests::tearDown");

    if (conn) {
    	CPPUNIT_ASSERT(OrmDropTable(conn,::pb_orm_test::BigMessageRepeated::descriptor()));
    	CPPUNIT_ASSERT(OrmDropTable(conn,::pb_orm_test::BigMessage::descriptor()));
		OrmConnClose(conn);
    }
    OrmShutdown();
}

void BigTests::testProtobufFields()
{
	Stopwatch swatch("BigTests::testProtobufFields");
	
	::pb_orm_test::BigMessage *msg = new ::pb_orm_test::BigMessage;
	
	CPPUNIT_ASSERT_MESSAGE("has_f_bool() must return false as it has not had a value set",!msg->has_f_bool());
	
	msg->set_f_bool(msg->f_bool()); 
	msg->set_f_int32(-32);
	msg->set_f_sint32(-32);
	msg->set_f_sfixed32(-32);
	msg->set_f_uint32(32);
	msg->set_f_fixed32(32);
	msg->set_f_int64(-64);
	msg->set_f_sint64(-64);
	msg->set_f_sfixed64(-64);
	msg->set_f_uint64(64);
	msg->set_f_fixed64(64);
	msg->set_f_float(1.32f);
	msg->set_f_double(1.64);
	msg->set_f_string("this is a string");
	
	msg->set_f_bytes("these\x1are bytes",15);
	msg->set_f_testenum(::pb_orm_test::two);
	msg->set_f_date(time(NULL));
	
	struct tm time_value = { 0 };
	time_value.tm_hour = 23;
	time_value.tm_min = 59;
	time_value.tm_sec = 59;
	msg->set_f_time(mktime(&time_value));
	
	
	struct tm date_value = { 0 };
	date_value.tm_year = 2011-1900; // years since 1900
	date_value.tm_mon = 12-1; // months since january [0..11]
	date_value.tm_mday = 31; // day of the month [1..31]
	msg->set_f_datetime(mktime(&date_value));
	
	CPPUNIT_ASSERT_MESSAGE("has_f_bool() must return true because a value was set",msg->has_f_bool());
	CPPUNIT_ASSERT(	msg->f_bytes() == std::string("these\x1are bytes",15));

	CPPUNIT_ASSERT(msg->f_int32() == -32);
	
	msg->clear_f_int32();
	
	CPPUNIT_ASSERT(msg->f_int32() == 123);
	
	delete msg;
}

void BigTests::testDatabaseTransaction()
{	
	Stopwatch swatch("BigTests::testDatabaseTransaction");
	{
		OrmTransaction trans(conn);
		OrmResult result;
		if (OrmConnQuery(conn,"INSERT INTO BigMessage (f_bool) VALUES (0)",result)) {
			OrmFreeResult(result);
		}
		trans.rollback();
	}
	
	{
		OrmResult result;
		CPPUNIT_ASSERT(OrmConnQuery(conn,"SELECT id FROM BigMessage",result));
		CPPUNIT_ASSERT_MESSAGE("expecting rollback to undo insertion",!OrmNext(result));
		OrmFreeResult(result);
	}
	
	{
		OrmTransaction trans(conn);
		OrmResult result;
		if (OrmConnQuery(conn,"INSERT INTO BigMessage (f_bool) VALUES (0)",result)) {
			OrmFreeResult(result);
		}
		trans.commit();
	}
	
	{
		OrmResult result;
		CPPUNIT_ASSERT(OrmConnQuery(conn,"SELECT id FROM BigMessage",result));
		CPPUNIT_ASSERT_MESSAGE("expected a record in result",OrmFirst(result));
		CPPUNIT_ASSERT_MESSAGE("expected a single record in result",!OrmNext(result));
		OrmFreeResult(result);
	}
	
}

// All code under test must be linked into the Unit Test bundle
void BigTests::testMessageCRUD()
{
	Stopwatch swatch("BigTests::testMessageCRUD");
	// Create a new message in a table.
	::pb_orm_test::BigMessage msg;
	
	pb::uint64 msgid;
	CPPUNIT_ASSERT(OrmMessageInsert(conn, msg, msgid));
	
	// We now should have exactly 1 message in the table
	CPPUNIT_ASSERT(OrmMessageFind(conn, msg.descriptor(), msgid));
	
	// Read a message from a table.
	OrmContext context;
	CPPUNIT_ASSERT(OrmMessageRead(conn, msg, msgid, false, context));
	
	// Change the message otherwise to actually change something in the table.
	msg.set_f_int32(42);
	
	CPPUNIT_ASSERT(msg.has_f_fixed32());
	msg.clear_f_fixed32();
	
	// Update a message in a table.
	CPPUNIT_ASSERT(OrmMessageUpdate(context));
	
	// Make sure the field is assigned
	msg.set_f_fixed32(999);
	
	// Read a message from a table.
	CPPUNIT_ASSERT(OrmMessageRead(conn, msg, msgid,false,context));
	
	CPPUNIT_ASSERT_MESSAGE("Expected field to be cleared",!msg.has_f_fixed32());
	
	// Delete a message from a table.
	CPPUNIT_ASSERT(OrmMessageDelete(conn, msg.descriptor(), msgid));
	
	// Message should no longer be present in the table.
	CPPUNIT_ASSERT(!OrmMessageFind(conn, msg.descriptor(), msgid));
	
	// Update a message in a table, should succeed but affect no rows in the db.
	CPPUNIT_ASSERT(OrmMessageUpdate(context));
	
	OrmFreeContext(context);
}

void BigTests::testMessageUpdate()
{
	Stopwatch swatch("BigTests::testMessageUpdate");
	OrmResult result;
	::pb_orm_test::BigMessage all;
	pb::uint64 allid;

	// set the bytes to a new value
	
	// STRING ENCODING GOTCHA:
	// "we\x01are" will actually be interpreted as "we\x1are".
	// The 'a' actually becomes part of the hex encoded character, stupid no ?
	// So we delimit the embedded hex value with additional double quotes
	// to prevent surprises.
	const char *blobdata = "contained there""\x1""are\0bytes";
	CPPUNIT_ASSERT(blobdata[15] == '\x1');
	std::string blob(blobdata,25);
	CPPUNIT_ASSERT(blob[15] == '\x1');
	
	all.set_f_bytes(blob);
	
	// create instance of the p1 field.
	pb_orm_test::Point *test = all.mutable_p1();
	test->set_x(1.23f);
	test->set_y(4.56f);
	
	// insert all message including the p1 field into the db
	CPPUNIT_ASSERT(OrmMessageInsert(conn, all, allid));
	
	// make sure the bytes value is gone.
	all.clear_f_bytes();
	
	// clear the message, then retrieve it so all fields are assigned from db
	all.Clear();
	OrmContext context;
	CPPUNIT_ASSERT(OrmMessageRead(conn, all, allid, false, context));
	
	// PRESENT IN: MESSAGE YES, DB NO
	// verify that after updateing the message is also in the db
	
	// change the all message and update the message in the db
	all.set_f_int64(1234567789);
	CPPUNIT_ASSERT(OrmMessageUpdate(context));
	OrmFreeContext(context);

	// clear the message, then retrieve it and verify p1 present and correct
	all.Clear();
	CPPUNIT_ASSERT(OrmMessageRead(conn, all, allid, false, context));
	
	CPPUNIT_ASSERT(all.has_f_bool());
	
	CPPUNIT_ASSERT(all.has_p1());
	CPPUNIT_ASSERT(all.p1().x() == 1.23f);
	CPPUNIT_ASSERT(all.p1().y() == 4.56f);
	
	// get id of the p1 for later checking
	const pb::FieldDescriptor *p1_F = 
	all.GetDescriptor()->FindFieldByName("p1");
	pb::uint64 p1_id;
	CPPUNIT_ASSERT(OrmFieldGetMessageId(conn, allid, p1_F, p1_id));
	
	// PRESENT IN: MESSAGE NO, DB YES
	// verify that after updateing the message is also removed from the the db
	
	// clear the p1 field for the 'all' message and update in db
	all.clear_p1();
	CPPUNIT_ASSERT(OrmMessageUpdate(context));
	OrmFreeContext(context);
	
	
	// retrieve the all message from the db and verify p1 still not set
	CPPUNIT_ASSERT(OrmMessageRead(conn, all, allid, false,context));
	CPPUNIT_ASSERT(!all.has_p1());

	// verify the bytes value contains expected value
	CPPUNIT_ASSERT(all.f_bytes().size() == blob.size());
	CPPUNIT_ASSERT(all.f_bytes() == blob);
	
	// check that the p1 record was really removed from the db
	pb_orm_test::Point dummy;
	CPPUNIT_ASSERT(!OrmMessageFind(conn, dummy.descriptor(), p1_id));
	
	// PRESENT IN: MESSAGE NO, DB NO
	// verify that after updateing the message is still not present int the db
	
	// clear the p1 field for the 'all' message and update in db
	all.clear_p1();
	CPPUNIT_ASSERT(OrmMessageUpdate(context));
	OrmFreeContext(context);

	// Verify the after the update the message is still gone and has not re-appeared
	CPPUNIT_ASSERT(!OrmMessageFind(conn, pb_orm_test::Point::descriptor(), p1_id));

	result = NULL;
	CPPUNIT_ASSERT(!OrmFieldSelectMessage(conn, allid, p1_F, result));
	if (result)
		OrmFreeResult(result);

	// finally delete the all message from the db.
	CPPUNIT_ASSERT(OrmMessageDelete(conn, all.descriptor(), allid));
}

void BigTests::testDateTime()
{
	Stopwatch swatch("BigTests::testDateTime");
	// Create a new message in a table.
	::pb_orm_test::BigMessage msg;;
	
	pb::uint64 msgid;
	CPPUNIT_ASSERT(OrmMessageInsert(conn,msg,msgid));
	
	// Read a message from a table.
	OrmContext context;
	CPPUNIT_ASSERT(OrmMessageRead(conn, msg, msgid, false, context));
	
	// Time value specified as default in proto file is supposed to be GMT.
	// Verify that the default date time got translated correctly
	int refhour = 13;
	
	time_t dbtime = msg.f_datetime();
	struct tm dbtime_struct = {0};
	gmtime_r(&dbtime,&dbtime_struct);
	CPPUNIT_ASSERT_MESSAGE("Expected datetime to be identical for default and read.",refhour == dbtime_struct.tm_hour);	
	dbtime = msg.f_time();
	dbtime_struct.tm_hour = 0;
	gmtime_r(&dbtime,&dbtime_struct);
	CPPUNIT_ASSERT_MESSAGE("Expected time to be identical for default and read.",refhour == dbtime_struct.tm_hour);
	
	// Change the datetime and see whether it is read back correctly.
	time_t refnow = time(NULL);
	msg.set_f_datetime(refnow);
	
	// Change the time with a 23:59:59 duration to see if we can store time durations.
	time_t refduration = 24 * 60 * 60 - 1;
	msg.set_f_time(refduration);
	
	// Update a message in a table.
	CPPUNIT_ASSERT(OrmMessageUpdate(context));
	
	// Read a message from a table.
	CPPUNIT_ASSERT(OrmMessageRead(conn, msg, msgid,false));
	
	time_t dbnow = msg.f_datetime();
	CPPUNIT_ASSERT(refnow == dbnow);
	
	time_t dbduration = msg.f_time();
	CPPUNIT_ASSERT(refduration == dbduration);
	
	// Delete a message from a table.
	CPPUNIT_ASSERT(OrmMessageDelete(conn, msg.descriptor(), msgid));
	
	// Message should no longer be present in the table.
	CPPUNIT_ASSERT(!OrmMessageFind(conn, msg.descriptor(), msgid));
	
	// Update a message in a table, should not affect any records as the record is gone.
	CPPUNIT_ASSERT(OrmMessageUpdate(context));
	
	OrmFreeContext(context);
}

void BigTests::testBigRepeatedCreate()
{
	Stopwatch swatch("BigTests::testBigRepeatedCreate");

	const pb::Descriptor *d = ::pb_orm_test::BigMessageRepeated::descriptor();
	const pb::FieldDescriptor *boolF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFBoolsFieldNumber);
	const pb::FieldDescriptor *int32F = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFInt32SFieldNumber);
	const pb::FieldDescriptor *sint32F = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFSint32SFieldNumber);
	const pb::FieldDescriptor *sfixed32F = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFSfixed32SFieldNumber);
	const pb::FieldDescriptor *uint32F = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFUint32SFieldNumber);
	const pb::FieldDescriptor *fixed32F = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFFixed32SFieldNumber);
	const pb::FieldDescriptor *int64F = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFInt64SFieldNumber);
	const pb::FieldDescriptor *sint64F = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFSint64SFieldNumber);
	const pb::FieldDescriptor *sfixed64F = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFSfixed64SFieldNumber);
	const pb::FieldDescriptor *uint64F = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFUint64SFieldNumber);
	const pb::FieldDescriptor *fixed64F = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFFixed64SFieldNumber);
	const pb::FieldDescriptor *floatF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFFloatsFieldNumber);
	const pb::FieldDescriptor *doubleF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFDoublesFieldNumber);
	const pb::FieldDescriptor *stringF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFStringsFieldNumber);
	const pb::FieldDescriptor *bytesF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFBytessFieldNumber);
	const pb::FieldDescriptor *testenumF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFTestenumsFieldNumber);
	const pb::FieldDescriptor *pointF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFPointsFieldNumber);
	const pb::FieldDescriptor *datetimeF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFDatetimesFieldNumber);
	const pb::FieldDescriptor *dateF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFDatesFieldNumber);
	const pb::FieldDescriptor *timeF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFTimesFieldNumber);
	const pb::FieldDescriptor *yearF = d->FindFieldByNumber(::pb_orm_test::BigMessageRepeated::kFYearsFieldNumber);
	
	
	const int NUM_REPEATED = 10;
	{
		time_t now = time(NULL);
		struct tm now_s = {0};
		gmtime_r(&now,&now_s);
		
		OrmTransaction trans(conn);
		
		::pb_orm_test::BigMessageRepeated bmr;
		pb::uint64 bmrid;
		CPPUNIT_ASSERT(OrmMessageInsert(conn, bmr, bmrid));
		
		
		for (int i=0; i<NUM_REPEATED; ++i) {
			
			pb::uint64 fieldid;
			CPPUNIT_ASSERT(OrmFieldAddRepeatedBool(conn, bmrid, boolF, true, fieldid));
			
			CPPUNIT_ASSERT(OrmFieldAddRepeatedInt32(conn, bmrid, int32F, i, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedInt32(conn, bmrid, sint32F, i, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedInt32(conn, bmrid, sfixed32F, i, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedUint32(conn, bmrid, uint32F, i, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedUint32(conn, bmrid, fixed32F, i, fieldid));
			
			CPPUNIT_ASSERT(OrmFieldAddRepeatedInt64(conn, bmrid, int64F, i, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedInt64(conn, bmrid, sint64F, i, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedInt64(conn, bmrid, sfixed64F, i, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedUint64(conn, bmrid, uint64F, i, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedUint64(conn, bmrid, fixed64F, i, fieldid));
			
			CPPUNIT_ASSERT(OrmFieldAddRepeatedFloat(conn, bmrid, floatF, i * 1.0f, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedDouble(conn, bmrid, doubleF, i * 1.0, fieldid));
			
			CPPUNIT_ASSERT(OrmFieldAddRepeatedString(conn, bmrid, stringF, "testing !!!", fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedBinary(conn, bmrid, bytesF, "hello there !!!!", fieldid));
			
			CPPUNIT_ASSERT(OrmFieldAddRepeatedEnum(conn, bmrid, testenumF, "two", fieldid));
			
			::pb_orm_test::Point pt;
			pt.set_x(1.0);
			pt.set_y(2.0);
			CPPUNIT_ASSERT(OrmFieldAddRepeatedMessage(conn, bmrid, pointF, pt, fieldid));
			
			CPPUNIT_ASSERT(OrmFieldAddRepeatedDateTime(conn, bmrid, datetimeF, now, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedDate(conn, bmrid, dateF, now, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedTime(conn, bmrid, timeF, now, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedInt64(conn, bmrid, yearF, 1984, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedInt64(conn, bmrid, yearF, 1985, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedInt64(conn, bmrid, yearF, 1986, fieldid));
			CPPUNIT_ASSERT(OrmFieldAddRepeatedInt64(conn, bmrid, yearF, 1987, fieldid));
			
		}
		
		trans.commit();
		
		CPPUNIT_ASSERT(OrmMessageRead(conn, bmr, bmrid, true));
		CPPUNIT_ASSERT(bmr.f_floats_size() == NUM_REPEATED);
		CPPUNIT_ASSERT(bmr.f_times_size() == NUM_REPEATED);
		
		time_t dbtime = bmr.f_times(3);
		struct tm dbtime_s = {0};
		gmtime_r(&dbtime,&dbtime_s);
		
		CPPUNIT_ASSERT(dbtime_s.tm_hour == now_s.tm_hour && dbtime_s.tm_min==now_s.tm_min && dbtime_s.tm_sec==now_s.tm_sec);
	}
}
