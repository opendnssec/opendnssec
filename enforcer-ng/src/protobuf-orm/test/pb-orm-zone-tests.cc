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
 pb-orm-zone-tests.cc

 Contains test cases to test with messages defined in the zone.proto file
 *****************************************************************************/

#include "pb-orm-zone-tests.h"
#include "timecollector.h"
#include "pbormtest.h"

#include "zone.pb.h"

CPPUNIT_TEST_SUITE_REGISTRATION(ZoneTests);

void ZoneTests::setUp()
{
	Stopwatch swatch("ZoneTests::setUp");

	conn = NULL;

	OrmInitialize();

	__setup_conn(conn);

	OrmDropTable(conn,::pb_orm_test::EnforcerZone::descriptor());

	CPPUNIT_ASSERT(OrmCreateTable(conn,::pb_orm_test::EnforcerZone::descriptor()));
}

void ZoneTests::tearDown()
{
	Stopwatch swatch("ZoneTests::tearDown");

    if (conn) {
    	CPPUNIT_ASSERT(OrmDropTable(conn,::pb_orm_test::EnforcerZone::descriptor()));
		OrmConnClose(conn);
    }
    OrmShutdown();
}

void ZoneTests::testZonesCRUD()
{	
	Stopwatch swatch("ZoneTests::testZonesCRUD");

	pb_orm_test::EnforcerZone zone;
	pb::uint64 zoneid;
	CPPUNIT_ASSERT_MESSAGE("Should fail because fields not set",!OrmMessageInsert(conn, zone, zoneid));

	zone.set_name("surfnet.nl");
	zone.set_policy("default");

	pb_orm_test::KeyData *keydata = zone.add_keys();
	keydata->set_locator("1234567890");
	keydata->set_algorithm(1);
	keydata->set_inception((pb::uint32)time(NULL)); // datetime !

	pb_orm_test::KeyState *ds = keydata->mutable_ds();

	ds->set_state(pb_orm_test::sohidden); // default = hidden
	ds->set_last_change(0); // opt
	ds->set_minimize(false); // default = false
	ds->set_ttl(3600); // opt

	pb_orm_test::KeyState *rrsig = keydata->mutable_rrsig();
	rrsig->set_state(pb_orm_test::sohidden); // default = hidden
	rrsig->set_last_change(0); // opt
	rrsig->set_minimize(false); // default = false
	rrsig->set_ttl(3600); // opt


	pb_orm_test::KeyState *dnskey = keydata->mutable_dnskey();
	dnskey->set_state(pb_orm_test::sohidden); // default = hidden
	dnskey->set_last_change(0); // opt
	dnskey->set_minimize(false); // default = false
	dnskey->set_ttl(3600); // opt

	keydata->set_role(pb_orm_test::ZSK);

	pb_orm_test::KeyState *rrsigdnskey = keydata->mutable_rrsigdnskey();
	rrsigdnskey->set_state(pb_orm_test::sohidden); // default = hidden
	rrsigdnskey->set_last_change(0); // opt
	rrsigdnskey->set_minimize(false); // default = false
	rrsigdnskey->set_ttl(3600); // opt

	zone.set_signconf_needs_writing(true);
	zone.set_signconf_path("/var/opendnssec/signconf/surfnet.nl.xml");
	zone.set_next_change(0);

	CPPUNIT_ASSERT_MESSAGE("should succeed now because required fields are set",OrmMessageInsert(conn, zone, zoneid));

	CPPUNIT_ASSERT(OrmMessageRead(conn, zone, zoneid, true));
}
