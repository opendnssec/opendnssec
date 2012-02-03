/*
 * Created by René Post on 12/8/11.
 * Copyright (c) 2011 xpt Software & Consulting B.V. All rights reserved.
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

//
//  pb-orm-database-helper.cc
//  protobuf-orm
//


#include "pb-orm-database-helper.h"
#include "pb-orm-log.h"

time_t pb_sqlite3_gmtime(struct tm *tm)
{
	// We don't want to depend on timegm() so we use a workaround via the
	// gmtime_r() function to determine this.
	// As input we use a moment in time just 10 days after the POSIX epoch.
	// The POSIX epoch is defined as the moment in time at midnight Coordinated
	// Universal Time (UTC) of Thursday, January 1, 1970. A time_t value is
	// the number of seconds elapsed since epoch.
	struct tm ref_tm = {0};
	ref_tm.tm_year = 70; // Years since 1900;
	ref_tm.tm_mday = 10; // 10th
	
	// We need the time difference between local time and UTC time.
	// mktime will interpret the UTC time stored in tm as local time
	// so let's assume we are in a time zone 1 hour ahead of UTC (UTC+1)
	// then a time of 13:00 interpreted as local time needs 1 hour subtracted 
	// to arrive at UTC time. This UTC time is then converted to a POSIX
	// time_t value.
	time_t posix_time = mktime(&ref_tm);
	
	// Use gmtime_r to convert the POSIX time back to a tm struct.
	// No time adjustment is done this time because POSIX time is 
	// defined in terms of UTC.
	gmtime_r(&posix_time, &ref_tm);
	if (ref_tm.tm_isdst != 0) {
		OrmLogError("expected gmtime_r to return zero in tm_isdst member of tm struct");
		return ((time_t)-1);
	}
	
	// Using mktime again to convert tm. This will again subtract 1 hour from
	// the time (under the assumption that we are 1 hour ahead of UTC).
	// We can now use this to determine how much local time differred
	// from UTC time on january the 10th 1970
	long diff_time = posix_time - mktime(&ref_tm);
	
	// We explicitly set tm_isdst to zero to prevent errors
	// when the time we are trying to convert is occuring at 
	// the moment when a dst change is in progress.
	// We require mktime to respect our setting of tm_isdst 
	// indicating that no dst is in effect.
	tm->tm_isdst = 0; // Tell (and force) mktime not to take dst into account.

	// We now can calculate and return a correct POSIX time.
	// So, although mktime() interprets gm_tm as local time adjusts for 
	// the time difference between local time and UTC time. We then undo
	// that adjustment by adding diff_time.
	return mktime(tm) + diff_time;
}

time_t pb_mysql_gmtime(struct tm *tm)
{
	return pb_sqlite3_gmtime(tm);
}
