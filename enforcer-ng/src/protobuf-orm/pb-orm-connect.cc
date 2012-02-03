/*
 * Created by René Post on 10/25/11.
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
//  pb-orm-connect.cc
//  protobuf-orm
//

#include "config.h"

#include "pb-orm-log.h"
#include "pb-orm-connect.h"
#include "pb-orm-database.h"
#include "pb-orm-database-sqlite3.h"
#include "pb-orm-database-mysql.h"

bool OrmConnectMySQL(const std::string &host,
					 int port,
					 const std::string &username,
					 const std::string &password,
					 const std::string &dbname,
					 const std::string &encoding,
					 OrmConn &handle)
{
#if defined(ENFORCER_DATABASE_MYSQL)
	DB::OrmConnT *conn = DB::MySQL::NewOrmConnT();
	if (!conn) {
		OrmLogError("unable to allocate connection, out of memory");
		return false;
	}

	if (host.size() > 0)
		conn->set_option("host", host);
	if (username.size() > 0)
		conn->set_option("username", username);
	if (password.size() > 0)
		conn->set_option("password", password);
	if (port)
		conn->set_option("port", port);
	if (dbname.size() > 0)
		conn->set_option("dbname", dbname);
	if (encoding.size() > 0)
		conn->set_option("encoding", encoding);

	if (!conn->connect()) {
		delete conn;
		return false;
	}
	handle = conn->handle();
	return true;
#else
	return false;
#endif
}

bool OrmConnectSQLite3(const std::string &dbdir,
					   const std::string &dbname,
					   OrmConn &handle)
{
#if defined(ENFORCER_DATABASE_SQLITE3)
	DB::OrmConnT *conn = DB::SQLite3::NewOrmConnT();

	if (!conn) {
		OrmLogError("unable to allocate connection, out of memory");
		return false;
	}

	if (dbdir.size() > 0)
		conn->set_option("sqlite3_dbdir", dbdir);
	if (dbname.size() > 0)
		conn->set_option("dbname", dbname);
	
	// allow busy timeout of transactions of 15 seconds.
	conn->set_option("timeout_ms", 15000);

	if (!conn->connect()) {
		delete conn;
		return false;
	}
	handle = conn->handle();
	return true;
#else
	return false;
#endif
}

void OrmConnClose(OrmConn handle)
{
	delete ((DB::OrmConnT *)handle);
}
