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
//  pb-orm-connect.h
//  protobuf-orm
//

#ifndef pb_orm_connect_h
#define pb_orm_connect_h

#include "pb-orm-common.h"

/**
 * Establish and ORM connection with a MySQL database.
 * \param[in] host name of the MySQL server to connect to e.g. "example.com"
 * \param[in] port port on the MySQL server to connect to use 0 (zero) to 
 *				connect to the default MySQL server port (3306).
 * \param[in] username name of the database user
 * \param[in] password password for the database user
 * \param[in] dbname name of the database to use
 * \param[in] encoding the character encoding to use e.g. "UTF-8"
 * \return bool returns whether the connection was successfully established.
 *
 */
bool OrmConnectMySQL(const std::string &host,
					 int port,
					 const std::string &username,
					 const std::string &password,
					 const std::string &dbname,
					 const std::string &encoding,
					 OrmConn &conn);

bool OrmConnectSQLite3(const std::string &dbdir,
					   const std::string &dbname,
					   OrmConn &conn);

void OrmConnClose(OrmConn conn);


class OrmConnRef {
public:
	OrmConnRef() : _conn(NULL) {
	}
	~OrmConnRef() {
		release();
	}
	operator OrmConn*() {
		return &_conn;
	}
	operator OrmConn&() {
		return _conn;
	}
	void release() {
		if (_conn) {
			OrmConnClose(_conn);
			_conn = NULL;
		}
	}
protected:
	OrmConn _conn;
private:
	// disable evil contructors
	OrmConnRef(const OrmConnRef&);
	void operator=(const OrmConnRef&);
};

#endif
