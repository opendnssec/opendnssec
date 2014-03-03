/*
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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

/*
 * orm.cpp
 *
 * Integration of protobuf-orm code in ods codebase
 * Hooks logging etc.
 *
 */

#include "config.h"
#include "orm.h"
#include "shared/log.h"
#include "shared/file.h"
#include "protobuf-orm/pb-orm.h"

static const char *module_str = "orm";

// The ap parameter has already been started with va_start.
// This handler only has to pass this on to a vprintf function
// to actually print it.
static int
ods_orm_log_error(const char *format, va_list ap)
{
	ods_log_verror(format, ap);
	return 0;
}

void
ods_orm_initialize()
{
	if (!OrmInitialize()) 
		ods_log_error("[%s] ORM initialization failed",module_str);
	else
		OrmSetLogErrorHandler(ods_orm_log_error);
}

void
ods_orm_shutdown()
{
	OrmSetLogErrorHandler(NULL);
	OrmShutdown();
}

static int
ods_orm_connect_mysql(int sockfd, engineconfig_type *config, OrmConn *conn)
{
	if (!OrmDatastoreMySQL()) {
		ods_log_error_and_printf(sockfd, module_str, "datastore MySQL is not available/builtin");
		return 0;
	}

	std::string host(config->db_host ? config->db_host : "");
	int port = config->db_port;
	std::string username(config->db_username ? config->db_username : "");
	std::string password(config->db_password ? config->db_password : "");
	std::string dbname(config->datastore ? config->datastore : "");
	std::string encoding("UTF-8");

	if (!OrmConnectMySQL(host,port,username,password,dbname,encoding,*conn)) {
		ods_log_error_and_printf(sockfd,
								 module_str,
								 "failed to open datastore \"%s\"",
								 config->datastore);
		return 0;
	}
	
	return 1;
}

static int
ods_orm_connect_sqlite3(int sockfd, engineconfig_type *config, OrmConn *conn)
{
	if (!OrmDatastoreSQLite3()) {
		ods_log_error_and_printf(sockfd, module_str, "datastore SQLite3 is not available/builtin");
		return 0;
	}

	// Split the datastore path into separate directory and name
	std::string dbdir(config->datastore);
	size_t slashpos = dbdir.rfind('/');
	if (slashpos == std::string::npos) {
		ods_log_error_and_printf(sockfd,
								 module_str,
								 "invalid datastore \"%s\"",
								 config->datastore);
		return 0;
	}
	std::string dbname;
	dbname = dbdir.substr(slashpos);
	dbdir.erase(slashpos);
	
	if (!OrmConnectSQLite3(dbdir, dbname, *conn)) {
		ods_log_error_and_printf(sockfd,
								 module_str,
								 "failed to open datastore \"%s\"",
								 config->datastore);
		return 0;
	}
	
	return 1;
}


int
ods_orm_connect(int sockfd, engineconfig_type *config, OrmConn *conn)
{
	if (config->db_username)
		return ods_orm_connect_mysql(sockfd,config,conn);
	else
		return ods_orm_connect_sqlite3(sockfd,config,conn);
}
