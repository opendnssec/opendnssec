/*
 * Created by René Post on 12/7/11.
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
//  pb-orm-database-sqlite3.cc
//  protobuf-orm
//

#include "pb-orm-database-sqlite3.h"

#if ENFORCER_DATABASE_SQLITE3

#include <stdlib.h>
#include <time.h>
#include <map>
#include <sqlite3.h>
#include <cstdio>

#include "pb-orm-str.h"
#include "pb-orm-log.h"
#include "pb-orm-database-helper.h"

#define HAVE_SILENT_BUSY_AND_LOCKED_ERRORS 1

namespace DB {

	bool SQLite3::initialize()
	{
		int err = sqlite3_initialize();
		if (err != SQLITE_OK) {
			OrmLogError("SQLITE3: sqlite3_initialize failed with error %d",err);
			return false;
		}

		return true;
	}

	void SQLite3::shutdown()
	{
		sqlite3_shutdown();
	}

	namespace SQLite3 {
		
		///////////////////////////
		//
		// SQLite3::OrmResultImpl
		//	declaration
		//
		///////////////////////////
		
		class OrmResultImpl : public ::DB::OrmResultImpl {
		public:
			sqlite3_stmt *stmt;
			std::map<std::string, int> fields;
			
			OrmResultImpl(sqlite3_stmt * stmt_);
			virtual ~OrmResultImpl();
			
			virtual bool assigned();
			virtual bool failed();
			
			virtual bool get_numrows(unsigned long long &numrows);
			
			virtual bool first_row();
			virtual bool next_row();
			
			virtual unsigned int get_field_idx(const std::string &fieldname);
			virtual bool field_is_null_idx(unsigned int fieldidx);
			virtual time_t get_datetime_idx(unsigned int fieldidx);
			virtual unsigned char get_uchar_idx(unsigned int fieldidx);
			virtual float get_float_idx(unsigned int fieldidx);
			virtual double get_double_idx(unsigned int fieldidx);
			virtual int get_int_idx(unsigned int fieldidx);
			virtual long long get_longlong_idx(unsigned int fieldidx);
			virtual unsigned long long get_ulonglong_idx(unsigned int fieldidx);
			virtual unsigned int get_uint_idx(unsigned int fieldidx);
			virtual const char *get_string_idx(unsigned int fieldidx);
			virtual const unsigned char *get_binary_idx(unsigned int fieldidx);
			virtual size_t get_field_length_idx(unsigned int fieldidx);
			
			virtual bool field_is_null(const std::string &fieldname);
			virtual time_t get_datetime(const std::string &fieldname);
			virtual unsigned char get_uchar(const std::string &fieldname);
			virtual float get_float(const std::string &fieldname);
			virtual double get_double(const std::string &fieldname);
			virtual int get_int(const std::string &fieldname);
			virtual long long get_longlong(const std::string &fieldname);
			virtual unsigned long long get_ulonglong(const std::string &fieldname);
			virtual unsigned int get_uint(const std::string &fieldname);
			virtual const char *get_string(const std::string &fieldname);
			virtual const unsigned char *get_binary(const std::string &fieldname);
			virtual size_t get_field_length(const std::string &fieldname);
			
		protected:
			void check_and_report_errors();
		};
		
	}
	
	///////////////////////////
	//
	// SQLite3::OrmResultImpl
	//	implementation
	//
	///////////////////////////
	
	SQLite3::OrmResultImpl::OrmResultImpl(sqlite3_stmt * stmt_)
	: stmt(stmt_)
	{
	}
	
	SQLite3::OrmResultImpl::~OrmResultImpl()
	{
		if (stmt) {
			sqlite3_finalize(stmt);
			stmt = NULL;
		}
	}
	
	bool SQLite3::OrmResultImpl::assigned()
	{
		return stmt != 0;
	}
	
	bool SQLite3::OrmResultImpl::failed()
	{
		if (!stmt)
			return true;
		sqlite3 *db = sqlite3_db_handle(stmt);
		if (!db)
			return true;
		int error = sqlite3_errcode(db);
		return error != SQLITE_OK && error != SQLITE_ROW && error != SQLITE_DONE;
	}
	
	bool SQLite3::OrmResultImpl::get_numrows(unsigned long long &numrows)
	{
		if (!stmt) return false;
		numrows = 0;
		if (sqlite3_reset(stmt) != SQLITE_OK) {
			
			return false;
		}
		int step = sqlite3_step(stmt);
		for ( ; step == SQLITE_ROW; step=sqlite3_step(stmt)) {
			// do nothing...
			// step returns SQLITE_ROW or SQLITE_DONE
			++numrows;
		}
		return step==SQLITE_DONE;
	}
	
	bool SQLite3::OrmResultImpl::first_row()
	{
		if (!stmt) return false;
		// reset result set, check for errors and select the first row.
		if (sqlite3_reset(stmt)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW)
			return false;

		// collect the field names from the result set and set them up for access.
		fields.clear();
		for (int i=0; i<sqlite3_data_count(stmt); ++i) {
			// offset field index with 1 to allow 0 to be invalid index.
			fields[sqlite3_column_name(stmt, i)] = 1+i;
		}
		
		return true;
	}
	
	bool SQLite3::OrmResultImpl::next_row()
	{
		if (!stmt) return false;
		return sqlite3_step(stmt)==SQLITE_ROW;
	}
	
	unsigned int SQLite3::OrmResultImpl::get_field_idx(const std::string &fieldname)
	{
		unsigned int fieldidx = fields[fieldname];
		if (fieldidx == 0)
			OrmLogError("invalid field name \"%s\"",fieldname.c_str());
		return fieldidx;
	}
	
	bool SQLite3::OrmResultImpl::field_is_null_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return true;
		}
		int column_type = sqlite3_column_type(stmt, fieldidx-1);
		return column_type == SQLITE_NULL;
	}

	time_t SQLite3::OrmResultImpl::get_datetime_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return ((time_t)-1);
		}

		const unsigned char *value = sqlite3_column_text(stmt, fieldidx-1);
		int valuelen = sqlite3_column_bytes(stmt, fieldidx-1);

//		printf("datetime:%s\n",value);

		unsigned long years,mons,days,hours,mins,secs;
		struct tm gm_tm = {0};
		gm_tm.tm_isdst = 0; // Tell mktime not to take dst into account.
		gm_tm.tm_year = 70; // 1970
		gm_tm.tm_mday = 1; // 1th day of the month
		const char *p = (const char *)value;
		char *pnext;
		bool bdateonly = true;
		switch (valuelen) {
			case 19:	// 2011-12-31 23:59:59
				bdateonly = false;
			case 10:	// 2011-12-31
				years = strtoul(p,&pnext,10);
				gm_tm.tm_year = ((int)years)-1900; /* years since 1900 */
				p = pnext+1;
				mons = strtoul(p,&pnext,10);
				gm_tm.tm_mon = ((int)mons)-1; /* months since January [0-11] */
				p = pnext+1;
				days = strtoul(p,&pnext,10);
				gm_tm.tm_mday = ((int)days); /* day of the month [1-31] */
				p = pnext+1;
				if (bdateonly)
					break;
			case 8:		// 23:59:59
				hours = strtoul(p,&pnext,10);
				gm_tm.tm_hour = (int)hours; /* hours since midnight [0-23] */
				if ((pnext-p) != 2) {
					OrmLogError("invalid hours in time: '%s'",value);
					return 0;
				}
				p = pnext+1;
				mins = strtoul(p,&pnext,10);
				gm_tm.tm_min = (int)mins; /* minutes after the hour [0-59] */
				if ((pnext-p) != 2) {
					OrmLogError("invalid minutes in time: '%s'",value);
					return 0;
				}
				p = pnext+1;
				secs = strtoul(p,&pnext,10);
				gm_tm.tm_sec = (int)secs; /* seconds after the minute [0-60] */
				if ((pnext-p) != 2) {
					OrmLogError("invalid seconds in time: '%s'",value);
					return 0;
				}
				break;
			default:
				OrmLogError("invalid date/time value: '%s'",value);
				return 0;
		}

		return pb_sqlite3_gmtime(&gm_tm);
	}
	
	unsigned char SQLite3::OrmResultImpl::get_uchar_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		int value = sqlite3_column_int(stmt, fieldidx-1);
		check_and_report_errors();
		return (unsigned char)value;
	}
	
	float SQLite3::OrmResultImpl::get_float_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0.0f;
		}
		double value = sqlite3_column_double(stmt, fieldidx-1);
		check_and_report_errors();
		return (float)value;
	}
	
	double SQLite3::OrmResultImpl::get_double_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0.0;
		}
		double value = sqlite3_column_double(stmt, fieldidx-1);
		check_and_report_errors();
		return value;
	}
	
	int SQLite3::OrmResultImpl::get_int_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		int value = sqlite3_column_int(stmt, fieldidx-1);
		check_and_report_errors();
		return value;
	}
	
	long long SQLite3::OrmResultImpl::get_longlong_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		sqlite3_int64 value = sqlite3_column_int64(stmt, fieldidx-1);
		check_and_report_errors();
		return value;
	}
	
	unsigned long long SQLite3::OrmResultImpl::get_ulonglong_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		sqlite3_int64 value = sqlite3_column_int64(stmt, fieldidx-1);
		check_and_report_errors();
		return (unsigned long long)value;
	}
	
	unsigned int SQLite3::OrmResultImpl::get_uint_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		int value = sqlite3_column_int(stmt, fieldidx-1);
		check_and_report_errors();
		return (unsigned int)value;
	}
	
	const char *SQLite3::OrmResultImpl::get_string_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return NULL;
		}
		const unsigned char *value = sqlite3_column_text(stmt,fieldidx-1);
		check_and_report_errors();
		return (const char *)value;
	}
	
	const unsigned char *SQLite3::OrmResultImpl::get_binary_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return NULL;
		}
		const unsigned char *value =
			(const unsigned char *)sqlite3_column_blob(stmt,fieldidx-1);
		check_and_report_errors();
		return value;
	}
	
	size_t SQLite3::OrmResultImpl::get_field_length_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		int value = sqlite3_column_bytes(stmt,fieldidx-1);
		check_and_report_errors();
		return (size_t)value;
	}
	
	bool SQLite3::OrmResultImpl::field_is_null(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return true;
		return field_is_null_idx( fieldidx );
	}
	
	time_t SQLite3::OrmResultImpl::get_datetime(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return ((time_t)-1);
		return get_datetime_idx(fieldidx);
	}
	
	unsigned char SQLite3::OrmResultImpl::get_uchar(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_uchar_idx(fieldidx);
	}
	
	float SQLite3::OrmResultImpl::get_float(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0.0f;
		return get_float_idx(fieldidx);
	}
	
	double SQLite3::OrmResultImpl::get_double(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0.0;
		return get_double_idx(fieldidx);
	}
	
	int SQLite3::OrmResultImpl::get_int(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_int_idx(fieldidx);
	}
	
	long long SQLite3::OrmResultImpl::get_longlong(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_longlong_idx(fieldidx);
	}
	
	unsigned long long SQLite3::OrmResultImpl::get_ulonglong(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_ulonglong_idx(fieldidx);
	}
	
	unsigned int SQLite3::OrmResultImpl::get_uint(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_uint_idx(fieldidx);
	}
	
	const char *SQLite3::OrmResultImpl::get_string(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return NULL;
		return get_string_idx(fieldidx);
	}
	
	const unsigned char *SQLite3::OrmResultImpl::get_binary(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return NULL;
		return get_binary_idx(fieldidx);
	}
	
	size_t SQLite3::OrmResultImpl::get_field_length(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_field_length_idx(fieldidx);
	}

	void SQLite3::OrmResultImpl::check_and_report_errors()
	{
		if (!stmt) {
			OrmLogError("sqlite3_statement pointer is NULL");
			return;
		}

		sqlite3 *db = sqlite3_db_handle(stmt);
		if (!db) {
			OrmLogError("sqlite3 pointer is NULL");
			return;
		}
		
		int rv = sqlite3_errcode(db);
		if (rv == SQLITE_OK || rv == SQLITE_ROW || rv == SQLITE_DONE)
			return;

#ifdef HAVE_SILENT_BUSY_AND_LOCKED_ERRORS
		// database table is either busy or locked
		if (rv == SQLITE_BUSY || rv == SQLITE_LOCKED)
			return;
#endif

		OrmLogError("SQLITE3: %s (%d)", sqlite3_errmsg(db), rv);
	}

	///////////////////////////
	//
	// SQLite3::OrmConnT
	//	declaration
	//
	///////////////////////////
	
	
	namespace SQLite3 {
	
		class OrmConnT : public DB::OrmConnT {
		public:
			sqlite3 *db;

			OrmConnT();
			virtual ~OrmConnT();
			
			virtual void set_option(const std::string &name,const std::string &value);
			virtual void set_option(const std::string &name,int value);
			
			virtual bool connect();
			virtual void close();
			
			virtual bool begin_transaction();
			virtual bool begin_transaction_rw();
			virtual bool in_transaction();
			virtual bool commit_transaction();
			virtual bool rollback_transaction();
			
			virtual OrmResultT query(const char *statement, int len);
			
			virtual bool table_exists(const std::string &name);
			virtual bool quote_string(const std::string &value, std::string &dest);
			virtual bool quote_binary(const std::string &value, std::string &dest);
			
			virtual unsigned long long sequence_last();
			const char *idfield();
			virtual OrmResultT CreateTableMessage(const std::string &name,
													const std::string &fields);
			virtual OrmResultT CreateTableRelation(const std::string &name);
			virtual OrmResultT CreateTableRepeatedValue(const std::string &name,
														  const std::string &type);
			
		protected:
			std::map< std::string, std::string >_options;
			std::map< std::string, int>_numoptions;
			bool successful(int rv);
		};

	}
	
	///////////////////////////
	//
	// SQLite3::OrmConnT
	//	implementation
	//
	///////////////////////////
	
	SQLite3::OrmConnT::OrmConnT() : db(NULL)
	{
		_numoptions["timeout_ms"] = 15000; // 15 seconds
	}
	
	SQLite3::OrmConnT::~OrmConnT()
	{
		close();
	}

	void SQLite3::OrmConnT::set_option(const std::string &name,
									   const std::string &value)
	{
		_options[name] = value;
	}
	
	void SQLite3::OrmConnT::set_option(const std::string &name,int value)
	{
		_numoptions[name] = value;
	}

	bool SQLite3::OrmConnT::connect()
	{
		std::string dbpath = _options["sqlite3_dbdir"];
		std::string dbname = _options["dbname"];
		OrmChain(dbpath, dbname, '/' );
		int rv = sqlite3_open_v2(dbpath.c_str(),
								 &db,
								 SQLITE_OPEN_READWRITE
								 | SQLITE_OPEN_CREATE
								 | SQLITE_OPEN_FULLMUTEX,
								 NULL);
		if (!successful(rv))
			return false;
		
		rv = sqlite3_busy_timeout(db, _numoptions["timeout_ms"]);
		if (!successful(rv)) {
			close();
			return false;
		}
		
		return true;
	}
	
	void SQLite3::OrmConnT::close()
	{
		if (db) {
			sqlite3_close(db);
			db = NULL;
		}
	}

	bool SQLite3::OrmConnT::begin_transaction()
	{
		return query("BEGIN",5).assigned();
	}

	bool SQLite3::OrmConnT::begin_transaction_rw()
	{
		return query("BEGIN IMMEDIATE",15).assigned();
	}
	
	bool SQLite3::OrmConnT::in_transaction()
	{
		return sqlite3_get_autocommit(db)==0;
	}

	bool SQLite3::OrmConnT::commit_transaction()
	{
		return query("COMMIT",6).assigned();
	}

	bool SQLite3::OrmConnT::rollback_transaction()
	{
		return query("ROLLBACK",8).assigned();
	}

	OrmResultT SQLite3::OrmConnT::query(const char *statement, int len)
	{
		sqlite3_stmt *stmt = NULL;

		int rv = sqlite3_prepare_v2(db,
									statement,
									(len<0) ? (int)-1 : (int)len+1,
									&stmt,
									NULL);
		if (!successful(rv)) {
			if (stmt)
				sqlite3_finalize(stmt);
			return OrmResultT();
		}
		
		if (!stmt) {
			OrmLogError("expected sqlite3_prepare_v2 to return a compiled "
						"statement, got NULL, out of memory ?");
			return OrmResultT();
		}

		int step = sqlite3_step(stmt);
		if (!successful(step)) {
			sqlite3_finalize(stmt);
			return OrmResultT();
		}
	
		return OrmResultT((OrmConn)this, new SQLite3::OrmResultImpl(stmt));
	}
		
	bool SQLite3::OrmConnT::table_exists(const std::string &name)
	{
		OrmResultT exists = queryf(
			"SELECT name FROM sqlite_master WHERE type='table' AND name='%s';",
									 name.c_str());
		if (exists.assigned())
			return exists->first_row();
		else
			return false;
	}
	
	bool SQLite3::OrmConnT::quote_string(const std::string &value,
										 std::string &dest)
	{
		char *strcopy = sqlite3_mprintf("%Q",value.c_str());
		if (!strcopy) {
			OrmLogError("unable to perform sqlite3_mprintf, out of memory ?");
			return false;
		}
		dest.assign(strcopy);
		sqlite3_free((void*)strcopy);
		return true;
	}
	
	bool SQLite3::OrmConnT::quote_binary(const std::string &value, std::string &dest)
	{
		size_t vsize = value.size();
		
		// encode empty value as a NULL
		if (vsize == 0) {
			dest = "NULL";
			return true;
		}
		
		// create hex encoded literal of the bytes in the value
		const char * const hexnib = "0123456789abcdef";
		const char *vdata = value.data();
		dest.clear();
		dest.push_back('X');
		dest.push_back('\'');
		for (size_t i=0; i<vsize; ++i) {
			char ch = vdata[i];
			dest.push_back( hexnib[(ch >> 4) & 0x0f] );
			dest.push_back( hexnib[(ch & 0x0f)] );
		}
		dest.push_back('\'');
		return true;
	}

	unsigned long long SQLite3::OrmConnT::sequence_last()
	{
		return sqlite3_last_insert_rowid(db);
	}

	const char *SQLite3::OrmConnT::idfield()
	{
		// To get maximum performance on SQLite the form below is choosen deliberately.
		// For example, we use INTEGER instead of INT or BIGINT and we don't use UNSIGNED.
		// Any one of those modifications would introduce a second id column alongside the 
		// ROWID column that is already there by default !
		// So if you think you need to modify the primary key id below please 
		// be aware of and investigate potential consequences.
		return "id INTEGER PRIMARY KEY AUTOINCREMENT";
	}

	OrmResultT SQLite3::OrmConnT::CreateTableMessage(const std::string &name,
												  const std::string &fields)
	{
		std::string allfields(fields);
		OrmChain(allfields,idfield(),',');
		return queryf("CREATE TABLE %s (%s)",
					  name.c_str(),
					  allfields.c_str());
	}

	OrmResultT SQLite3::OrmConnT::CreateTableRelation(const std::string &name)
	{
		return queryf("CREATE TABLE %s (parent_id INTEGER,child_id INTEGER,"
					  "PRIMARY KEY(parent_id,child_id))",
					  name.c_str());
	}

	OrmResultT SQLite3::OrmConnT::CreateTableRepeatedValue(const std::string &name,
															 const std::string &type)
	{
		return queryf("CREATE TABLE %s (value %s,parent_id INTEGER,%s)",
					  name.c_str(),
					  type.c_str(),
					  idfield());
	}

	bool SQLite3::OrmConnT::successful(int rv)
	{
		if (rv == SQLITE_OK || rv == SQLITE_ROW || rv == SQLITE_DONE)
			return true;

#ifdef HAVE_SILENT_BUSY_AND_LOCKED_ERRORS
		// database table is either busy or locked
		if (rv == SQLITE_BUSY || rv == SQLITE_LOCKED)
			return false;
#endif

		OrmLogError("SQLITE3: %s (%d)", sqlite3_errmsg(db), rv);
		return false;
	}

	///////////////////////////
	//
	// SQLite3::NewOrmConnT
	//	definition
	//
	///////////////////////////

	OrmConnT * SQLite3::NewOrmConnT()
	{
		return new SQLite3::OrmConnT();
	}


} // namespace DB

#endif // ENFORCER_DATABASE_SQLITE3
