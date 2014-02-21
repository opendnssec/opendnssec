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
//  pb-orm-database-mysql.cc
//  protobuf-orm
//

#include "pb-orm-database-mysql.h"

#if ENFORCER_DATABASE_MYSQL

#include <stdlib.h>
#include <time.h>
#include <map>
#include <utility>
#include <mysql/mysql.h>
#include <cstdio>

#include "pb-orm-str.h"
#include "pb-orm-log.h"
#include "pb-orm-database-helper.h"

namespace DB {

	bool MySQL::initialize()
	{
		return true;
	}

	void MySQL::shutdown()
	{
	}

	namespace MySQL {
		
		///////////////////////////
		//
		// MySQL::OrmResultImpl
		//	declaration
		//
		///////////////////////////
		
		class OrmResultImpl : public ::DB::OrmResultImpl {
		public:
			MYSQL_RES *result;
			std::map<std::string, int> fields;
			std::map<int, std::pair<const char *, size_t> > row;
			
			OrmResultImpl(MYSQL_RES *result_);
			OrmResultImpl(bool success);
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
			
		private:
			bool _fetch_row();
			bool _success;
		};
		
	}
	
	///////////////////////////
	//
	// MySQL::OrmResultImpl
	//	implementation
	//
	///////////////////////////
	
	MySQL::OrmResultImpl::OrmResultImpl(MYSQL_RES *result_)
		: result(result_), _success(false)
	{
		if (result) {
			MYSQL_FIELD *mysql_fields;
			unsigned int i, num_fields;

			if (!(mysql_fields = mysql_fetch_fields(result))) {
				OrmLogError("Unable to fetch fields, destroying result");
				mysql_free_result(result);
				result = NULL;
				return;
			}

			for (i=0, num_fields=mysql_num_fields(result); i<num_fields; i++) {
				fields[mysql_fields[i].name] = i+1;
			}

			_success = true;
		}
	}

	MySQL::OrmResultImpl::OrmResultImpl(bool success)
		: result(NULL), _success(success)
	{
	}
	
	MySQL::OrmResultImpl::~OrmResultImpl()
	{
		if (result) {
			mysql_free_result(result);
			result = NULL;
		}
	}
	
	bool MySQL::OrmResultImpl::assigned()
	{
		return result || _success;
	}
	
	bool MySQL::OrmResultImpl::failed()
	{
		return !_success;
	}
	
	bool MySQL::OrmResultImpl::get_numrows(unsigned long long &numrows)
	{
		if (!result)
			return false;

		numrows = mysql_num_rows(result);

		return true;
	}
	
	bool MySQL::OrmResultImpl::_fetch_row()
	{
		if (!result)
			return false;

		MYSQL_ROW r;
		unsigned long *l;
		unsigned int i, num_fields;

		if (!(r = mysql_fetch_row(result))) {
			return false;
		}

		if (!(l = mysql_fetch_lengths(result))) {
			return false;
		}

		row.clear();

		for (i=0, num_fields = mysql_num_fields(result); i<num_fields; i++) {
			row[i].first = r[i];
			row[i].second = l[i];
		}

		return true;
	}

	bool MySQL::OrmResultImpl::first_row()
	{
		if (!result)
			return false;

		if (!mysql_num_rows(result))
			return false;
		
		mysql_data_seek(result, 0);

		return _fetch_row();
	}
	
	bool MySQL::OrmResultImpl::next_row()
	{
		if (!result)
			return false;

		if (!mysql_num_rows(result))
			return false;

		return _fetch_row();
	}
	
	unsigned int MySQL::OrmResultImpl::get_field_idx(const std::string &fieldname)
	{
		unsigned int fieldidx = fields[fieldname];
		if (fieldidx == 0)
			OrmLogError("invalid field name \"%s\"",fieldname.c_str());
		return fieldidx;
	}
	
	bool MySQL::OrmResultImpl::field_is_null_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return true;
		}
		return row[fieldidx-1].first == NULL;
	}

	time_t MySQL::OrmResultImpl::get_datetime_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return ((time_t)-1);
		}
		if (!row[fieldidx-1].first) {
			return ((time_t)-1);
		}

		const char *value = row[fieldidx-1].first;
		size_t valuelen = row[fieldidx-1].second;

//		printf("datetime:%s\n",value);

		unsigned long years,mons,days,hours,mins,secs;
		struct tm gm_tm = {0};
		gm_tm.tm_isdst = 0; // Tell mktime not to take dst into account.
		gm_tm.tm_year = 70; // 1970
		gm_tm.tm_mday = 1; // 1th day of the month
		const char *p = value;
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

		return pb_mysql_gmtime(&gm_tm);
	}
	
	unsigned char MySQL::OrmResultImpl::get_uchar_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		if (!row[fieldidx-1].first) {
			return 0;
		}
		return (unsigned char)atoi(row[fieldidx-1].first);
	}
	
	float MySQL::OrmResultImpl::get_float_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0.0f;
		}
		if (!row[fieldidx-1].first) {
			return 0.0f;
		}
		return atof(row[fieldidx-1].first);
	}
	
	double MySQL::OrmResultImpl::get_double_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0.0;
		}
		if (!row[fieldidx-1].first) {
			return 0.0;
		}
		return strtod(row[fieldidx-1].first, NULL);
	}
	
	int MySQL::OrmResultImpl::get_int_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		if (!row[fieldidx-1].first) {
			return 0;
		}
		return atoi(row[fieldidx-1].first);
	}
	
	long long MySQL::OrmResultImpl::get_longlong_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		if (!row[fieldidx-1].first) {
			return 0;
		}
		return atoll(row[fieldidx-1].first);
	}
	
	unsigned long long MySQL::OrmResultImpl::get_ulonglong_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		if (!row[fieldidx-1].first) {
			return 0;
		}
		return strtoull(row[fieldidx-1].first, NULL, 10);
	}
	
	unsigned int MySQL::OrmResultImpl::get_uint_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		if (!row[fieldidx-1].first) {
			return 0;
		}
		return (unsigned int)strtoul(row[fieldidx-1].first, NULL, 10);
	}
	
	const char *MySQL::OrmResultImpl::get_string_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return NULL;
		}
		if (!row[fieldidx-1].first) {
			return NULL;
		}
		return row[fieldidx-1].first;
	}
	
	const unsigned char *MySQL::OrmResultImpl::get_binary_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return NULL;
		}
		if (!row[fieldidx-1].first) {
			return NULL;
		}
		return (const unsigned char *)row[fieldidx-1].first;
	}
	
	size_t MySQL::OrmResultImpl::get_field_length_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return 0;
		}
		if (!row[fieldidx-1].first) {
			return 0;
		}
		return row[fieldidx-1].second;
	}
	
	bool MySQL::OrmResultImpl::field_is_null(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return true;
		return field_is_null_idx( fieldidx );
	}
	
	time_t MySQL::OrmResultImpl::get_datetime(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return ((time_t)-1);
		return get_datetime_idx(fieldidx);
	}
	
	unsigned char MySQL::OrmResultImpl::get_uchar(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_uchar_idx(fieldidx);
	}
	
	float MySQL::OrmResultImpl::get_float(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0.0f;
		return get_float_idx(fieldidx);
	}
	
	double MySQL::OrmResultImpl::get_double(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0.0;
		return get_double_idx(fieldidx);
	}
	
	int MySQL::OrmResultImpl::get_int(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_int_idx(fieldidx);
	}
	
	long long MySQL::OrmResultImpl::get_longlong(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_longlong_idx(fieldidx);
	}
	
	unsigned long long MySQL::OrmResultImpl::get_ulonglong(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_ulonglong_idx(fieldidx);
	}
	
	unsigned int MySQL::OrmResultImpl::get_uint(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_uint_idx(fieldidx);
	}
	
	const char *MySQL::OrmResultImpl::get_string(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return NULL;
		return get_string_idx(fieldidx);
	}
	
	const unsigned char *MySQL::OrmResultImpl::get_binary(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return NULL;
		return get_binary_idx(fieldidx);
	}
	
	size_t MySQL::OrmResultImpl::get_field_length(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return get_field_length_idx(fieldidx);
	}


	///////////////////////////
	//
	// MySQL::OrmConnT
	//	declaration
	//
	///////////////////////////
	
	
	namespace MySQL {
	
		class OrmConnT : public DB::OrmConnT {
		public:
			MYSQL *db;

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
			unsigned int _transaction_level;
			std::map< std::string, std::string >_options;
			std::map< std::string, int>_numoptions;
			bool successful(int rv);
		};

	}
	
	///////////////////////////
	//
	// MySQL::OrmConnT
	//	implementation
	//
	///////////////////////////
	
	MySQL::OrmConnT::OrmConnT()
		: db(NULL), _transaction_level(0)
	{
		_numoptions["timeout_ms"] = 15000; // 15 seconds
	}
	
	MySQL::OrmConnT::~OrmConnT()
	{
		close();
	}

	void MySQL::OrmConnT::set_option(const std::string &name,
									   const std::string &value)
	{
		_options[name] = value;
	}
	
	void MySQL::OrmConnT::set_option(const std::string &name,int value)
	{
		_numoptions[name] = value;
	}

	bool MySQL::OrmConnT::connect()
	{
		if (!(db = mysql_init(NULL))) {
			OrmLogError("Unable to initialize MYSQL struct");
			return false;
		}

		std::string host = _options["host"];
		std::string username = _options["username"];
		std::string password = _options["password"];
		int port = _numoptions["port"];
		std::string dbname = _options["dbname"];
		std::string encoding = _options["encoding"];
		int timeout = _numoptions["timeout_ms"] / 1000;
		my_bool reconnect = 1;

		if (timeout < 1) {
			OrmLogError("Timeout set to low, less then one second");
			return false;
		}

		if (!mysql_real_connect(db, host.c_str(), username.c_str(), password.c_str(), dbname.c_str(), port, NULL, 0)) {
			OrmLogError("Unable to connect to MySQL database: %s", mysql_error(db));
			return false;
		}
		
		if (mysql_autocommit(db, true)) {
			OrmLogError("Unable to set MySQL autocommit to true: %s", mysql_error(db));
			close();
			return false;
		}

		if (mysql_options(db, MYSQL_OPT_CONNECT_TIMEOUT, (char*)&timeout)) {
			OrmLogError("Unable to set MySQL connect timeout: %s", mysql_error(db));
			close();
			return false;
		}

		if (mysql_options(db, MYSQL_OPT_READ_TIMEOUT, (char*)&timeout)) {
			OrmLogError("Unable to set MySQL read timeout: %s", mysql_error(db));
			close();
			return false;
		}
		
		if (mysql_options(db, MYSQL_OPT_WRITE_TIMEOUT, (char*)&timeout)) {
			OrmLogError("Unable to set MySQL write timeout: %s", mysql_error(db));
			close();
			return false;
		}

		if (mysql_options(db, MYSQL_OPT_RECONNECT, (char*)&reconnect)) {
			OrmLogError("Unable to enable MySQL reconnect: %s", mysql_error(db));
			close();
			return false;
		}

		if (encoding == "UTF-8") {
			encoding = "utf8";
		}

		if (mysql_set_character_set(db, encoding.c_str())) {
			OrmLogError("Unable to set MySQL character set to %s: %s", encoding.c_str(), mysql_error(db));
			close();
			return false;
		}

		_options["encoding"] = encoding;

		return true;
	}
	
	void MySQL::OrmConnT::close()
	{
		if (db) {
			mysql_close(db);
			db = NULL;
		}
	}

	bool MySQL::OrmConnT::begin_transaction()
	{
		if (!_transaction_level) {
			if (mysql_autocommit(db, false)) {
				OrmLogError("Unable to set autocommit off");
				return false;
			}
		}

		_transaction_level++;

		return true;
	}

	bool MySQL::OrmConnT::begin_transaction_rw()
	{
		return begin_transaction();
	}
	
	bool MySQL::OrmConnT::in_transaction()
	{
		return (_transaction_level?true:false);
	}

	bool MySQL::OrmConnT::commit_transaction()
	{
		if (!_transaction_level) {
			OrmLogError("Not in transaction, can not commit");
			return false;
		}

		if (mysql_commit(db)) {
			OrmLogError("Unable to commit the transaction: %s", mysql_error(db));
			return false;
		}

		_transaction_level--;

		if (!_transaction_level) {
			if (mysql_autocommit(db, true)) {
				OrmLogError("Unable to set autocommit on");
				return false;
			}
		}

		return true;
	}

	bool MySQL::OrmConnT::rollback_transaction()
	{
		if (!_transaction_level) {
			OrmLogError("Not in transaction, can not rollback");
			return false;
		}

		if (mysql_rollback(db)) {
			OrmLogError("Unable to rollback the transaction: %s", mysql_error(db));
			return false;
		}

		_transaction_level = 0;

		if (mysql_autocommit(db, true)) {
			OrmLogError("Unable to set autocommit on");
			return false;
		}

		return true;
	}

	OrmResultT MySQL::OrmConnT::query(const char *statement, int len)
	{
		MYSQL_RES *result = NULL;

		if (mysql_real_query(db, statement, len)) {
			OrmLogError("Unable to execute statement: %s", mysql_error(db));
			OrmLogError("%*s", len, statement);
			return OrmResultT();
		}
		
		if (!(result = mysql_store_result(db))) {
			if (!mysql_field_count(db)) {
				return OrmResultT((OrmConn)this, new MySQL::OrmResultImpl(true));
			}

			OrmLogError("Unable to store result from statement: %s", mysql_error(db));
			OrmLogError("%*s", len, statement);
			return OrmResultT();
		}
	
		return OrmResultT((OrmConn)this, new MySQL::OrmResultImpl(result));
	}
		
	bool MySQL::OrmConnT::table_exists(const std::string &name)
	{
		OrmResultT exists = queryf("SHOW TABLES LIKE '%s'", name.c_str());

		if (exists.assigned())
			return exists->first_row();
		else
			return false;
	}
	
	bool MySQL::OrmConnT::quote_string(const std::string &value,
										 std::string &dest)
	{
		char quoted[4097], *quotedp;
		size_t len;

		if (value.length() > 2048) {
			quotedp = (char *)malloc((value.length() * 2) + 1);

			if (mysql_real_escape_string(db, quotedp, value.c_str(), value.length())) {
				dest = "'";
				dest += quotedp;
				dest += "'";
				free(quotedp);
				return true;
			}
			free(quotedp);
		}
		else {
			if (mysql_real_escape_string(db, quoted, value.c_str(), value.length())) {
				dest = "'";
				dest += quoted;
				dest += "'";
				return true;
			}
		}

		return false;
	}
	
	bool MySQL::OrmConnT::quote_binary(const std::string &value, std::string &dest)
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

	unsigned long long MySQL::OrmConnT::sequence_last()
	{
		return mysql_insert_id(db);
	}

	const char *MySQL::OrmConnT::idfield()
	{
		// To get maximum performance on SQLite the form below is choosen deliberately.
		// For example, we use INTEGER instead of INT or BIGINT and we don't use UNSIGNED.
		// Any one of those modifications would introduce a second id column alongside the 
		// ROWID column that is already there by default !
		// So if you think you need to modify the primary key id below please 
		// be aware of and investigate potential consequences.
		return "id INTEGER PRIMARY KEY AUTO_INCREMENT";
	}

	OrmResultT MySQL::OrmConnT::CreateTableMessage(const std::string &name,
												  const std::string &fields)
	{
		std::string allfields(fields);
		OrmChain(allfields,idfield(),',');
		return queryf("CREATE TABLE %s (%s) ENGINE=InnoDB CHARACTER SET '%s'",
					  name.c_str(),
					  allfields.c_str(),
					  _options["encoding"].c_str());
	}

	OrmResultT MySQL::OrmConnT::CreateTableRelation(const std::string &name)
	{
		return queryf("CREATE TABLE %s (parent_id INTEGER,child_id INTEGER,"
					  "PRIMARY KEY(parent_id,child_id)) ENGINE=InnoDB CHARACTER SET '%s'",
					  name.c_str(),
					  _options["encoding"].c_str());
	}

	OrmResultT MySQL::OrmConnT::CreateTableRepeatedValue(const std::string &name,
															 const std::string &type)
	{
		return queryf("CREATE TABLE %s (value %s,parent_id INTEGER,%s) ENGINE=InnoDB CHARACTER SET '%s'",
					  name.c_str(),
					  type.c_str(),
					  idfield(),
					  _options["encoding"].c_str());
	}

	///////////////////////////
	//
	// MySQL::NewOrmConnT
	//	definition
	//
	///////////////////////////

	OrmConnT * MySQL::NewOrmConnT()
	{
		return new MySQL::OrmConnT();
	}


} // namespace DB

#endif // ENFORCER_DATABASE_MYSQL
