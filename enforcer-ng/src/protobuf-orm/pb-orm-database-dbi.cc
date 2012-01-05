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
//  pb-orm-database-dbi.cc
//  protobuf-orm
//

#include "pb-orm-database-dbi.h"

#ifdef USE_CLIENT_LIB_DBI

#include "pb-orm-str.h"
#include "pb-orm-log.h"

#include <dbi/dbi.h>

namespace DB {
	
	
	bool DBI::initialize(const std::string &driverdir)
	{
		printf("%s\n",dbi_version());

		// return number of drivers loaded
		return dbi_initialize(driverdir.c_str()) > 0; 
	}

	void DBI::shutdown()
	{
		dbi_shutdown();
	}

	namespace DBI {
		
		///////////////////////////
		//
		// DBI::OrmResultImpl
		//	declaration
		//
		///////////////////////////

		class OrmResultImpl : public ::DB::OrmResultImpl {
		public:
			dbi_result result;
			
			OrmResultImpl(dbi_result result_);
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
		};
	
	}
	
	///////////////////////////
	//
	// DBI::OrmResultImpl
	//	implementation
	//
	///////////////////////////

	DBI::OrmResultImpl::OrmResultImpl(dbi_result result_)
	: result(result_)
	{
	}
	
	DBI::OrmResultImpl::~OrmResultImpl()
	{
		if (result) {
			dbi_result_free(result);
			result = 0;
		}
	}
	
	bool DBI::OrmResultImpl::assigned()
	{
		return result != NULL;
	}
	
	bool DBI::OrmResultImpl::failed()
	{
		dbi_conn conn = dbi_result_get_conn(result);
		return dbi_conn_error(conn, NULL) != DBI_ERROR_NONE;
	}
	
	bool DBI::OrmResultImpl::get_numrows(unsigned long long &numrows)
	{
		if (!result) return false;
		numrows = dbi_result_get_numrows(result);
		return numrows != DBI_ROW_ERROR;
	}
	
	bool DBI::OrmResultImpl::first_row()
	{
		if (!result) return false;
		// test for available row in the result because enumerating the first
		// item in an empty result will report an error via the callback.
		if (dbi_result_has_next_row(result)==0)
			return false;
		return dbi_result_first_row(result)!=0;
	}
	
	bool DBI::OrmResultImpl::next_row()
	{
		if (!result) return false;
		return dbi_result_next_row(result)!=0;
	}
	
	unsigned int DBI::OrmResultImpl::get_field_idx(const std::string &fieldname)
	{
		unsigned int fieldidx = dbi_result_get_field_idx(result, fieldname.c_str());
		if (fieldidx == 0)
			OrmLogError("invalid field name \"%s\"",fieldname.c_str());
		return fieldidx;
	}
	
	bool DBI::OrmResultImpl::field_is_null_idx(unsigned int fieldidx)
	{
		if (fieldidx == 0) {
			OrmLogError("zero is an invalid field index");
			return true;
		}
		
		/* BROKEN in SQLITE3 driver dbd_sqlite3.c revision 1.20  was fixed in 
		 * CVS over 2 years ago in dbd_sqlite3.c revision 1.37 but nobody 
		 * bothers to release updated libdbi and libdbi-drivers packages.
		 * 
		 * To use SQLITE3 you need to patch the dbd_sqlite3.c driver.
		 */
		
		int is_null = dbi_result_field_is_null_idx(result, fieldidx);
		if (is_null!=0 && is_null!=1) {
			if (is_null == DBI_FIELD_FLAG_ERROR)
				OrmLogError("DBI_FIELD_FLAG_ERROR: cannot determine whether field is NULL");
			else
				OrmLogError("Internal error, cannot determine whether field is NULL");
			return false;
		}
		return is_null != 0;
	}
	
	time_t DBI::OrmResultImpl::get_datetime_idx(unsigned int fieldidx)
	{
		return dbi_result_get_datetime_idx(result, fieldidx);
	}
	
	unsigned char DBI::OrmResultImpl::get_uchar_idx(unsigned int fieldidx)
	{
		return dbi_result_get_uchar_idx(result, fieldidx);
	}
	
	float DBI::OrmResultImpl::get_float_idx(unsigned int fieldidx)
	{
		return dbi_result_get_float_idx(result, fieldidx);
	}
	
	double DBI::OrmResultImpl::get_double_idx(unsigned int fieldidx)
	{
		return dbi_result_get_double_idx(result, fieldidx);
	}
	
	int DBI::OrmResultImpl::get_int_idx(unsigned int fieldidx)
	{
		return dbi_result_get_int_idx(result, fieldidx);
	}
	
	long long DBI::OrmResultImpl::get_longlong_idx(unsigned int fieldidx)
	{
		return dbi_result_get_longlong_idx(result, fieldidx);
	}
	
	unsigned long long DBI::OrmResultImpl::get_ulonglong_idx(unsigned int fieldidx)
	{
		return dbi_result_get_ulonglong_idx(result, fieldidx);
	}
	
	unsigned int DBI::OrmResultImpl::get_uint_idx(unsigned int fieldidx)
	{
		return dbi_result_get_uint_idx(result, fieldidx);
	}
	
	const char *DBI::OrmResultImpl::get_string_idx(unsigned int fieldidx)
	{
		return dbi_result_get_string_idx(result, fieldidx);
	}
	
	const unsigned char *DBI::OrmResultImpl::get_binary_idx(unsigned int fieldidx)
	{
		return dbi_result_get_binary_idx(result, fieldidx);
	}
	
	size_t DBI::OrmResultImpl::get_field_length_idx(unsigned int fieldidx)
	{
		return dbi_result_get_field_length_idx(result, fieldidx);
	}
	
	bool DBI::OrmResultImpl::field_is_null(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return true;
		return field_is_null_idx( fieldidx );
	}
	
	time_t DBI::OrmResultImpl::get_datetime(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return dbi_result_get_datetime_idx(result, fieldidx);
	}
	
	unsigned char DBI::OrmResultImpl::get_uchar(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return dbi_result_get_uchar_idx(result, fieldidx);
	}
	
	float DBI::OrmResultImpl::get_float(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0.0f;
		return dbi_result_get_float_idx(result, fieldidx);
	}
	
	double DBI::OrmResultImpl::get_double(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0.0;
		return dbi_result_get_double_idx(result, fieldidx);
	}
	
	int DBI::OrmResultImpl::get_int(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return dbi_result_get_int_idx(result, fieldidx);
	}
	
	long long DBI::OrmResultImpl::get_longlong(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return dbi_result_get_longlong_idx(result, fieldidx);
	}
	
	unsigned long long DBI::OrmResultImpl::get_ulonglong(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return dbi_result_get_ulonglong_idx(result, fieldidx);
	}
	
	unsigned int DBI::OrmResultImpl::get_uint(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return dbi_result_get_uint_idx(result, fieldidx);
	}
	
	const char *DBI::OrmResultImpl::get_string(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return NULL;
		return dbi_result_get_string_idx(result, fieldidx);
	}
	
	const unsigned char *DBI::OrmResultImpl::get_binary(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return NULL;
		return dbi_result_get_binary_idx(result, fieldidx);
	}
	
	size_t DBI::OrmResultImpl::get_field_length(const std::string &fieldname)
	{
		unsigned int fieldidx = get_field_idx(fieldname);
		if (fieldidx == 0)
			return 0;
		return dbi_result_get_field_length_idx(result, fieldidx);
	}
	
	namespace DBI {

		///////////////////////////
		//
		// DBI::OrmConnT
		//	declaration
		//
		///////////////////////////
		
		class OrmConnT : public DB::OrmConnT {
		protected:
			bool _in_transaction;
		public:
			dbi_conn conn;
			
			OrmConnT(const char *driver);
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
		
		};

	}

	///////////////////////////
	//
	// DBI::OrmConnT
	//	implementation
	//
	///////////////////////////

	static void dbi_conn_error_handler_cb(dbi_conn conn, void *user_argument)
	{
		int err = dbi_conn_error(conn, NULL);
		if (err == DBI_ERROR_NONE) {
			OrmLogError("expected database error in database error handler callback.");
			return;
		}
#if USE_DB_SQLITE3
		// sqlite driver will freak out and corrupt memory when using 
		// multiple threads with dbi_conn_error that returns an error message.
		OrmLogError("dbi_conn_error %d",err);
#else
		const char *errmsg;
		if (dbi_conn_error(conn, &errmsg)!=DBI_ERROR_NONE)
			OrmLogError(errmsg);
#endif
	}
	
	DBI::OrmConnT::OrmConnT(const char *driver) : _in_transaction(false)
	{
		conn = dbi_conn_new(driver);
		dbi_conn_error_handler(conn, dbi_conn_error_handler_cb, NULL);
	}
	
	DBI::OrmConnT::~OrmConnT()
	{
		close();
	}

	void DBI::OrmConnT::set_option(const std::string &name,const std::string &value)
	{
		dbi_conn_set_option(conn, name.c_str(), value.c_str());
	}

	void DBI::OrmConnT::set_option(const std::string &name,int value)
	{
		dbi_conn_set_option_numeric(conn, name.c_str(), value);
	}
	
	bool DBI::OrmConnT::connect()
	{
		if (!conn) {
			OrmLogError("connection was not created");
			return false;
		}
		if (dbi_conn_connect(conn) >= 0)
			return true;
		const char *errmsg;
		if (dbi_conn_error(conn, &errmsg)!=DBI_ERROR_NONE)
			OrmLogError(errmsg);
		else
			OrmLogError("expected error, but got DBI_ERROR_NONE");
		return false;
	}
	
	void DBI::OrmConnT::close()
	{
		if (conn) {
			dbi_conn_error_handler(conn, NULL, NULL);
			dbi_conn_close(conn);
			conn = NULL;
		}
	}
	
	bool DBI::OrmConnT::begin_transaction()
	{
		dbi_result result = dbi_conn_query(conn,"BEGIN");
		if (!result)
			return false;
		_in_transaction = true;
		dbi_result_free(result);
		return true;
	}

	bool DBI::OrmConnT::begin_transaction_rw()
	{
		dbi_result result = dbi_conn_query(conn,"BEGIN");
		if (!result)
			return false;
		_in_transaction = true;
		dbi_result_free(result);
		return true;
	}
	
	bool DBI::OrmConnT::in_transaction()
	{
		return _in_transaction;
	}
	
	bool DBI::OrmConnT::commit_transaction()
	{
		dbi_result result = dbi_conn_query(conn,"COMMIT");
		if (!result)
			return false;
		_in_transaction = false;
		dbi_result_free(result);
		return true;
	}
	
	bool DBI::OrmConnT::rollback_transaction()
	{
		_in_transaction = false;
		dbi_result result = dbi_conn_query(conn,"ROLLBACK");
		if (!result)
			return false;
		dbi_result_free(result);
		return true;
	}
	
	OrmResultT DBI::OrmConnT::query(const char *statement, int len)
	{
		dbi_result result = dbi_conn_query(conn, statement);
		return OrmResultT( (OrmConn)this, new DBI::OrmResultImpl( result ));
	}
	
	bool DBI::OrmConnT::table_exists(const std::string &name)
	{
		// Skip table creation when it exists.
		const char *db = dbi_conn_get_option(conn, "dbname");
		dbi_result result = dbi_conn_get_table_list(conn, db, name.c_str());
					
		OrmResultT r( (OrmConn)this, new DBI::OrmResultImpl( result ));
		
		if (r.assigned()) {
			unsigned long long numrows;
			bool tableExists = r->get_numrows(numrows) && numrows==1;
			return tableExists;
			//TODO:  enhance this with automatic table altering when message type has changed.
		}
		return false;
	}
	
	bool DBI::OrmConnT::quote_string(const std::string &value, std::string &dest)
	{
		char *strcopy;
		size_t strsize = dbi_conn_quote_string_copy(conn,value.c_str(),&strcopy);
		if (!strsize)
			return false;
		dest.assign(strcopy,strsize);
		free(strcopy);
		return true;
	}
	
	bool DBI::OrmConnT::quote_binary(const std::string &value, std::string &dest)
	{
		unsigned char *bincopy;
		size_t binsize = dbi_conn_quote_binary_copy(conn,
													(const unsigned char*)value.data(),
													value.size(),
													&bincopy);
		if (!binsize)
			return false;
		dest.assign((const char *)bincopy,binsize);
		free(bincopy);
		return true;
	}

	unsigned long long DBI::OrmConnT::sequence_last()
	{
		return dbi_conn_sequence_last(conn, NULL);
		
	}
	
	namespace DBI {
		
		namespace MySQL {
		
			///////////////////////////
			//
			// DBI::MySQL::OrmConnT
			//	declaration
			//
			///////////////////////////
			
			class OrmConnT : public ::DB::DBI::OrmConnT {
			public:
				OrmConnT();
				
				const char *idfield();
				virtual OrmResultT CreateTableMessage(const std::string &name,
														const std::string &fields);
				virtual OrmResultT CreateTableRelation(const std::string &name);
				virtual OrmResultT CreateTableRepeatedValue(const std::string &name,
															  const std::string &type);
			};

		}
	}

	///////////////////////////
	//
	// DBI::MySQL::OrmConnT
	//	implementation
	//
	///////////////////////////
	
	DBI::MySQL::OrmConnT::OrmConnT() : DBI::OrmConnT("mysql")
	{
	}

	const char *DBI::MySQL::OrmConnT::idfield()
	{
		return "id INTEGER AUTO_INCREMENT NOT NULL PRIMARY KEY";
	}

	OrmResultT DBI::MySQL::OrmConnT::CreateTableMessage(const std::string &name,
														  const std::string &fields)
	{
		std::string allfields(fields);
		OrmChain(allfields, idfield(), ',');
		return queryf("CREATE TABLE %s (%s)",
					  name.c_str(),
					  allfields.c_str());
	}

	OrmResultT DBI::MySQL::OrmConnT::CreateTableRelation(const std::string &name)
	{
		return queryf("CREATE TABLE %s (parent_id INTEGER,child_id INTEGER,PRIMARY KEY(parent_id,child_id))",
					  name.c_str());
		
	}

	OrmResultT DBI::MySQL::OrmConnT::CreateTableRepeatedValue(const std::string &name,
																const std::string &type)
	{
		return queryf("CREATE TABLE %s (value %s,parent_id INTEGER,%s)",
					  name.c_str(),
					  type.c_str(),
					  idfield());
	}
	
	namespace DBI {
		
		namespace SQLite3 {
			
			///////////////////////////
			//
			// DBI::MySQL::OrmConnT
			//	declaration
			//
			///////////////////////////
			
			class OrmConnT : public ::DB::DBI::OrmConnT {
			public:
				OrmConnT();

				virtual bool begin_transaction_rw();
				
				const char *idfield();
				virtual OrmResultT CreateTableMessage(const std::string &name,
														const std::string &fields);
				virtual OrmResultT CreateTableRelation(const std::string &name);
				virtual OrmResultT CreateTableRepeatedValue(const std::string &name,
															  const std::string &type);
			};
			
		}
	}

	///////////////////////////
	//
	// DBI::SQLite3::OrmConnT
	//	implementation
	//
	///////////////////////////
	
	DBI::SQLite3::OrmConnT::OrmConnT() : DBI::OrmConnT("sqlite3")
	{
	}

	bool DBI::SQLite3::OrmConnT::begin_transaction_rw()
	{
		dbi_result result = dbi_conn_query(conn,"BEGIN IMMEDIATE");
		if (!result)
			return false;
		_in_transaction = true;
		dbi_result_free(result);
		return true;
	}
	
	const char *DBI::SQLite3::OrmConnT::idfield()
	{
		// To get maximum performance on SQLite the form below is choosen deliberately.
		// For example, we use INTEGER instead of INT or BIGINT and we don't use UNSIGNED.
		// Any one of those modifications would introduce a second id column alongside the 
		// ROWID column that is already there by default !
		// So if you think you need to modify the primary key id below please 
		// be aware of and investigate potential consequences.
		return "id INTEGER PRIMARY KEY AUTOINCREMENT";
	}
	
	OrmResultT DBI::SQLite3::OrmConnT::CreateTableMessage(const std::string &name,
															const std::string &fields)
	{
		std::string allfields(fields);
		OrmChain(allfields,idfield(),',');
		return queryf("CREATE TABLE %s (%s)",
					  name.c_str(),
					  allfields.c_str());
	}
	
	OrmResultT DBI::SQLite3::OrmConnT::CreateTableRelation(const std::string &name)
	{
		return queryf("CREATE TABLE %s (parent_id INTEGER,child_id INTEGER,PRIMARY KEY(parent_id,child_id))",
					  name.c_str());
	}
	
	OrmResultT DBI::SQLite3::OrmConnT::CreateTableRepeatedValue(const std::string &name,
																  const std::string &type)
	{
		return queryf("CREATE TABLE %s (value %s,parent_id INTEGER,%s)",
					  name.c_str(),
					  type.c_str(),
					  idfield());
	}

	///////////////////////////
	//
	// DBI::MySQL::NewOrmConnT
	//	definition
	//
	///////////////////////////

	OrmConnT * DBI::MySQL::NewOrmConnT()
	{
		return new DBI::MySQL::OrmConnT();
		
	}
		
	///////////////////////////
	//
	// DBI::SQLite3::NewOrmConnT
	//	definition
	//
	///////////////////////////
	
	OrmConnT * DBI::SQLite3::NewOrmConnT()
	{
		return new DBI::SQLite3::OrmConnT();
	}

} // namespace DB

#endif // USE_CLIENT_LIB_DBI
