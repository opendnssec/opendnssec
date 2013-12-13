/*
 * Created by René Post on 12/6/11.
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
//  pb-orm-database.h
//  protobuf-orm
//

#ifndef pb_orm_database_h
#define pb_orm_database_h

#include "pb-orm-common.h"

namespace DB {

	class OrmResultImpl {
	public:
		OrmResultImpl();
		virtual ~OrmResultImpl();
		
		virtual bool assigned() = 0;
		
		// The failed() member funciton  calls into the underlying database 
		// engine to retrieve the last error code. This may be slow. So only
		// call it to determine whether one of the getters (get_xxxx) declared
		// below has failed. Normally you should rely on OrmResultT::assigned()
		// to determine whether a db call succeeded or not.
		virtual bool failed() = 0;
		
		virtual bool get_numrows(unsigned long long &numrows) = 0;
		
		virtual bool first_row() = 0;
		virtual bool next_row() = 0;
		
		virtual unsigned int get_field_idx(const std::string &fieldname) = 0;
		virtual bool field_is_null_idx(unsigned int fieldidx) = 0;
		virtual time_t get_datetime_idx(unsigned int fieldidx) = 0;
		virtual unsigned char get_uchar_idx(unsigned int fieldidx) = 0;
		virtual float get_float_idx(unsigned int fieldidx) = 0;
		virtual double get_double_idx(unsigned int fieldidx) = 0;
		virtual int get_int_idx(unsigned int fieldidx) = 0;
		virtual long long get_longlong_idx(unsigned int fieldidx) = 0;
		virtual unsigned long long get_ulonglong_idx(unsigned int fieldidx) = 0;
		virtual unsigned int get_uint_idx(unsigned int fieldidx) = 0;
		virtual const char *get_string_idx(unsigned int fieldidx) = 0;
		virtual const unsigned char *get_binary_idx(unsigned int fieldidx) = 0;
		virtual size_t get_field_length_idx(unsigned int fieldidx) = 0;
		
		virtual bool field_is_null(const std::string &fieldname) = 0;
		virtual time_t get_datetime(const std::string &fieldname) = 0;
		virtual unsigned char get_uchar(const std::string &fieldname) = 0;
		virtual float get_float(const std::string &fieldname) = 0;
		virtual double get_double(const std::string &fieldname) = 0;
		virtual int get_int(const std::string &fieldname) = 0;
		virtual long long get_longlong(const std::string &fieldname) = 0;
		virtual unsigned long long get_ulonglong(const std::string &fieldname) = 0;
		virtual unsigned int get_uint(const std::string &fieldname) = 0;
		virtual const char *get_string(const std::string &fieldname) = 0;
		virtual const unsigned char *get_binary(const std::string &fieldname) = 0;
		virtual size_t get_field_length(const std::string &fieldname) = 0;

	private:
		// disable evil constructors
		OrmResultImpl(const OrmResultImpl&);
		void operator=(const OrmResultImpl&);

	private:
		int _refcount;
	public:
		static OrmResultImpl *retain(OrmResultImpl* self);
		static void release(OrmResultImpl* &self);
	};

	class OrmResultT {
	public:
		OrmConn conn;

		OrmResultT();
		OrmResultT(OrmConn conn_, OrmResultImpl *impl_);
		OrmResultT(const OrmResultT &value);
		void operator=(const OrmResultT&);
		~OrmResultT();
		
		bool new_handle(OrmResult &handle) const;
		bool assigned() const;

		OrmResultImpl* operator ->();
		
	protected:
		OrmResultImpl *_impl;
	};

	class OrmConnT {
	public:
		OrmConnT();
		virtual ~OrmConnT();
		OrmConn handle() const;
		
		virtual void set_option(const std::string &name,const std::string &value) = 0;
		virtual void set_option(const std::string &name,int value) = 0;
		
		virtual bool connect() = 0;
		virtual void close() = 0;
		
		virtual bool begin_transaction() = 0;
		virtual bool begin_transaction_rw() = 0;
		virtual bool in_transaction() = 0;
		virtual bool commit_transaction() = 0;
		virtual bool rollback_transaction() = 0;
		
		virtual OrmResultT query(const char *statement, int len) = 0;
		OrmResultT queryf(const char *format, ...);
		
		virtual bool table_exists(const std::string &name) = 0;
		virtual bool quote_string(const std::string &value, std::string &dest) = 0;
		virtual bool quote_binary(const std::string &value, std::string &dest) = 0;

		virtual unsigned long long sequence_last() = 0;

		virtual OrmResultT CreateTableMessage(const std::string &name,
											  const std::string &fields) = 0;
		virtual OrmResultT CreateTableRelation(const std::string &name) = 0;
		virtual OrmResultT CreateTableRepeatedValue(const std::string &name,
													const std::string &type) = 0;
	private:
		// disable evil constructors
		OrmConnT(const OrmConnT&);
		void operator=(const OrmConnT&);
	};
		
} // namespace DB

#define RESULT (*(DB::OrmResultT*)result)
#define CONN ((DB::OrmConnT*)conn)

#endif
