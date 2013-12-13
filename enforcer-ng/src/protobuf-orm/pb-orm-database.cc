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
//  pb-orm-database.cc
//  protobuf-orm
//

#include "pb-orm-database.h"
#include "pb-orm-log.h"
#include "pb-orm-str.h"

#include <stdio.h> 
#include <stdarg.h>

namespace DB {

	///////////////////////////
	//
	// OrmResultImpl
	//
	///////////////////////////
	
	OrmResultImpl::OrmResultImpl() : _refcount(1)
	{
	}
	
	OrmResultImpl::~OrmResultImpl()
	{
		
	}

	OrmResultImpl *OrmResultImpl::retain(OrmResultImpl* self)
	{
		if (self)
			self->_refcount++;
		return self;
	}
	
	void OrmResultImpl::release(OrmResultImpl* &self)
	{
		if (self && --self->_refcount == 0) {
			delete self;
			self = NULL;
		}
	}
	
	///////////////////////////
	//
	// OrmResultT
	//
	///////////////////////////

	OrmResultT::OrmResultT() :conn(0), _impl(NULL)
	{
	}

	OrmResultT::OrmResultT(OrmConn conn_, OrmResultImpl *impl_)
	: conn(conn_), _impl(impl_)
	{
	}
	
	OrmResultT::OrmResultT(const OrmResultT &value)
	: conn(value.conn), _impl(OrmResultImpl::retain(value._impl))
	{
	}

	void OrmResultT::operator=(const OrmResultT&value)
	{
		conn = value.conn;
		OrmResultImpl::retain(value._impl);
		OrmResultImpl::release(_impl);
		_impl = value._impl;
	}
	
	OrmResultT::~OrmResultT()
	{
		OrmResultImpl::release(_impl);
	}
		
	OrmResultImpl* OrmResultT::operator ->()
	{
		return _impl;
	}
	
	bool OrmResultT::new_handle(OrmResult &handle) const
	{
		OrmResultT *obj = new OrmResultT(*this);
		if (!obj) {
			OrmLogError("unable to allocated OrmResult, out of memory");
			return false;
		}
		handle = (OrmResult)obj;
		return true;
	}
	
	bool OrmResultT::assigned() const 
	{
		return _impl && _impl->assigned();
	}

	///////////////////////////
	//
	// OrmConnT
	//
	///////////////////////////
		
	OrmConnT::OrmConnT()
	{
	}

	OrmConnT::~OrmConnT()
	{
	}

	OrmConn OrmConnT::handle() const
	{
		return (OrmConn)this;
	}
	
	OrmResultT OrmConnT::queryf(const char *format, ...)
	{
		// short form
		char statement[128];
		va_list args;
		va_start(args, format);
		int cneeded = vsnprintf(statement,sizeof(statement),format,args);
		va_end(args);
		if (cneeded<sizeof(statement))
			return query(statement,cneeded);
		
		// long form
		OrmResultT result;
		char *pstatement = new char[cneeded+1];
		if (!pstatement) {
			OrmLogError("out of memory");
			return result;
		}
		va_start(args, format);
		bool ok = vsnprintf(pstatement,cneeded+1,format,args)==cneeded;
		va_end(args);
		if (ok)
			result = query(pstatement,cneeded);
		else
			OrmLogError("vsnprintf error");
		delete[] pstatement;
		return result;
	}

} // namespace DB
