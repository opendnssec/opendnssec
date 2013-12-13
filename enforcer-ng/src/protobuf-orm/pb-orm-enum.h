/*
 * Created by René Post on 11/3/11.
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
//  pb-orm-enum.h
//  protobuf-orm
//

#ifndef pb_orm_enum_h
#define pb_orm_enum_h

#include "pb-orm-common.h"
#include <cstdarg>

bool OrmConnQuery(OrmConn conn,
				  const std::string &statement,
				  OrmResult &result);

bool OrmMessageFind(OrmConn conn,
					const pb::Descriptor *descriptor,
					pb::uint64 id);

bool OrmMessageSelect(OrmConn conn,
					  const pb::Descriptor *descriptor,
					  pb::uint64 id,
					  OrmResult &result);

bool OrmMessageEnum(OrmConn conn,
					const pb::Descriptor *descriptor,
					OrmResult &result);

bool OrmMessageEnumWhere(OrmConn conn,
						 const pb::Descriptor *descriptor,
						 OrmResult &result,
						 const char *format,
						 va_list ap);

bool OrmMessageEnumWhere(OrmConn conn,
						 const pb::Descriptor *descriptor,
						 OrmResult &result,
						 const char *format,
						 ...);

bool OrmMessageCount(OrmConn conn,
					 const pb::Descriptor *descriptor,
					 pb::uint64 &count);

bool OrmMessageCountWhere(OrmConn conn,
						  const pb::Descriptor *descriptor,
						  pb::uint64 &count,
						  const char *format,
						  va_list ap);

bool OrmMessageCountWhere(OrmConn conn,
						  const pb::Descriptor *descriptor,
						  pb::uint64 &count,
						  const char *format,
						  ...);

bool OrmFieldSelectMessage(OrmConn conn,
						   pb::uint64 id,
						   const pb::FieldDescriptor* field,
						   OrmResult &result);

bool OrmFieldEnumAllRepeatedValues(OrmConn conn,
								   pb::uint64 id,
								   const pb::FieldDescriptor* field,
								   OrmResult &result);

// Gettting the size (number of rows) in a result may be very expensive.
// Worst case a loop may be executed visiting all records in the result.
bool OrmGetSize(OrmResult result, pb::uint64 &size);

bool OrmFirst(OrmResult result);
bool OrmNext(OrmResult result);

void OrmFreeResult(OrmResult result);

class OrmResultRef {
public:
	OrmResultRef() : _res(NULL) {
	}
	~OrmResultRef() {
		release();
	}
	operator OrmResult*() {
		return &_res;
	}
	operator OrmResult&() {
		return _res;
	}
	void release() {
		if (_res) {
			OrmFreeResult(_res);
			_res = NULL;
		}
	}
protected:
	OrmResult _res;
private:
	// disable evil contructors
	OrmResultRef(const OrmResultRef&);
	void operator=(const OrmResultRef&);
};

#endif
