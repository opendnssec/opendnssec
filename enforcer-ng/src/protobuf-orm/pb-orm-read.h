/*
 * Created by René Post on 10/24/11.
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
//  pb-orm-read.h
//  protobuf-orm
//

#ifndef pb_orm_read_h
#define pb_orm_read_h

#include "pb-orm-common.h"


// Read a message for reading only. 
bool OrmMessageRead(OrmConn conn,
					pb::Message &value,
					pb::uint64 id,
					bool recurse);


// Read a message that can be updated later.
// Create the context required for updating the message in the database
// later using OrmMessageUpdate.
bool OrmMessageRead(OrmConn conn,
					pb::Message &value,
					pb::uint64 id,
					bool recurse,
					OrmContext &context);

void OrmFreeContext(OrmContext context);

// Read a required or optional message's id
bool OrmFieldGetMessageId(OrmConn conn,
						  pb::uint64 id,
						  const pb::FieldDescriptor* field,
						  pb::uint64 &fieldid);

bool OrmGetId(OrmResult result, pb::uint64 &id);
bool OrmGetBool(OrmResult result, bool &value);
bool OrmGetFloat(OrmResult result, float &value);
bool OrmGetDouble(OrmResult result, double &value);
bool OrmGetInt32(OrmResult result, pb::int32 &value);
bool OrmGetInt64(OrmResult result, pb::int64 &value);
bool OrmGetUint32(OrmResult result, pb::uint32 &value);
bool OrmGetUint64(OrmResult result, pb::uint64 &value);
bool OrmGetString(OrmResult result, std::string &value);
bool OrmGetBinary(OrmResult result, std::string &value);
bool OrmGetMessage(OrmResult result, pb::Message &value, bool recurse);
bool OrmGetMessage(OrmResult result,
				   pb::Message &value,
				   bool recurse,
				   OrmContext &context);
bool OrmGetEnum(OrmResult result, std::string &value);
bool OrmGetDateTime(OrmResult result, time_t &value);
bool OrmGetDate(OrmResult result, time_t &value);
bool OrmGetTime(OrmResult result, time_t &value);

class OrmContextRef {
public:
	OrmContextRef() : _ctx(NULL) {
	}
	~OrmContextRef() {
		release();
	}
	operator OrmContext*() {
		return &_ctx;
	}
	operator OrmContext&() {
		return _ctx;
	}
	void release() {
		if (_ctx) {
			OrmFreeContext(_ctx);
			_ctx = NULL;
		}
	}
protected:
	OrmContext _ctx;
private:
	// disable evil contructors
	OrmContextRef(const OrmContextRef&);
	void operator=(const OrmContextRef&);
};

#endif
