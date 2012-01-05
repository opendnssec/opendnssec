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
//  pb-orm-create.h
//  protobuf-orm
//

#ifndef pb_orm_create_h
#define pb_orm_create_h

#include "pb-orm-common.h"

bool OrmMessageInsert(OrmConn conn,
					  const pb::Message &message,
					  pb::uint64 &id);

bool OrmFieldAddRepeatedValue(OrmConn conn,
							  pb::uint64 id,
							  const pb::Message &message,
							  const pb::FieldDescriptor *field,
							  int index,
							  pb::uint64 &fieldid);

bool OrmFieldAddRepeatedBool(OrmConn conn,
							 pb::uint64 id,
							 const pb::FieldDescriptor *field,
							 bool value,
							 pb::uint64 &fieldid);

bool OrmFieldAddRepeatedFloat(OrmConn conn,
							  pb::uint64 id,
							  const pb::FieldDescriptor *field,
							  float value,
							  pb::uint64 &fieldid);

bool OrmFieldAddRepeatedDouble(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							   double value,
							   pb::uint64 &fieldid);

bool OrmFieldAddRepeatedInt32(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							  pb::int32 value,
							   pb::uint64 &fieldid);

bool OrmFieldAddRepeatedInt64(OrmConn conn,
							  pb::uint64 id,
							  const pb::FieldDescriptor *field,
							  pb::int64 value,
							  pb::uint64 &fieldid);

bool OrmFieldAddRepeatedUint32(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							   pb::uint32 value,
							   pb::uint64 &fieldid);

bool OrmFieldAddRepeatedUint64(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							   pb::uint64 value,
							   pb::uint64 &fieldid);

bool OrmFieldAddRepeatedString(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							   const std::string &value,
							   pb::uint64 &fieldid);

bool OrmFieldAddRepeatedBinary(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							   const std::string &value,
							   pb::uint64 &fieldid);

bool OrmFieldAddRepeatedMessage(OrmConn conn,
								pb::uint64 id,
								const pb::FieldDescriptor *field,
								const pb::Message &value,
								pb::uint64 &fieldid);

bool OrmFieldAddRepeatedEnum(OrmConn conn,
							 pb::uint64 id,
							 const pb::FieldDescriptor *field,
							 const std::string &value,
							 pb::uint64 &fieldid);

bool OrmFieldAddRepeatedDateTime(OrmConn conn,
								 pb::uint64 id,
								 const pb::FieldDescriptor *field,
								 time_t value,
								 pb::uint64 &fieldid);

bool OrmFieldAddRepeatedDate(OrmConn conn,
							 pb::uint64 id,
							 const pb::FieldDescriptor *field,
							 time_t value,
							 pb::uint64 &fieldid);

bool OrmFieldAddRepeatedTime(OrmConn conn,
							 pb::uint64 id,
							 const pb::FieldDescriptor *field,
							 time_t value,
							 pb::uint64 &fieldid);

#endif
