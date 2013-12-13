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
//  pb-orm-update.h
//  protobuf-orm
//

#ifndef pb_orm_update_h
#define pb_orm_update_h

#include "pb-orm-common.h"

// Update a message in a table.
// Note that you are only allowed to update a message using a context retrieved
// from the database by OrmMessageRead. Also you are only allowed to call the 
// OrmMessageUpdate function once. The reason for this is that updating a message
// may introduce differences between the message in memory and the message in 
// the db. So you first need to use OrmMessageRead again to refresh the message
// from the db before calling OrmMessageUpdate again.
bool OrmMessageUpdate(OrmContext context);

// NOTE: does not handle repeated message values.
bool OrmFieldSetRepeatedValue(OrmConn conn,
							  pb::uint64 id,
							  const pb::Message &message,
							  const pb::FieldDescriptor *field,
							  int index,
							  pb::uint64 fieldid);

bool OrmFieldSetRepeatedBool(OrmConn conn,
							const pb::FieldDescriptor *field,
							bool value,
							pb::uint64 fieldid);

bool OrmFieldSetRepeatedFloat(OrmConn conn,
							  const pb::FieldDescriptor *field,
							  float value,
							  pb::uint64 fieldid);

bool OrmFieldSetRepeatedDouble(OrmConn conn,
							   const pb::FieldDescriptor *field,
							   double value,
							   pb::uint64 fieldid);

bool OrmFieldSetRepeatedInt32(OrmConn conn,
							  const pb::FieldDescriptor *field,
							  pb::int32 value,
							  pb::uint64 fieldid);

bool OrmFieldSetRepeatedInt64(OrmConn conn,
							  const pb::FieldDescriptor *field,
							  pb::int64 value,
							  pb::uint64 fieldid);

bool OrmFieldSetRepeatedUint32(OrmConn conn,
							   const pb::FieldDescriptor *field,
							   pb::uint32 value,
							   pb::uint64 fieldid);

bool OrmFieldSetRepeatedUint64(OrmConn conn,
							  const pb::FieldDescriptor *field,
							  pb::uint64 value,
							  pb::uint64 fieldid);

bool OrmFieldSetRepeatedString(OrmConn conn,
							   const pb::FieldDescriptor *field,
							   const std::string &value,
							   pb::uint64 fieldid);

bool OrmFieldSetRepeatedBinary(OrmConn conn,
							   const pb::FieldDescriptor *field,
							   const std::string &value,
							   pb::uint64 fieldid);

bool OrmFieldSetRepeatedMessage(OrmContext context,
								const pb::FieldDescriptor *field);

bool OrmFieldSetRepeatedEnum(OrmConn conn,
							const pb::FieldDescriptor *field,
							const std::string &value,
							pb::uint64 fieldid);

bool OrmFieldSetRepeatedDateTime(OrmConn conn,
								 const pb::FieldDescriptor *field,
								 time_t value,
								 pb::uint64 fieldid);

bool OrmFieldSetRepeatedDate(OrmConn conn,
							const pb::FieldDescriptor *field,
							time_t value,
							pb::uint64 fieldid);

bool OrmFieldSetRepeatedTime(OrmConn conn,
							 const pb::FieldDescriptor *field,
							 time_t value,
							 pb::uint64 fieldid);

#endif
