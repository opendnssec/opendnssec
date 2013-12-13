/*
 * Created by René Post on 10/26/11.
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

/*****************************************************************************
 pb-orm-value.h
 protobuf-orm
 
 Extract protobuf values as SQL strings, properly quoted where needed.
 *****************************************************************************/

#ifndef pb_orm_value_h
#define pb_orm_value_h

#include "pb-orm-common.h"

void pb_field_name(const pb::FieldDescriptor *field,
				   std::string &name);

bool pb_field_value(OrmConn conn,
					const pb::Message *message,
					const pb::FieldDescriptor *field,
					std::string &dest);

bool pb_field_bool_value(bool value,
						 std::string &dest);

bool pb_field_float_value(float value,
						  std::string &dest);

bool pb_field_double_value(double value,
						   std::string &dest);

bool pb_field_int32_value(pb::int32 value,
						  std::string &dest);

bool pb_field_int64_value(pb::int64 value,
						  std::string &dest);

bool pb_field_uint32_value(pb::uint32 value,
						   std::string &dest);

bool pb_field_uint64_value(pb::uint64 value,
						   std::string &dest);

bool pb_field_string_value(OrmConn conn,
						   const std::string &value,
						   std::string &dest);

bool pb_field_binary_value(OrmConn conn,
						   const std::string &value,
						   std::string &dest);

bool pb_field_enum_value(const std::string &value,
						 std::string &dest);

bool pb_field_datetime_value(time_t value,
							 std::string &dest);

bool pb_field_date_value(time_t value,
						 std::string &dest);

bool pb_field_time_value(time_t value,
						 std::string &dest);

bool pb_field_repeated_value(OrmConn conn,
							 const pb::Message *message,
							 const pb::FieldDescriptor *field,
							 int index,
							 std::string &dest);

#endif
