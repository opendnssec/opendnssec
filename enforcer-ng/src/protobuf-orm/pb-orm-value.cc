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
 pb-orm-value.cc
 protobuf-orm
 
 Extract protobuf values as SQL strings, properly quoted where needed.
 *****************************************************************************/

#include <time.h>
#include <math.h>

#include "pb-orm-value.h"
#include "pb-orm-str.h"
#include "pb-orm-log.h"
#include "pb-orm-database.h"
#include "orm.pb.h"

static time_t
pb_reflection_get_time(const pb::Reflection *reflection,
					   const pb::Message &message,
					   const pb::FieldDescriptor *field)
{
	switch (field->cpp_type()) {
		case pb::FieldDescriptor::CPPTYPE_INT32:
			return reflection->GetInt32(message, field);
		case pb::FieldDescriptor::CPPTYPE_INT64:
			return reflection->GetInt64(message, field);
		case pb::FieldDescriptor::CPPTYPE_UINT32:
			return reflection->GetUInt32(message, field);
		case pb::FieldDescriptor::CPPTYPE_UINT64:
			return reflection->GetUInt64(message, field);
		case pb::FieldDescriptor::CPPTYPE_DOUBLE:
			return floor(reflection->GetDouble(message, field));
		case pb::FieldDescriptor::CPPTYPE_FLOAT:
			return floorf(reflection->GetFloat(message, field));
		default:
			OrmLogError("ERROR: Incompatible value type for time_t");
			return -1;
	}
	OrmLogError("ERROR: internal error in pb_reflection_get_time");
	return -1;
}

void pb_field_name(const pb::FieldDescriptor *field, std::string &name)
{		
	name = field->name();
	if (field->options().HasExtension(orm::column)) {
		orm::Column column = field->options().GetExtension(orm::column);
		if (column.has_name())
			name = column.name();
	}		
}

bool pb_field_value(OrmConn conn,
					const pb::Message *message,
					const pb::FieldDescriptor *field,
					std::string &dest)
{
	const pb::Reflection *reflection = message->GetReflection();
	
	// A type that is not present should be represented by NULL
	if (!reflection->HasField(*message, field)) {
		dest = "NULL";
		return true;
	}
	
	orm::Column	column;
	if (field->options().HasExtension(orm::column)) {
		column = field->options().GetExtension(orm::column);
	}
	if (column.has_type()) {
		switch (column.type()) {
			case orm::DATETIME: {
				time_t value = pb_reflection_get_time(reflection, *message, field);
				return pb_field_datetime_value(value,dest);
			}
			case orm::DATE: {
				time_t value = pb_reflection_get_time(reflection, *message, field);
				return pb_field_date_value(value,dest);
			}
			case orm::TIME: {
				time_t value = pb_reflection_get_time(reflection, *message, field);
				return pb_field_time_value(value,dest);
			}
			case orm::YEAR: {
				break;
			}
			default:
				OrmLogError("unknown ormoption.type");
				return false;
		}
	}
	
	switch (field->type()) {
		case pb::FieldDescriptor::TYPE_BOOL:
			return pb_field_bool_value(reflection->GetBool(*message, field), dest);
		case pb::FieldDescriptor::TYPE_FLOAT:
			return pb_field_float_value(reflection->GetFloat(*message,field),dest);
		case pb::FieldDescriptor::TYPE_DOUBLE:
			return pb_field_double_value(reflection->GetDouble(*message,field),dest);
		case pb::FieldDescriptor::TYPE_INT32:
		case pb::FieldDescriptor::TYPE_SFIXED32:
		case pb::FieldDescriptor::TYPE_SINT32:
			return pb_field_int32_value(reflection->GetInt32(*message,field),dest);
		case pb::FieldDescriptor::TYPE_INT64:
		case pb::FieldDescriptor::TYPE_SFIXED64:
		case pb::FieldDescriptor::TYPE_SINT64:
			return pb_field_int64_value(reflection->GetInt64(*message,field),dest);
		case pb::FieldDescriptor::TYPE_UINT32:
		case pb::FieldDescriptor::TYPE_FIXED32:
			return pb_field_uint32_value(reflection->GetUInt32(*message,field),dest);
		case pb::FieldDescriptor::TYPE_UINT64:
		case pb::FieldDescriptor::TYPE_FIXED64:
			return pb_field_uint64_value(reflection->GetUInt64(*message,field),dest);
		case pb::FieldDescriptor::TYPE_STRING: {
			std::string str;
			const std::string &strref = reflection->GetStringReference(*message,
																	   field,
																	   &str);
			return pb_field_string_value(conn, strref, dest);
		}
		case pb::FieldDescriptor::TYPE_GROUP:
			OrmLogError("cannot create string value for TYPE_GROUP");
			return false;
		case pb::FieldDescriptor::TYPE_MESSAGE:
			OrmLogError("cannot create string value for TYPE_MESSAGE");
			return false;
		case pb::FieldDescriptor::TYPE_BYTES: {
			std::string bin;
			const std::string &binref = reflection->GetStringReference(*message,
																	   field,
																	   &bin);
			return pb_field_binary_value(conn, binref, dest);
		}
			
		case pb::FieldDescriptor::TYPE_ENUM:
			return OrmFormat(dest,"'%s'",
							  reflection->GetEnum(*message,field)->name().c_str());
	}
	OrmLogError("ERROR: UNKNOWN FIELD TYPE");
	return false;
}

bool pb_field_bool_value(bool value,
						 std::string &dest)
{
	return OrmFormat(dest,"%d",value?1:0);
}

bool pb_field_float_value(float value,
						  std::string &dest)
{
	return OrmFormat(dest,"%g",value);
}

bool pb_field_double_value(double value,
						  std::string &dest)
{
	return OrmFormat(dest,"%g",value);
}

bool pb_field_int32_value(pb::int32 value,
						  std::string &dest)
{
	return OrmFormat(dest,"%d",value);
}

bool pb_field_int64_value(pb::int64 value,
						  std::string &dest)
{
	return OrmFormat(dest,"%lld",value);
}

bool pb_field_uint32_value(pb::uint32 value,
						   std::string &dest)
{
	return OrmFormat(dest,"%u",value);
}

bool pb_field_uint64_value(pb::uint64 value,
						   std::string &dest)
{
	return OrmFormat(dest,"%llu",value);
}

bool pb_field_string_value(OrmConn conn,const std::string &value, std::string &dest)
{
	return CONN->quote_string(value,dest);
}

bool pb_field_binary_value(OrmConn conn,const std::string &value, std::string &dest)
{
	return CONN->quote_binary(value,dest);
}

bool pb_field_datetime_value(time_t value,std::string &dest)
{
	char timestr[32];
	struct tm timestruct;
	if (value==-1)
		return false;
	strftime(timestr, sizeof(timestr), "'%Y-%m-%d %H:%M:%S'", gmtime_r(&value, &timestruct));
	dest.assign(timestr);
	return true;
}

bool pb_field_date_value(time_t value,std::string &dest)
{
	char timestr[32];
	struct tm timestruct;
	if (value==-1)
		return false;
	strftime(timestr, sizeof(timestr), "'%Y-%m-%d'", gmtime_r(&value, &timestruct));
	dest.assign(timestr);
	return true;
}

bool pb_field_time_value(time_t value,std::string &dest)
{
	char timestr[32];
	struct tm timestruct;
	if (value==-1)
		return false;
	strftime(timestr, sizeof(timestr), "'%H:%M:%S'", gmtime_r(&value, &timestruct));
	dest.assign(timestr);
	return true;
}

bool pb_field_enum_value(const std::string &value,
						 std::string &dest)
{
	return OrmFormat(dest,"'%s'",value.c_str());
}

static time_t
pb_reflection_get_repeated_time_at_index(const pb::Reflection *reflection,
										 const pb::Message &message,
										 const pb::FieldDescriptor *field,
										 int index)
{
	switch (field->cpp_type()) {
		case pb::FieldDescriptor::CPPTYPE_INT32:
			return reflection->GetRepeatedInt32(message, field, index);
		case pb::FieldDescriptor::CPPTYPE_INT64:
			return reflection->GetRepeatedInt64(message, field, index);
		case pb::FieldDescriptor::CPPTYPE_UINT32:
			return reflection->GetRepeatedUInt32(message, field, index);
		case pb::FieldDescriptor::CPPTYPE_UINT64:
			return reflection->GetRepeatedUInt64(message, field, index);
		case pb::FieldDescriptor::CPPTYPE_DOUBLE:
			return floor(reflection->GetRepeatedDouble(message, field, index));
		case pb::FieldDescriptor::CPPTYPE_FLOAT:
			return floorf(reflection->GetRepeatedFloat(message, field, index));
		default:
			OrmLogError("ERROR: Incompatible value type for time_t");
			return -1;
	}
	OrmLogError("ERROR: internal error in pb_reflection_get_repeated_time_at_index");
	return -1;
}

bool
pb_field_repeated_value(OrmConn conn,
						const pb::Message *message,
						const pb::FieldDescriptor *field,
						int index,
						std::string &dest)
{
	const pb::Reflection *reflection = message->GetReflection();
	
	orm::Column column;
	if (field->options().HasExtension(orm::column)) {
		column = field->options().GetExtension(orm::column);
	}
	if (column.has_type()) {
		switch (column.type()) {
			case orm::DATETIME: {
				time_t value = 
				pb_reflection_get_repeated_time_at_index(reflection,
														 *message,
														 field,
														 index);
				return pb_field_datetime_value(value, dest);
			}
			case orm::DATE: {
				time_t value = 
				pb_reflection_get_repeated_time_at_index(reflection,
														 *message,
														 field,
														 index);
				return pb_field_date_value(value, dest);
			}
			case orm::TIME: {
				time_t value = 
				pb_reflection_get_repeated_time_at_index(reflection,
														 *message,
														 field,
														 index);
				return pb_field_time_value(value, dest);
			}
			case orm::YEAR: {
				break;
			}
			default:
				OrmLogError("unknown ormoption.type");
				return false;
		}
	}
	
	switch (field->type()) {
		case pb::FieldDescriptor::TYPE_BOOL:
			return pb_field_bool_value(reflection->GetRepeatedBool(*message, field, index),dest);
		case pb::FieldDescriptor::TYPE_FLOAT:
			return pb_field_float_value(reflection->GetRepeatedFloat(*message,field, index),dest);
		case pb::FieldDescriptor::TYPE_DOUBLE:
			return pb_field_double_value(reflection->GetRepeatedDouble(*message,field, index),dest);
		case pb::FieldDescriptor::TYPE_INT32:
		case pb::FieldDescriptor::TYPE_SFIXED32:
		case pb::FieldDescriptor::TYPE_SINT32:
			return pb_field_int32_value(reflection->GetRepeatedInt32(*message,field, index),dest);
		case pb::FieldDescriptor::TYPE_INT64:
		case pb::FieldDescriptor::TYPE_SFIXED64:
		case pb::FieldDescriptor::TYPE_SINT64:
			return pb_field_int64_value(reflection->GetRepeatedInt64(*message,field, index),dest);
		case pb::FieldDescriptor::TYPE_UINT32:
		case pb::FieldDescriptor::TYPE_FIXED32:
			return pb_field_uint32_value(reflection->GetRepeatedUInt32(*message,field, index),dest);
		case pb::FieldDescriptor::TYPE_UINT64:
		case pb::FieldDescriptor::TYPE_FIXED64:
			return pb_field_uint64_value(reflection->GetRepeatedUInt64(*message,field, index),dest);
		case pb::FieldDescriptor::TYPE_STRING: {
			std::string str;
			const std::string &strref =
			reflection->GetRepeatedStringReference(*message,
												   field,
												   index,
												   &str);
			return pb_field_string_value(conn,strref,dest);
		}
		case pb::FieldDescriptor::TYPE_GROUP:
			OrmLogError("cannot create string value for TYPE_GROUP");
			return false;
		case pb::FieldDescriptor::TYPE_MESSAGE:
			OrmLogError("cannot create string value for TYPE_MESSAGE");
			return false;
		case pb::FieldDescriptor::TYPE_BYTES: {
			std::string bin;
			const std::string &binref =
			reflection->GetRepeatedStringReference(*message,
												   field,
												   index,
												   &bin);
			return pb_field_binary_value(conn,binref,dest);
		}
			
		case pb::FieldDescriptor::TYPE_ENUM:
			return OrmFormat(dest,"'%s'",
							  reflection->GetRepeatedEnum(*message,field,index)->name().c_str());
	}
	OrmLogError("ERROR: UNKNOWN FIELD TYPE");
	return false;
}
