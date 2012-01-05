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
//  pb-orm-create.cc
//  protobuf-orm
//

#include <math.h>
#include <time.h>

#include "pb-orm-create.h"
#include "pb-orm-value.h"
#include "pb-orm-str.h"
#include "pb-orm-log.h"
#include "pb-orm-database.h"
#include "orm.pb.h"

static bool
pb_insert_names_and_values_into_table(OrmConn conn,
									  const std::string &table,
									  const std::string &names,
									  const std::string &values)
{
	DB::OrmResultT result;
	if (names.size() > 0) {
		result = CONN->queryf("INSERT INTO %s (%s) VALUES (%s)",
							  table.c_str(),
							  names.c_str(),
							  values.c_str());
	} else {
		result = CONN->queryf("INSERT INTO %s (id) VALUES (NULL)",
							  table.c_str());
		
	}
	if (!result.assigned()) {
		OrmLogError("failed to insert values into table: %s",table.c_str());
		return false; // valid id is never 0
	}
	return true;
}

static bool
pb_field_add_repeated_message(OrmConn conn,
							  pb::uint64 id,
							  const pb::FieldDescriptor *field,
							  pb::uint64 childid)
{
	// insert new parent_id,child_id pair into the repeated field table.
	std::string table = field->containing_type()->name() + "_" + field->name();
	std::string names("parent_id,child_id");
	std::string values;
	if (!pb_field_uint64_value(id,values))
		return false;
	std::string childidstr;
	if (!pb_field_uint64_value(childid,childidstr))
		return false;
	OrmChain(values,childidstr,',');
	
	return pb_insert_names_and_values_into_table(conn, table, names, values);
}

static bool
pb_field_add_repeated_value(OrmConn conn,
							pb::uint64 id,
							const pb::FieldDescriptor *field,
							const std::string &value,
							pb::uint64 &fieldid)
{
	// insert both value and parent_id into the repeated field table
	std::string table = field->containing_type()->name() + "_" + field->name();
	std::string names = "value,parent_id";
	std::string values = value;
	std::string parentidstr;
	if (!pb_field_uint64_value(id,parentidstr))
		return false;
	OrmChain(values,parentidstr,',');	
	
	// when failed to insert aggregated value, don't continue.
	if (!pb_insert_names_and_values_into_table(conn,table,names,values))
		return false;
	// get the id that was created during the last insert.
	fieldid = CONN->sequence_last();
	return true;
}

static bool
pb_field_type_valid(const pb::FieldDescriptor *field)
{
	pb::FieldDescriptor::Type type = field->type();

	// Check for out of range values.
	if (type < pb::FieldDescriptor::TYPE_DOUBLE
		|| type > pb::FieldDescriptor::MAX_TYPE) {
		OrmLogError("pb::FieldDescriptor::Type value out of range");
		return false;
	}

	// fail on GROUP values
	if (type == pb::FieldDescriptor::TYPE_GROUP) {
		OrmLogError("unable to handle TYPE_GROUP values.");
		return false;
	}
	
	return true;
}

bool OrmMessageInsert(OrmConn conn, const pb::Message &message, pb::uint64 &id)
{
	std::string names;
	std::string values;
	const pb::Descriptor *descriptor = message.GetDescriptor();
	const pb::Reflection *reflection = message.GetReflection();
	
	// Check that required fields are actually assigned a value.
	for (int i=0; i<descriptor->field_count(); ++i) {
		const pb::FieldDescriptor *field = descriptor->field(i);
		if (field->is_required() && !reflection->HasField(message, field)) {
			// OrmLogError("required field was not assigned a value");
			return false;
		}
	}
	
	std::vector<const pb::FieldDescriptor*> fields;
	reflection->ListFields(message,&fields);
	
	names.clear();
	values.clear();
	for (int fi=0; fi<fields.size(); ++fi) {
		
		// we don't handle repeated fields during this stage of an insert.
		if (fields[fi]->is_repeated())
			continue;
		
		if (!pb_field_type_valid(fields[fi]))
			return false;
		
		std::string name;
		pb_field_name(fields[fi],name);
		OrmChain(names,name,',');
		
		std::string value;
		if (fields[fi]->type() == pb::FieldDescriptor::TYPE_MESSAGE) {
			// Handle MESSAGE value
			pb::uint64 fieldid;
			if (!OrmMessageInsert(conn,reflection->GetMessage(message, fields[fi]),fieldid))
				return false; // failed to insert aggregated message, don't continue.
			
			// failed to format field, don't continue.
			if (!pb_field_uint64_value(fieldid,value))
				return false;
		} else {
			// Handle other types of values.
			if (!pb_field_value(conn,&message,fields[fi],value))
				return false;
		}
		
		OrmChain(values,value,',');
		
	}
	
	if (!pb_insert_names_and_values_into_table(conn,
											   message.GetDescriptor()->name(),
											   names,
											   values)
		)
		return false;

	// get the id that was created during the last insert.
	id = CONN->sequence_last();

	// Insert repeated fields that reference this message by id.	
	for (int fi=0; fi<fields.size(); ++fi) {
		
		// we only handle fields that are repeated.
		if (!fields[fi]->is_repeated())
			continue;

		if (!pb_field_type_valid(fields[fi]))
			return false;
		
		for (int index=0; index<reflection->FieldSize(message,fields[fi]); ++index) {
			// Handle other types of values.
			pb::uint64 fieldid;
			
			if (!OrmFieldAddRepeatedValue(conn, id, message, fields[fi], index, fieldid))
				return false;
		}
	}
	return true;
}

bool OrmFieldAddRepeatedValue(OrmConn conn,
							  pb::uint64 id,
							  const pb::Message &message,
							  const pb::FieldDescriptor *field,
							  int index,
							  pb::uint64 &fieldid)
{
	if (field->type() == pb::FieldDescriptor::TYPE_MESSAGE) {
		// Handle MESSAGE value
		const pb::Message &value =
			message.GetReflection()->GetRepeatedMessage(message, field, index);
		if (!OrmFieldAddRepeatedMessage(conn,id,field,value,fieldid))
			return false;
	} else {
		std::string value;
		if (!pb_field_repeated_value(conn,&message,field,index,value))
			return false;
		if (!pb_field_add_repeated_value(conn, id, field, value, fieldid))
			return false;
	}	
	return true;
}

bool OrmFieldAddRepeatedBool(OrmConn conn,
							 pb::uint64 id,
							 const pb::FieldDescriptor *field,
							 bool value,
							 pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_bool_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}

bool OrmFieldAddRepeatedFloat(OrmConn conn,
							  pb::uint64 id,
							  const pb::FieldDescriptor *field,
							  float value,
							  pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_float_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}

bool OrmFieldAddRepeatedDouble(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							   double value,
							   pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_double_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}


bool OrmFieldAddRepeatedInt32(OrmConn conn,
							  pb::uint64 id,
							  const pb::FieldDescriptor *field,
							  pb::int32 value,
							  pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_int32_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}


bool OrmFieldAddRepeatedInt64(OrmConn conn,
							  pb::uint64 id,
							  const pb::FieldDescriptor *field,
							  pb::int64 value,
							  pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_int64_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}

bool OrmFieldAddRepeatedUint32(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							   pb::uint32 value,
							   pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_uint32_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}

bool OrmFieldAddRepeatedUint64(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							   pb::uint64 value,
							   pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_uint64_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}


bool OrmFieldAddRepeatedString(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							   const std::string &value,
							   pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_string_value(conn,value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}

bool OrmFieldAddRepeatedBinary(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor *field,
							   const std::string &value,
							   pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_binary_value(conn,value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}

bool OrmFieldAddRepeatedMessage(OrmConn conn,
								pb::uint64 id,
								const pb::FieldDescriptor *field,
								const pb::Message &value,
								pb::uint64 &fieldid)
{
	// insert the message value and hold on to the returned childid
	if (!OrmMessageInsert(conn,value,fieldid))
		return false; // when failed to insert aggregated message, don't continue.
	
	return pb_field_add_repeated_message(conn, id, field, fieldid);
}

bool OrmFieldAddRepeatedEnum(OrmConn conn,
							 pb::uint64 id,
							 const pb::FieldDescriptor *field,
							 const std::string &value,
							 pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_enum_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}


bool OrmFieldAddRepeatedDateTime(OrmConn conn,
								 pb::uint64 id,
								 const pb::FieldDescriptor *field,
								 time_t value,
								 pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_datetime_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}


bool OrmFieldAddRepeatedDate(OrmConn conn,
							 pb::uint64 id,
							 const pb::FieldDescriptor *field,
							 time_t value,
							 pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_date_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}


bool OrmFieldAddRepeatedTime(OrmConn conn,
							 pb::uint64 id,
							 const pb::FieldDescriptor *field,
							 time_t value,
							 pb::uint64 &fieldid)
{
	std::string valuestr;
	if (!pb_field_time_value(value,valuestr))
		return false;
	return pb_field_add_repeated_value(conn, id, field, valuestr, fieldid);
}


