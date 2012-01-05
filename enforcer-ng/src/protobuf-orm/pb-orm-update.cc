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
//  pb-orm-update.cc
//  protobuf-orm
//

#include "pb-orm-enum.h"
#include "pb-orm-create.h"
#include "pb-orm-read.h"
#include "pb-orm-update.h"
#include "pb-orm-delete.h"

#include "pb-orm-value.h"
#include "pb-orm-str.h"
#include "pb-orm-log.h"
#include "pb-orm-database.h"
#include "pb-orm-context.h"

#include "orm.pb.h"

static bool
pb_field_set_repeated_value(OrmConn conn,
							const pb::FieldDescriptor *field,
							const std::string value,
							pb::uint64 fieldid)
{
	if (!field->is_repeated()) {
		OrmLogError("expected field to be repeated");
		return false;
	}
	std::string table = field->containing_type()->name() + "_" + field->name();
	
	std::string assignment = "value=" + value;
	
	DB::OrmResultT result( CONN->queryf("UPDATE %s SET %s WHERE id=%llu",
									table.c_str(),
									assignment.c_str(),
									fieldid) );
	if (!result.assigned())
		return false;
	return true;
}

static bool
pb_field_update_repeated_value(OrmContextT *context,
							   const pb::FieldDescriptor *field)
{
	const pb::Reflection *reflection = context->message->GetReflection();
	int pb_fieldsize = reflection->FieldSize(*context->message, field);
	
	if (field->type() == pb::FieldDescriptor::TYPE_MESSAGE) {
		// Note that we create a copy of the field context in fc.
		// We are going to mutate fc and don't want to damage the original.
		std::map<pb::uint64, OrmContext> fc = context->fields[field->number()]; // copy !
		std::map<pb::uint64, OrmContext>::iterator fcit;
		
		// Update existing field values and insert newly added ones in the db.
		for (int i=0; i<pb_fieldsize; ++i) {
			const pb::Message &value = reflection->GetRepeatedMessage(*context->message, field,i);
			pb::uint64 msgvalkey = (pb::uint64)&value;
			fcit = fc.find(msgvalkey);
			if (fcit != fc.end()) {
				// message already present in db, update it.
				if (!OrmMessageUpdate(fcit->second))
					return false;

				// remove the message from the map (fc) after handling it.
				fc.erase(fcit);
			} else {
				// message not yet present in db, insert it.
				pb::uint64 fieldid;
				if (!OrmFieldAddRepeatedMessage(context->conn,
												context->id,
												field,
												value,
												fieldid)
					)
					return false;
			}
		}
		
		// What remains in fc are messages no longer present in the 
		// repeated field. delete those from the db.
		for (fcit=fc.begin(); fcit != fc.end(); ++fcit) {
			OrmContextT *fcontext = (OrmContextT*)fcit->second;
			if (!OrmFieldDeleteRepeatedValue(context->conn, field, fcontext->id))
				return false;
		}

		return true;
	} else {
		std::map<pb::uint64, OrmContext> &fc = context->fields[field->number()];
		int db_fieldsize = (int)fc.size();
		int fieldsize = (db_fieldsize < pb_fieldsize ? db_fieldsize : pb_fieldsize);

		// update first fieldsize number of fields in the db from message field values
		for (int i=0; i<fieldsize; ++i) {
			OrmContextT *fcontext = (OrmContextT*)fc[i];
			if (!OrmFieldSetRepeatedValue(context->conn, context->id, *context->message, field, i, fcontext->id))
				return false;
		}
		
		if (db_fieldsize < pb_fieldsize) {
			// More values in repeated field of the message than in db.
			// Insert fields from message into db.
			for (int i=db_fieldsize; i<pb_fieldsize; ++i) {
				pb::uint64 fieldid;
				if (!OrmFieldAddRepeatedValue(context->conn, context->id, *context->message, field, i, fieldid))
					return  false;
			}
		} else {
			// More values in db than in repeated field of the message.
			// Delete fields from db.
			for (int i=pb_fieldsize; i<db_fieldsize; ++i) {
				OrmContextT *fcontext = (OrmContextT*)fc[i];
				if (!OrmFieldDeleteRepeatedValue(context->conn, field, fcontext->id))
					return false;
			}
		}
		
		return true;
	}
}

static bool
pb_field_update_value(OrmContextT *context,
					  const pb::FieldDescriptor *field,
					  std::string &assignments)
{
	const pb::Reflection *reflection = context->message->GetReflection();

	// Handle non-repeated fields.
	bool bFieldHasValue = reflection->HasField(*context->message, field);
	
	// Check that required fields are actually assigned a value.
	if (field->is_required() && !bFieldHasValue) {
		// OrmLogError("required field was not assigned a value");
		return false;
	}
	
	pb::FieldDescriptor::Type type = field->type();
	
	// Check for out of range values.
	if (type < pb::FieldDescriptor::TYPE_DOUBLE
		|| type > pb::FieldDescriptor::MAX_TYPE) {
		OrmLogError("pb::FieldDescriptor::Type value out of range");
		return false;
	}
	
	// fail on GROUP values
	if (type == pb::FieldDescriptor::TYPE_GROUP) {
		OrmLogError("no support for TYPE_GROUP values");
		return false;
	}
	
	std::string name;
	pb_field_name(field,name);
	
	std::string value;
	if (type == pb::FieldDescriptor::TYPE_MESSAGE) {
		// Handle MESSAGE value
		
		// lookup the field tag in the OrmContextT class
		// if we find it, then message was already present, so 
		// in that case update the existing message.
		std::map<pb::uint64, OrmContext> &fc = context->fields[field->number()];
		if (fc.size() > 1) {
			OrmLogError("invalid number of fields associated with message");
			return false;
		}
		pb::uint64 fieldid = 0;
		OrmContext fcontext = NULL;
		if (fc.begin() != fc.end()) {
			fcontext = fc.begin()->second;
			if (!fcontext) {
				OrmLogError("expected context to be assigned for field");
				return false;
			}
			fieldid = ((OrmContextT*)fcontext)->id;
		}
		
		// We need to lookup the id of the field to deterine what to do.
		// Find out what fieldid is being used.
		if (fieldid != 0) {
			// The field is currently present in the table
			
			if (bFieldHasValue) {
				
				// Field is also present in message => Update existing.
				if (!OrmMessageUpdate(fcontext))
					return false; // failed to update aggregated message, don't continue.
				
				// no need to update the field id stored in the table, it hasn't changed.
				return true;
				
			} else {
				// Field is not present in message => Delete existing.
				if (!OrmMessageDelete(context->conn,field->message_type(),fieldid))
					return false; // Failed to delete aggregated message, don't continue.
				value = "NULL";
			}
		} else {
			// The field is currently not present in the table
			
			if (bFieldHasValue) {
				// Field is present in message => Insert new.
				
				pb::uint64 fieldid;
				if (!OrmMessageInsert(context->conn, reflection->GetMessage(*context->message, field), fieldid))
					return false;
				
				if (!pb_field_uint64_value(fieldid, value))
					return false;
				
			} else {
				// Field is not present in message => nothing to do
				return true;
			}
		}
	} else {
		// Handle other types of values.
		if (!pb_field_value(context->conn,context->message,field,value))
			return false;
	}
	OrmChain(assignments,name + "=" + value,',');
	return true;
}

bool OrmMessageUpdate(OrmContext context)
{
	OrmContextT *ctx = (OrmContextT *)context;
	if (!ctx) {
		OrmLogError("OrmMessageUpdate invalid context passed (context is NULL)");
		return false;
	}
	if (!ctx->message) {
		OrmLogError("OrmMessageUpdate invalid context passed (message is NULL)");
		return false;
	}
	if (ctx->id == 0) {
		OrmLogError("OrmMessageUpdate invalid context passed (id is 0)");
		return false;
	}

	// Recursively update aggregated messages and repeated values
	// For values stored in the table associated with the current message create
	// a string with assignments.
	std::string assignments;
	const pb::Descriptor *descriptor = ctx->message->GetDescriptor();
	for (int f=0; f<descriptor->field_count(); ++f) {
		const pb::FieldDescriptor*field = descriptor->field(f);
		if (field->is_repeated()) {
			if (!pb_field_update_repeated_value(ctx,field))
				return false;
		} else {
			if (!pb_field_update_value(ctx,field,assignments))
				return false;
		}
	}
	
	if (assignments.size() > 0) {
		OrmConn conn = ctx->conn;
		
		DB::OrmResultT result( CONN->queryf("UPDATE %s SET %s WHERE id=%llu",
										ctx->message->GetDescriptor()->name().c_str(),
										assignments.c_str(),
										ctx->id) );
		if (!result.assigned())
			return false;
	}
	return true;
}

bool OrmFieldSetRepeatedValue(OrmConn conn,
							  pb::uint64 id,
							  const pb::Message &message,
							  const pb::FieldDescriptor *field,
							  int index,
							  pb::uint64 fieldid)
{
	std::string value;			
	if (!pb_field_repeated_value(conn,&message,field,index,value))
		return false;
	return pb_field_set_repeated_value(conn, field, value, fieldid);
}

bool OrmFieldSetRepeatedBool(OrmConn conn,
							 const pb::FieldDescriptor *field,
							 bool value,
							 pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_bool_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedFloat(OrmConn conn,
							  const pb::FieldDescriptor *field,
							  float value,
							  pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_float_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedDouble(OrmConn conn,
							   const pb::FieldDescriptor *field,
							   double value,
							   pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_double_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedInt32(OrmConn conn,
							  const pb::FieldDescriptor *field,
							  pb::int32 value,
							  pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_int32_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedInt64(OrmConn conn,
							  const pb::FieldDescriptor *field,
							  pb::int64 value,
							  pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_int64_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedUint32(OrmConn conn,
							   const pb::FieldDescriptor *field,
							   pb::uint32 value,
							   pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_uint32_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedUint64(OrmConn conn,
							   const pb::FieldDescriptor *field,
							   pb::uint64 value,
							   pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_uint64_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedString(OrmConn conn,
							   const pb::FieldDescriptor *field,
							   const std::string &value,
							   pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_string_value(conn,value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedBinary(OrmConn conn,
							   const pb::FieldDescriptor *field,
							   const std::string &value,
							   pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_binary_value(conn,value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedMessage(OrmContext context,
								const pb::FieldDescriptor *field)
{
	if (!field->is_repeated()) {
		OrmLogError("expected field to be repeated");
		return false;
	}
	
	// Message has to be present, update it in the table.
	return OrmMessageUpdate(context);
}

bool OrmFieldSetRepeatedEnum(OrmConn conn,
							 const pb::FieldDescriptor *field,
							 const std::string &value,
							 pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_enum_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedDateTime(OrmConn conn,
								 const pb::FieldDescriptor *field,
								 time_t value,
								 pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_datetime_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedDate(OrmConn conn,
							 const pb::FieldDescriptor *field,
							 time_t value,
							 pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_date_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

bool OrmFieldSetRepeatedTime(OrmConn conn,
							 const pb::FieldDescriptor *field,
							 time_t value,
							 pb::uint64 fieldid)
{
	std::string assignment;
	if (!pb_field_time_value(value,assignment))
		return false;
	return pb_field_set_repeated_value(conn, field, assignment, fieldid);
}

