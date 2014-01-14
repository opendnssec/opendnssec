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
//  pb-orm-read.cc
//  protobuf-orm
//

#include "pb-orm-read.h"
#include "pb-orm-enum.h"
#include "pb-orm-log.h"
#include "pb-orm-database.h"
#include "pb-orm-context.h"
#include "orm.pb.h"


static bool
pb_reflection_set_datetime(const pb::Reflection *reflection,
						   pb::Message* message,
						   const pb::FieldDescriptor* field,
						   time_t value) 
{	
	switch (field->cpp_type()) {
		case pb::FieldDescriptor::CPPTYPE_INT32:
			reflection->SetInt32(message, field,(pb::int32)value);
			return true;
		case pb::FieldDescriptor::CPPTYPE_INT64:
			reflection->SetInt64(message, field, value);
			return true;
		case pb::FieldDescriptor::CPPTYPE_UINT32:
			reflection->SetUInt32(message, field, (pb::uint32)value);
			return true;
		case pb::FieldDescriptor::CPPTYPE_UINT64:
			reflection->SetUInt64(message, field, value);
			return true;
		case pb::FieldDescriptor::CPPTYPE_DOUBLE:
			reflection->SetDouble(message, field, value);
			return true;
		case pb::FieldDescriptor::CPPTYPE_FLOAT:
			reflection->SetFloat(message, field, value);
			return true;
		default:
			OrmLogError("ERROR: Incompatible value type for time_t");
			return false;
	}
	OrmLogError("ERROR: internal error in pb_reflection_set_time");
	return false;	
}

static bool
pb_reflection_set_repeated_datetime(const pb::Reflection *reflection,
								pb::Message* message,
								const pb::FieldDescriptor* field,
								time_t value) 
{	
	switch (field->cpp_type()) {
		case pb::FieldDescriptor::CPPTYPE_INT32:
			reflection->AddInt32(message, field, (pb::uint32)value);
			return true;
		case pb::FieldDescriptor::CPPTYPE_INT64:
			reflection->AddInt64(message, field, value);
			return true;
		case pb::FieldDescriptor::CPPTYPE_UINT32:
			reflection->AddUInt32(message, field, (pb::uint32)value);
			return true;
		case pb::FieldDescriptor::CPPTYPE_UINT64:
			reflection->AddUInt64(message, field, value);
			return true;
		case pb::FieldDescriptor::CPPTYPE_DOUBLE:
			reflection->AddDouble(message, field, value);
			return true;
		case pb::FieldDescriptor::CPPTYPE_FLOAT:
			reflection->AddFloat(message, field, value);
			return true;
		default:
			OrmLogError("ERROR: Incompatible value type for time_t");
			return false;
	}
	OrmLogError("ERROR: internal error in pb_reflection_set_repeated_time");
	return false;	
}

static bool
pb_assign_field(OrmResult result,
				pb::Message &message,
				const pb::FieldDescriptor*field,
				bool recurse,
				OrmContextT *context)
{
	if (result==NULL || !RESULT.assigned())
		return false;

	orm::Column column;
	if (field->options().HasExtension(orm::column)) {
		column = field->options().GetExtension(orm::column);
	}
	
	std::string orm_name;
	if (column.has_name())
		orm_name = column.name();
	else
		orm_name = field->name();

	unsigned int field_idx = RESULT->get_field_idx(orm_name);
	if (field_idx==0)
		return false;

	const pb::Reflection *reflection = message.GetReflection();
	
	// Determine whether the field in the database contains NULL
	if (RESULT->field_is_null_idx(field_idx)) {
		// Handle NULL values in db fields, clear the field value in the message.
		reflection->ClearField(&message, field);
		return true;
	}

	if (column.has_type()) {
		switch (column.type()) {
			case orm::DATETIME: 
			case orm::DATE:
			case orm::TIME: {
				time_t value = RESULT->get_datetime_idx(field_idx);
				if (RESULT->failed())
					return false;
				return pb_reflection_set_datetime(reflection, &message, field, value);
			}
			case orm::YEAR:
				break;
			default:
				OrmLogError("ERROR: Unknown value for ormoption.type");
				return false;
		}
	}
	
	// Handle NOT NULL values in db fields, assign field value in the message.
	switch (field->type()) {
		case pb::FieldDescriptor::TYPE_BOOL: {
			unsigned char value = RESULT->get_uchar_idx(field_idx);
			if (RESULT->failed())
				return false;
			if (value>1) {
				OrmLogError("TYPE_BOOL value retrieved from database out of range");
				return false;
			}
			reflection->SetBool(&message,field, value!=0);
			return true;
		}
		case pb::FieldDescriptor::TYPE_FLOAT: {
			float value = RESULT->get_float_idx(field_idx);
			if (RESULT->failed())
				return false;
			reflection->SetFloat(&message, field, value);
			return true;			
		}
		case pb::FieldDescriptor::TYPE_DOUBLE: {
			double value = RESULT->get_double_idx(field_idx);
			if (RESULT->failed())
				return false;
			reflection->SetDouble(&message, field, value);
			return true;			
		}
		case pb::FieldDescriptor::TYPE_INT32:
		case pb::FieldDescriptor::TYPE_SFIXED32:
		case pb::FieldDescriptor::TYPE_SINT32: {
			int value = RESULT->get_int_idx(field_idx);
			if (RESULT->failed())
				return false;
			reflection->SetInt32(&message,field,value);
			return true;			
		}
		case pb::FieldDescriptor::TYPE_INT64:
		case pb::FieldDescriptor::TYPE_SFIXED64:
		case pb::FieldDescriptor::TYPE_SINT64: {
			long long value = RESULT->get_longlong_idx(field_idx);
			if (RESULT->failed())
				return false;
			reflection->SetInt64(&message,field,value);
			return true;			
		}
		case pb::FieldDescriptor::TYPE_UINT32:
		case pb::FieldDescriptor::TYPE_FIXED32: {
			unsigned int value = RESULT->get_uint_idx(field_idx);
			if (RESULT->failed())
				return false;
			reflection->SetUInt32(&message,field,value);
			return true;			
		}
		case pb::FieldDescriptor::TYPE_UINT64:
		case pb::FieldDescriptor::TYPE_FIXED64: {
			unsigned long long value = RESULT->get_ulonglong_idx(field_idx);
			if (RESULT->failed())
				return false;
			reflection->SetUInt64(&message,field,value);
			return true;			
		}
		case pb::FieldDescriptor::TYPE_STRING: {
			const char *value = RESULT->get_string_idx(field_idx);
			if (RESULT->failed())
				return false;
			reflection->SetString(&message,field,value);
			return true;			
		}
		case pb::FieldDescriptor::TYPE_GROUP:
			OrmLogError("cannot assign TYPE_GROUP field from database");
			return false;
		case pb::FieldDescriptor::TYPE_MESSAGE: {
			unsigned long long id = RESULT->get_ulonglong_idx(field_idx);
			if (RESULT->failed())
				return false;
			/** YBS: If recurse is not set I believe we should return 
			 * here to prevent many database lookups. It however seems
			 * to cause pb-orm-test failures. */
			/** if (!recurse) return true; */
			pb::Message *value = reflection->MutableMessage(&message, field);
			if (!context)
				return OrmMessageRead(RESULT.conn, *value, id, recurse);
			OrmContext fctx;
			bool ok = OrmMessageRead(RESULT.conn, *value, id, recurse, fctx);
			if (ok)
				context->fields[field->number()][(pb::uint64)value] = fctx;
			return ok;
		}
		case pb::FieldDescriptor::TYPE_BYTES: {
			const unsigned char *value = RESULT->get_binary_idx(field_idx);
			if (RESULT->failed())
				return false;
			size_t size = RESULT->get_field_length_idx(field_idx);
			if (RESULT->failed())
				return false;
			reflection->SetString(&message,field,std::string((const char *)value,size));
			return true;			
		}
		case pb::FieldDescriptor::TYPE_ENUM: {
			const char *strvalue = RESULT->get_string_idx(field_idx);
			if (RESULT->failed() || !strvalue)
				return false;
			const pb::EnumValueDescriptor *value =
				field->enum_type()->FindValueByName(strvalue);
			if (value == NULL) {
				OrmLogError("Unable to find enum value %s",strvalue);
				return false;
			}
			reflection->SetEnum(&message, field, value);
			return true;
		}
	}
	OrmLogError("ERROR: Unknown value for field->type");
	return false;
}

static bool
pb_create_context(OrmResult result, 
				  pb::Message &message,
				  const pb::FieldDescriptor*field,
				  OrmContextT *context)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	if (context==NULL)
		return true;

	OrmContextT *fcontext = new OrmContextT;
	if (!fcontext) {
		OrmLogError("unable to allocate OrmContext");
		return false;
	}
	fcontext->conn = context->conn;
	if (!OrmGetId(result, fcontext->id)) {
		delete fcontext;
		return false;
	}
	int index = message.GetReflection()->FieldSize(message, field)-1;
	context->fields[field->number()][index] = (OrmContext)fcontext;
	return true;			
}

static bool
pb_add_repeated_field(OrmResult result,pb::Message &message,const pb::FieldDescriptor*field, OrmContextT *context)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	const pb::Reflection *reflection = message.GetReflection();

	// Check non message fields for NULL values (not allowed !)
	if (field->type() != pb::FieldDescriptor::TYPE_MESSAGE) {
		// Determine whether the field in the database contains NULL
		// Handle NULL values in db fields, clear the field value in the message.
		if (RESULT->field_is_null("value")) {
			OrmLogError("Internal error, retrieved repeated field is NULL");
			return false;
		}
	}
	
	if (field->options().HasExtension(orm::column)) {
		orm::Column column = field->options().GetExtension(orm::column);
		if (column.has_type()) {
			switch (column.type()) {
				case orm::DATETIME:
				case orm::DATE:
				case orm::TIME: {
					time_t value = RESULT->get_datetime("value");
					if (RESULT->failed())
						return false;
					if (!pb_reflection_set_repeated_datetime(reflection, &message, field, value))
						return false;
					return pb_create_context(result,message,field,context);
				}
				case orm::YEAR:
					break;
				default:
					OrmLogError("ERROR: Unknown value for ormoption.type");
					return false;
			}
		}
	}
	
	// Handle NOT NULL values in db fields, assign field value in the message.
	switch (field->type()) {
		case pb::FieldDescriptor::TYPE_BOOL: {
			bool value;
			if (!OrmGetBool(result, value))
				return false;
			reflection->AddBool(&message,field,value);
			return pb_create_context(result,message,field,context);
		}
		case pb::FieldDescriptor::TYPE_FLOAT: {
			float value;
			if (!OrmGetFloat(result, value))
				return false;
			reflection->AddFloat(&message,field,value);
			return pb_create_context(result,message,field,context);
		}
		case pb::FieldDescriptor::TYPE_DOUBLE: {
			double value;
			if (!OrmGetDouble(result, value))
				return false;
			reflection->AddDouble(&message,field,value);
			return pb_create_context(result,message,field,context);
		}
		case pb::FieldDescriptor::TYPE_INT32:
		case pb::FieldDescriptor::TYPE_SFIXED32:
		case pb::FieldDescriptor::TYPE_SINT32: {
			pb::int32 value;
			if (!OrmGetInt32(result, value))
				return false;
			reflection->AddInt32(&message,field,value);
			return pb_create_context(result,message,field,context);
		}
		case pb::FieldDescriptor::TYPE_INT64:
		case pb::FieldDescriptor::TYPE_SFIXED64:
		case pb::FieldDescriptor::TYPE_SINT64: {
			pb::int64 value;
			if (!OrmGetInt64(result, value))
				return false;
			reflection->AddInt64(&message,field,value);
			return pb_create_context(result,message,field,context);
		}
		case pb::FieldDescriptor::TYPE_UINT32:
		case pb::FieldDescriptor::TYPE_FIXED32: {
			pb::uint32 value;
			if (!OrmGetUint32(result, value))
				return false;
			reflection->AddUInt32(&message,field,value);
			return pb_create_context(result,message,field,context);
		}
		case pb::FieldDescriptor::TYPE_UINT64:
		case pb::FieldDescriptor::TYPE_FIXED64: {
			pb::uint64 value;
			if (!OrmGetUint64(result, value))
				return false;
			reflection->AddUInt64(&message,field,value);
			return pb_create_context(result,message,field,context);
		}
		case pb::FieldDescriptor::TYPE_STRING: {
			std::string value;
			if (!OrmGetString(result,value))
				return false;
			reflection->AddString(&message,field,value);
			return pb_create_context(result,message,field,context);
		}
		case pb::FieldDescriptor::TYPE_GROUP:
			OrmLogError("cannot assign TYPE_GROUP field from database");
			return false;
		case pb::FieldDescriptor::TYPE_MESSAGE: {
			pb::Message *value = reflection->AddMessage(&message, field);
			if (!value) {
				OrmLogError("Reflection::AddMessage(field) returned NULL");
				return false;
			}
			if (!context)
				return OrmGetMessage(result,*value,true);
			OrmContext fctx;
			bool ok = OrmGetMessage(result, *value, true, fctx);
			if (ok) {
				pb::uint64 msgkeyvalue = (pb::uint64)value;
				context->fields[field->number()][msgkeyvalue] = fctx;
			}
			return true;
		}
		case pb::FieldDescriptor::TYPE_BYTES: {
			std::string value;
			if (!OrmGetBinary(result,value))
				return false;
			reflection->AddString(&message,field,value);
			return pb_create_context(result,message,field,context);
		}
		case pb::FieldDescriptor::TYPE_ENUM: {
			std::string valuestr;
			if (!OrmGetEnum(result, valuestr))
				return false;
			const pb::EnumValueDescriptor *value =
				field->enum_type()->FindValueByName(valuestr);
			if (value == NULL) {
				OrmLogError("Unable to find enum value %s",valuestr.c_str());
				return false;
			}
			reflection->AddEnum(&message, field, value);
			return pb_create_context(result,message,field,context);
		}
	}
	OrmLogError("ERROR: Unknown value for field->type");
	return false;
}

bool OrmMessageRead(OrmConn conn,
				   pb::Message &value,
				   pb::uint64 id,
				   bool recurse)
{
	OrmResult result;
	if (!OrmMessageSelect(conn, value.GetDescriptor(), id, result))
		return false;
	bool ok = OrmGetMessage(result, value, recurse);
	OrmFreeResult(result);
	return ok;
}


bool OrmMessageRead(OrmConn conn,
					pb::Message &value,
					pb::uint64 id,
					bool recurse,
					OrmContext &context)
{
	OrmResult result;
	if (!OrmMessageSelect(conn, value.GetDescriptor(), id, result))
		return false;
	bool ok = OrmGetMessage(result, value, recurse, context);
	OrmFreeResult(result);
	if (!ok)
		return false;
	return true;
}

void OrmFreeContext(OrmContext context)
{
	OrmContextT *ctx = (OrmContextT *)context;
	if (ctx)
		delete ctx;
	else
		OrmLogError("NULL context passed to OrmFreeContext");
}

bool OrmFieldGetMessageId(OrmConn conn,
						  pb::uint64 id,
						  const pb::FieldDescriptor* field,
						  pb::uint64 &fieldid)
{
	OrmResult result;
	if (!OrmFieldSelectMessage(conn, id, field, result))
		return false;
	bool ok = OrmGetId(result, fieldid);
	OrmFreeResult(result);
	return ok;
}

bool OrmGetId(OrmResult result, pb::uint64 &id)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	id = RESULT->get_ulonglong("id");
	return !RESULT->failed();
}

bool OrmGetBool(OrmResult result, bool &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	unsigned char uval = RESULT->get_uchar("value");
	if (RESULT->failed())
		return false;
	if (uval>1) {
		OrmLogError("TYPE_BOOL value retrieved from database out of range");
		return false;
	}
	value = uval!=0;
	return true;
}

bool OrmGetFloat(OrmResult result, float &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	value = RESULT->get_float("value");
	return !RESULT->failed();
}

bool OrmGetDouble(OrmResult result, double &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	value = RESULT->get_double("value");
	return !RESULT->failed();
}

bool OrmGetInt32(OrmResult result, pb::int32 &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	value = RESULT->get_int("value");
	return !RESULT->failed();
}

bool OrmGetInt64(OrmResult result, pb::int64 &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	value = RESULT->get_longlong("value");
	return !RESULT->failed();
}

bool OrmGetUint32(OrmResult result, pb::uint32 &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	value = RESULT->get_uint("value");
	return !RESULT->failed();
}

bool OrmGetUint64(OrmResult result, pb::uint64 &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	value = RESULT->get_ulonglong("value");
	return !RESULT->failed();
}

bool OrmGetString(OrmResult result, std::string &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	const char *string = RESULT->get_string("value");
	if (string)
		value.assign(string);
	else
		value.clear();
	return !RESULT->failed();
}

bool OrmGetBinary(OrmResult result, std::string &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	unsigned int field_idx = RESULT->get_field_idx("value");
	if (field_idx==0)
		return false;
	const unsigned char *binary = RESULT->get_binary_idx(field_idx);
	if (binary==NULL)
		value.clear();
	if (RESULT->failed())
		return false;
	size_t size = RESULT->get_field_length_idx(field_idx);
	value.assign((const char *)binary, size);
	return true;
}

static bool
_OrmGetMessage(OrmResult result, pb::Message &message, bool recurse, OrmContextT *context)
{
	const pb::Descriptor *descriptor = message.GetDescriptor();
	for (int f=0; f<descriptor->field_count(); ++f) {
		const pb::FieldDescriptor*field = descriptor->field(f);
		if (field->is_repeated()) {
			if (recurse) {
				// recursively get the repeated fields.
				
				// the contents replaces what is already present.
				message.GetReflection()->ClearField(&message, field);
				
				pb::uint64 id;
				if (!OrmGetId(result, id))
					return false;
				
				OrmResult fieldres;
				if (!OrmFieldEnumAllRepeatedValues(RESULT.conn,
												   id,
												   field,
												   fieldres)
					)
					return false;
				
				for (bool ok=OrmFirst(fieldres); ok; ok=OrmNext(fieldres)) {
					if (!pb_add_repeated_field(fieldres, message, field, context))
						return false;
				}
				
				OrmFreeResult(fieldres);
			} else {
				// don't handle repeated fields when recurse is false
			}
		} else {
			if (!pb_assign_field(result, message, field, recurse, context))
				return false;
		}
		
	}
	return true;
}

bool OrmGetMessage(OrmResult result, pb::Message &message, bool recurse)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	return _OrmGetMessage(result,message,recurse,NULL);
}

bool OrmGetMessage(OrmResult result,
				   pb::Message &message,
				   bool recurse,
				   OrmContext &context)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	// Allocate the context required for updating the message in the table
	OrmContextT *ctx = new OrmContextT;
	if (!ctx) {
		OrmLogError("unable to allocate OrmContext");
		return false;
	}
	ctx->conn = RESULT.conn;
	ctx->message = &message;
	if (OrmGetId(result, ctx->id) && _OrmGetMessage(result, message, recurse, ctx)) {
		context = (OrmContext)ctx;
		return true;
	}

	delete ctx;
	context = NULL;
	return false;
}

bool OrmGetEnum(OrmResult result, std::string &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	const char *string = RESULT->get_string("value");
	if (string)
		value.assign(string);
	else
		value.clear();
	return !RESULT->failed();
}

bool OrmGetDateTime(OrmResult result, time_t &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	value = RESULT->get_datetime("value");
	return !RESULT->failed();
}

bool OrmGetDate(OrmResult result, time_t &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	value = RESULT->get_datetime("value");
	return !RESULT->failed();
}

bool OrmGetTime(OrmResult result, time_t &value)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	value = RESULT->get_datetime("value");
	return !RESULT->failed();
}
