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
//  pb-orm-enum.cc
//  protobuf-orm
//

#include "pb-orm-enum.h"
#include "pb-orm-value.h"
#include "pb-orm-log.h"
#include "pb-orm-database.h"

#include <stdio.h> 
#include <stdarg.h>

bool OrmConnQuery(OrmConn conn,
				  const std::string &statement,
				  OrmResult &result)
{
	return CONN->query(statement.c_str(),(int)statement.size()).new_handle(result);
}

bool OrmMessageFind(OrmConn conn,
					const pb::Descriptor *descriptor,
					pb::uint64 id)
{
	DB::OrmResultT r( CONN->queryf("SELECT id FROM %s WHERE id=%llu",
								   descriptor->name().c_str(),
								   id) );
	if (!r.assigned()) {
		OrmLogError("failed select from table: %s",descriptor->name().c_str());
		return false;
	}
	// Query should be able to select the first row.
	return r->first_row();
}

bool OrmMessageSelect(OrmConn conn,
					  const pb::Descriptor *descriptor,
					  pb::uint64 id,
					  OrmResult &result)
{
	DB::OrmResultT r( CONN->queryf("SELECT * FROM %s WHERE id=%llu",
							   descriptor->name().c_str(),
							   id) );
	if (!r.assigned()) {
		OrmLogError("failed select from table: %s",descriptor->name().c_str());
		return false;
	}
	if (!r->first_row()) {
		OrmLogError("expected to be able to select the first record in table: %s",
				  descriptor->name().c_str());
		return false;
	}
	return r.new_handle(result);
}

bool OrmMessageEnum(OrmConn conn,
					const pb::Descriptor *descriptor,
					OrmResult &result)
{
	DB::OrmResultT r( CONN->queryf("SELECT * FROM %s",
							   descriptor->name().c_str()) );
	if (!r.assigned()) {
		OrmLogError("expected to be able to select from table: %s",
			  descriptor->name().c_str());
		return false;
	}
	return r.new_handle(result);
}

bool OrmMessageEnumWhere(OrmConn conn,
						 const pb::Descriptor *descriptor,
						 OrmResult &result,
						 const char *format,
						 va_list ap)
{
	char where[256];
	int cneeded = vsnprintf(where,sizeof(where),format,ap);
	if (cneeded >= sizeof(where)) {
		OrmLogError("where clause overflow in OrmMessageEnumWhere");
		return false;
	}
	
	DB::OrmResultT r( CONN->queryf("SELECT * FROM %s WHERE %s",
									 descriptor->name().c_str(),where) );
	if (!r.assigned()) {
		OrmLogError("expected to be able to select from table: %s",
					descriptor->name().c_str());
		return false;
	}
	return r.new_handle(result);
}

bool OrmMessageEnumWhere(OrmConn conn,
						 const pb::Descriptor *descriptor,
						 OrmResult &result,
						 const char *format,
						 ...)
{
	va_list ap;
	va_start(ap, format);
	bool ok =OrmMessageEnumWhere(conn,descriptor,result,format,ap);
	va_end(ap);
	return ok;
}
						
bool OrmMessageCount(OrmConn conn,
					 const pb::Descriptor *descriptor,
					 pb::uint64 &count)
{
	DB::OrmResultT r( CONN->queryf("SELECT count(1) FROM %s",
								   descriptor->name().c_str()) );
	if (!r.assigned()) {
		OrmLogError("failed select from table: %s",descriptor->name().c_str());
		return false;
	}
	if (!r->first_row()) {
		OrmLogError("failed to select the first record in table: %s",
					descriptor->name().c_str());
		return false;
	}
	count = r->get_ulonglong_idx(1);
	if (r->failed()) {
		OrmLogError("expected to be able to retrieve count from query result");
		return false;
	}
	return true;
}

bool OrmMessageCountWhere(OrmConn conn,
						  const pb::Descriptor *descriptor,
						  pb::uint64 &count,
						  const char *format,
						  va_list ap)
{
	char where[256];
	int cneeded = vsnprintf(where,sizeof(where),format,ap);
	if (cneeded >= sizeof(where)) {
		OrmLogError("where clause overflow in OrmMessageEnumWhere");
		return false;
	}
	
	DB::OrmResultT r( CONN->queryf("SELECT count(1) FROM %s WHERE %s",
								   descriptor->name().c_str(),where) );
	if (!r.assigned()) {
		OrmLogError("failed select from table: %s",descriptor->name().c_str());
		return false;
	}
	if (!r->first_row()) {
		OrmLogError("failed to select the first record in table: %s",
					descriptor->name().c_str());
		return false;
	}
	count = r->get_ulonglong_idx(1);
	if (r->failed()) {
		OrmLogError("expected to be able to retrieve count from query result");
		return false;
	}

	return true;
}

bool OrmMessageCountWhere(OrmConn conn,
						  const pb::Descriptor *descriptor,
						  pb::uint64 &count,
						  const char *format,
						  ...)
{
	va_list ap;
	va_start(ap, format);
	bool ok =OrmMessageCountWhere(conn,descriptor,count,format,ap);
	va_end(ap);
	return ok;
	
}

bool OrmFieldSelectMessage(OrmConn conn,
						   pb::uint64 id,
						   const pb::FieldDescriptor* field,
						   OrmResult &result)
{
	result = NULL;
	
	if (field->is_repeated()) {
		OrmLogError("expected singular field");
		return false;
	}
	if (field->type()!=pb::FieldDescriptor::TYPE_MESSAGE) {
		OrmLogError("expected field with type message");
		return false;
	}

	// Get field name, may have been renamed by option.
	std::string field_name;
	pb_field_name(field,field_name);

	// Single field; containing table stores id for the field's message table
	DB::OrmResultT r( CONN->queryf("SELECT %s FROM %s WHERE id=%llu",
							   field_name.c_str(),
							   field->containing_type()->name().c_str(),
							   id) );
	if (!r.assigned()) {
		OrmLogError("expected to be able to select a message");
		return false;
	}

	if (!r->first_row()) {
		OrmLogError("expected to be able to select the first row");
		return false;
	}
	
	// Get the fieldid
	pb::uint64 fieldid = r->get_ulonglong_idx(1);
	if (r->failed()) {
		OrmLogError("expected to be able to retrieve field from database result");
		return false;
	}

	if (fieldid==0)
		return false;
	
	r = CONN->queryf("SELECT * FROM %s WHERE id=%llu",
					 field->message_type()->name().c_str(),
					 fieldid);
	if (!r.assigned()) {
		OrmLogError("expected to be able to select message");
		return false;
	}
	
	if (!r->first_row()) {
		OrmLogError("expected to be able to select the first row");
		return false;
	}

	return r.new_handle(result);
}

bool OrmFieldEnumAllRepeatedValues(OrmConn conn,
							   pb::uint64 id,
							   const pb::FieldDescriptor* field,
							   OrmResult &result)
{
	if (!field->is_repeated()) {
		OrmLogError("expected field to be repeated");
		return false;
	}

	std::string fld = field->containing_type()->name() + "_" + field->name();
	
	DB::OrmResultT r;
	if (field->type() == pb::FieldDescriptor::TYPE_MESSAGE) {
		std::string msg = field->message_type()->name();
		// Repeated field; containing table id is stored in child table as parent_id
		// We need to join the table for the field relation with the table for the
		// field value message type.
		r = CONN->queryf("SELECT msg.*"
						 " FROM %s msg INNER JOIN %s fld ON msg.id=fld.child_id"
						 " WHERE fld.parent_id=%llu",
						 msg.c_str(),
						 fld.c_str(),id);
	} else {
		// Repeated field; containing table id is stored in child table as parent_id
		r = CONN->queryf("SELECT fld.*"
						 " FROM %s fld"
						 " WHERE fld.parent_id=%llu",
						 fld.c_str(),
						 id);
	}
	if (!r.assigned()) {
		OrmLogError("expected to be able to enumerate values");
		return false;
	}
	return r.new_handle(result);
}

bool OrmGetSize(OrmResult result, pb::uint64 &size)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	return RESULT->get_numrows((unsigned long long &)size);
}

bool OrmFirst(OrmResult result)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	return RESULT->first_row();
}

bool OrmNext(OrmResult result)
{
	if (result==NULL || !RESULT.assigned())
		return false;
	return RESULT->next_row();
}

void OrmFreeResult(OrmResult result)
{
	if (result)
		delete (DB::OrmResultT*)result;
}
