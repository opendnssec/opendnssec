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
//  pb-orm-delete.cc
//  protobuf-orm
//

#include "pb-orm-read.h"
#include "pb-orm-delete.h"

#include "pb-orm-enum.h"

#include "pb-orm-log.h"
#include "pb-orm-database.h"

#include "orm.pb.h"

#include <stdio.h> 
#include <stdarg.h>

bool OrmMessageDelete(OrmConn conn,const pb::Descriptor *descriptor,pb::uint64 id)
{
	return OrmMessageDeleteWhere(conn,descriptor,"id=%llu",id);
}

bool OrmMessageDeleteWhere(OrmConn conn,
						   const pb::Descriptor *descriptor,
						   const char *format, va_list ap)
{
	// 256 bytes for where clause must be sufficient
	char where[256];
	int cneeded = vsnprintf(where,sizeof(where),format,ap);
	if (cneeded>=sizeof(where)) {
		OrmLogError("where clause overflow in OrmMessageDeleteWhere");
		return false;
	}

	// enumerate the ids of the messages that should be deleted
	DB::OrmResultT r( CONN->queryf("SELECT id FROM %s WHERE %s",
									descriptor->name().c_str(),where) );
	if (!r.assigned()) {
		OrmLogError("expected to be able to select from table: %s",
					descriptor->name().c_str());
		return false;
	}

	for (bool ok=r->first_row(); ok; ok=r->next_row()) {

		// Get the message id
		pb::uint64 id = r->get_ulonglong_idx(1);
		if (r->failed()) {
			OrmLogError("expected to be able to retrieve id from query result");
			return false;
		}
		
		if (id==0) {
			OrmLogError("retieved id contains invalid value zero (0)");
			return false;
		}
		
		// Go through all fields stored in separate tables and cascade delete them
		for (int f=0; f<descriptor->field_count(); ++f) {
			const pb::FieldDescriptor *field = descriptor->field(f);
			if (field->is_repeated()) {
				if (!OrmFieldDeleteAllRepeatedValues(conn,id,field))
					return false;
			} else {
				if (field->type() == pb::FieldDescriptor::TYPE_MESSAGE) {
					if (!OrmFieldDeleteMessage(conn, id, field))
						return false;
				} else {
					// nothing to do for a singular non message field
					// as it will be deleted along with the message.
				}
			}
		}
	}

	// Delete the actual messages in one go.
	DB::OrmResultT result( CONN->queryf("DELETE FROM %s WHERE %s",
										descriptor->name().c_str(),
										where) );
	if (!result.assigned()) {
		OrmLogError("failed to delete messages where \"%s\" from table: %s",
					where, descriptor->name().c_str());
		return false;
	}
	
	return true;
}


bool OrmMessageDeleteWhere(OrmConn conn,
						   const pb::Descriptor *descriptor,
						   const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	bool ok = OrmMessageDeleteWhere(conn, descriptor, format, ap);
	va_end(ap);
	return ok;
}

bool OrmFieldDeleteMessage(OrmConn conn,
						   pb::uint64 id,
						   const pb::FieldDescriptor *field)
{
	pb::uint64 childid;
	if (OrmFieldGetMessageId(conn,id,field,childid)) {
		return OrmMessageDelete(conn, field->message_type(), childid);
	}
	return true;
}

bool OrmFieldDeleteAllRepeatedValues(OrmConn conn,
									 pb::uint64 id,
									 const pb::FieldDescriptor *field)
{
	if (!field->is_repeated()) {
		OrmLogError("expected field to be repeated");
		return false;
	}

	if (field->type() == pb::FieldDescriptor::TYPE_MESSAGE) {
		std::string fld = field->containing_type()->name() + "_" + field->name();
		
		DB::OrmResultT result( CONN->queryf("SELECT child_id FROM %s WHERE parent_id=%llu",
											fld.c_str(),
											id) );
		if (!result.assigned()) {
			OrmLogError("failed select child ids with parent_id: %llu from table: %s",
					  id,fld.c_str());
			return false;
		}
		for (bool ok=result->first_row(); ok ;ok=result->next_row()) {
			pb::uint64 childid = result->get_ulonglong("child_id");
			if (result->failed()) {
				// Failed to retrieve the child_id field from the current row.
				// NOTE: error has already been reported by error handler.
				// We continue anyway to prevent other rows that actually
				// can be deleted from remaining in the tables.
			} else {
				if (childid == 0)
					OrmLogError("expected valid child_id, got zero");
				else {
					// childid is valid, so lets delete the message
					OrmMessageDelete(conn, field->message_type(), childid);
				}
			}
		}
	}
	
	std::string table = field->containing_type()->name() + "_" + field->name();
	DB::OrmResultT result( CONN->queryf("DELETE FROM %s WHERE parent_id=%llu",
										table.c_str(),
										id) );
	if (!result.assigned()) {
		OrmLogError("failed to delete all records with parent_id: %llu from table: %s",
				  id,
				  table.c_str());
		return false;
	}
	return true;
}

bool OrmFieldDeleteRepeatedValue(OrmConn conn,
								 const pb::FieldDescriptor *field,
								 pb::uint64 fieldid)
{
	if (!field->is_repeated()) {
		OrmLogError("expected field to be repeated");
		return false;
	}
		
	std::string table = field->containing_type()->name() + "_" + field->name();

	// Also delete the referenced message
	DB::OrmResultT result;
	if (field->type() == pb::FieldDescriptor::TYPE_MESSAGE) {
		if (!OrmMessageDelete(conn, field->message_type(), fieldid))
			return false;
		result = CONN->queryf("DELETE FROM %s WHERE child_id=%llu",
							  table.c_str(),
							  fieldid);
	} else {
		result = CONN->queryf("DELETE FROM %s WHERE id=%llu",
							  table.c_str(),
							  fieldid);
	}
	if (!result.assigned()) {
		OrmLogError("failed to delete record with child_id: %llu from table: %s",
				  fieldid,
				  table.c_str());
		return false;
	}
	return true;
}
