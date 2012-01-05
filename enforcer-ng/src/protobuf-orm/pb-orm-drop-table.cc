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

//
//  pb-orm-drop-table.cc
//  protobuf-orm
//

#include "pb-orm-drop-table.h"
#include "pb-orm-value.h"
#include "pb-orm-log.h"
#include "pb-orm-database.h"

bool OrmDropTable(OrmConn conn,const pb::Descriptor* descriptor)
{
	if (!CONN->table_exists(descriptor->name()))
		return true; // if it doesn't exist, the table must have been dropped already.
	
	bool ok = true;
	
	// drop table for the message
	{
		DB::OrmResultT result( CONN->queryf("DROP TABLE %s",
											descriptor->name().c_str()) );
		if (!result.assigned()) {
			OrmLogError("failed to drop table: %s",descriptor->name().c_str());
			ok = false;
		}
	}
	
	// drop all tables created for fields of the message
	for (int f=0; f<descriptor->field_count(); ++f) {
		const pb::FieldDescriptor *field = descriptor->field(f);
		// drop tables that implement repeated behavior
		if (field->is_repeated()) {
			std::string table_name;
			table_name = field->containing_type()->name() + "_" + field->name();
			if (CONN->table_exists(table_name)) {
				DB::OrmResultT result( CONN->queryf("DROP TABLE %s",
													table_name.c_str()) );
				if (!result.assigned()) {
					OrmLogError("failed to drop table: %s",table_name.c_str());
					ok = false;
				}
			}
		}
		// drop associated message tables
		if (field->type() == pb::FieldDescriptor::TYPE_MESSAGE) {
			if (!OrmDropTable(conn, descriptor->field(f)->message_type())) {
				ok = false;
			}
		}
	}

	return ok;
}
