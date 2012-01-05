/*
 * Created by René Post on 10/21/11.
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
//  pb-orm-create-table.cc
//  protobuf-orm
//

#include "pb-orm-create-table.h"
#include "pb-orm-value.h"
#include "pb-orm-str.h"
#include "pb-orm-log.h"
#include "pb-orm-database.h"
#include "orm.pb.h"

static const char * const
pb_type_to_orm_type[] =
{
	//0
	"",
	//1 double, exactly eight bytes on the wire. TYPE_DOUBLE
	"DOUBLE",
	//2 float, exactly four bytes on the wire. TYPE_FLOAT
	"FLOAT",
	//3 int64, varint on the wire. Negative numbers take 10 bytes.
	//	Use TYPE_SINT64 if negative values are likely. TYPE_INT64
	"BIGINT",
	//4 uint64, varint on the wire. TYPE_UINT64
	"BIGINT UNSIGNED",
	//5 int32, varint on the wire. Negative numbers take 10 bytes.
	//	Use TYPE_SINT32 if negative values are likely. TYPE_INT32
	"INT",
	//6 uint64, exactly eight bytes on the wire. TYPE_FIXED64
	"BIGINT UNSIGNED",
	//7 uint32, exactly four bytes on the wire. TYPE_FIXED32
	"INT UNSIGNED",
	//8 bool, varint on the wire. TYPE_BOOL
	"TINYINT UNSIGNED",
	//9 UTF-8 text. TYPE_STRING
	"VARCHAR(255)",
	//10 Tag-delimited message.  Deprecated. TYPE_GROUP
	"",
	//11 Length-delimited message. TYPE_MESSAGE
	"",
	//12 Arbitrary byte array. TYPE_BYTES
	"BLOB",
	//13 uint32, varint on the wire TYPE_UINT32
	"INT UNSIGNED",
	//14 Enum, varint on the wire TYPE_ENUM
	"ENUM",
	//15 int32, exactly four bytes on the wire TYPE_SFIXED32
	"INT",
	//16 int64, exactly eight bytes on the wire TYPE_SFIXED64
	"BIGINT",
	//17 int32, ZigZag-encoded varint on the wire TYPE_SINT32
	"INT",
	//18 int64, ZigZag-encoded varint on the wire TYPE_SINT64
	"BIGINT",
};


static
bool pb_field_default_value(OrmConn conn,
							const pb::FieldDescriptor *field,
							std::string &dest)
{
	if (field->is_repeated()) {
		OrmLogError("cannot create default string value for repeated field");
		return false;
	}

	orm::Column column;
	
	if (field->options().HasExtension(orm::column)) {
		column = field->options().GetExtension(orm::column);
	}
	
	if (column.has_type()) {
		switch (column.type()) {
			case orm::DATETIME:
			case orm::DATE:
			case orm::TIME: {
				if (!column.has_default_()) {
					OrmLogError("expected (orm).default value.");
					return false;
				}
				dest = "'" + column.default_() + "'";
				return true;
			}
			case orm::YEAR: {
				if (!column.has_default_()) {
					OrmLogError("expected (orm).default value.");
					return false;
				}
				dest = column.default_();
				return true;
			}
			default:
				OrmLogError("unknown (orm).type value.");
				return false;
		}
	}
	
	switch (field->type()) {
		case pb::FieldDescriptor::TYPE_BOOL:
			return pb_field_bool_value(field->default_value_bool(),dest);
		case pb::FieldDescriptor::TYPE_FLOAT:
			return pb_field_float_value(field->default_value_float(),dest);
		case pb::FieldDescriptor::TYPE_DOUBLE:
			return pb_field_double_value(field->default_value_double(),dest);
		case pb::FieldDescriptor::TYPE_INT32:
		case pb::FieldDescriptor::TYPE_SFIXED32:
		case pb::FieldDescriptor::TYPE_SINT32:
			return pb_field_int32_value(field->default_value_int32(),dest);
		case pb::FieldDescriptor::TYPE_INT64:
		case pb::FieldDescriptor::TYPE_SFIXED64:
		case pb::FieldDescriptor::TYPE_SINT64:
			return pb_field_int64_value(field->default_value_int64(),dest);
		case pb::FieldDescriptor::TYPE_UINT32:
		case pb::FieldDescriptor::TYPE_FIXED32:
			return pb_field_uint32_value(field->default_value_uint32(),dest);
		case pb::FieldDescriptor::TYPE_UINT64:
		case pb::FieldDescriptor::TYPE_FIXED64:
			return pb_field_uint64_value(field->default_value_uint64(),dest);
		case pb::FieldDescriptor::TYPE_STRING: {
			std::string strref = field->default_value_string();
			return pb_field_string_value(conn, strref, dest);
		}
		case pb::FieldDescriptor::TYPE_GROUP:
			OrmLogError("cannot create string value for TYPE_GROUP");
			return false;
		case pb::FieldDescriptor::TYPE_MESSAGE:
			OrmLogError("cannot create string value for TYPE_MESSAGE");
			return false;
		case pb::FieldDescriptor::TYPE_BYTES: {
			std::string binref = field->default_value_string();
			return pb_field_binary_value(conn, binref, dest);
		}
			
		case pb::FieldDescriptor::TYPE_ENUM:
			return OrmFormat(dest,"'%s'",
							  field->default_value_enum()->name().c_str());
	}
	OrmLogError("ERROR: UNKNOWN FIELD TYPE");
	return false;
}

static bool 
pb_field_to_orm_type(OrmConn conn,
					   const pb::FieldDescriptor *field,
					   std::string &orm_type)
{
	orm_type = std::string( pb_type_to_orm_type[field->type()] );
	bool has_default_value = false;

	// Allow column name and column type override.
	if (field->options().HasExtension(orm::column)) {
		const orm::Column column = field->options().GetExtension(orm::column);
		if (column.has_type()) {
			switch (column.type()) {
				case orm::DATETIME:
					orm_type = "DATETIME";
					break;
				case orm::DATE:
					orm_type = "DATE";
					break;
				case orm::TIME:
					orm_type = "TIME";
					break;
				case orm::YEAR:
					orm_type = "YEAR";
					break;
			}
		}
		has_default_value = column.has_default_();
	}

	// If the type was not valid, return with false.
	if (orm_type.size() == 0)
		return false;

	// Finish actual sql enum type by using the enum type description.
	if (field->type() == pb::FieldDescriptor::TYPE_ENUM) {
		bool bUseSqlEnums = false;
		if (bUseSqlEnums) {
			std::string typevals;
			for (int ev=0; ev<field->enum_type()->value_count();++ev) {
				const pb::EnumValueDescriptor*evd = 
					field->enum_type()->value(ev);
				if (typevals.size()>0)
					typevals += ", ";
				typevals += "'" + evd->name() + "'";
			}
			orm_type += "(" + typevals + ")";
		} else {
			size_t maxEnumValueLength = 0;
			for (int ev=0; ev<field->enum_type()->value_count();++ev) {
				const pb::EnumValueDescriptor*evd = 
					field->enum_type()->value(ev);
				if (evd->name().size() > maxEnumValueLength)
					maxEnumValueLength = evd->name().size();
			}
			OrmFormat(orm_type, "VARCHAR(%u)",maxEnumValueLength);
		}
	}

	// Add a default clause for fields that have a default value
	if ( has_default_value || field->has_default_value() ) {
		
		if (has_default_value && field->has_default_value()) {
			OrmLogError("Unable set 2 default values for field");
			return false;
		}
		
		std::string default_value;
		if (!pb_field_default_value(conn,field,default_value))
			return false;		
		
		orm_type += " DEFAULT " + default_value;
	}
	
	// Return a column name and type
	return true;
}

bool OrmCreateTable(OrmConn conn, const pb::Descriptor* descriptor)
{	
	// Create a table based on the meta information of a protocol buffer message

	if (CONN->table_exists(descriptor->name()))
		return true;

	std::string fields;
	for (int f=0; f<descriptor->field_count(); ++f) {
		const pb::FieldDescriptor *field = descriptor->field(f);
		if (field->is_repeated()) {
			std::string orm_name = descriptor->name()+ "_" + field->name();

			if (!CONN->table_exists(orm_name)) 
			{
				DB::OrmResultT result;
				if (field->type() != pb::FieldDescriptor::TYPE_MESSAGE) {
					std::string orm_type;
					if (!pb_field_to_orm_type(conn,field,orm_type))
						return false;
					result = CONN->CreateTableRepeatedValue(orm_name, orm_type);
				} else {
					result = CONN->CreateTableRelation(orm_name);
				}
				if (!result.assigned()) {
					OrmLogError("failed to create table: %s",orm_name.c_str());
					return false;
				}
			}

		} else {
			// required or optional
			
			std::string column_name;
			if (field->type() == pb::FieldDescriptor::TYPE_MESSAGE) {
				std::string name;
				pb_field_name(field,name);
				column_name = name + " INTEGER";
			} else {
				std::string name;
				pb_field_name(field,name);
				std::string orm_type;
				if (!pb_field_to_orm_type(conn,field,orm_type))
					return false;
				column_name = name + " " + orm_type;
			}
			
			if (field->is_required())
				OrmChain(fields, column_name + " NOT NULL", ',');
			else
				OrmChain(fields, column_name, ',');
		}
		if (field->type() == pb::FieldDescriptor::TYPE_MESSAGE) {
			if (!OrmCreateTable(conn, field->message_type()))
				return false;
		}
	}

	DB::OrmResultT result( CONN->CreateTableMessage(descriptor->name(), fields) );
	if (!result.assigned()) {
		OrmLogError("failed to create table: %s",descriptor->name().c_str());
		return false;
	}
	return true;
}
