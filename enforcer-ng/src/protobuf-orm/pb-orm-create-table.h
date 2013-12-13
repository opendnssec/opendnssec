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
//  pb-orm-create-table.h
//  protobuf-orm
//

#ifndef pb_orm_create_table_h
#define pb_orm_create_table_h

#include "pb-orm-common.h"

/*
 
Repeated Values
---------------
A protobuf field that is declared as 'repeated' may contain zero or more values.

 
Required Values
--------------- 
A protobuf field that contains a single value can be either be declared as 
required or optional. This maps nicely to the SQL concept of nullable values.
So either a field has a value or it doesn't. When it does have a value that
should be of the type defined for the field.

 
Default Values
-------------
Both protobuf message field declarations and SQL Column declarations support
the notion of a default value. There is a subtle difference between the two
implementations though when the column is optional 

 */

bool OrmCreateTable(OrmConn conn, const pb::Descriptor* descriptor);

#endif
