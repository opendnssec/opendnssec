/*
 * Created by René Post on 10/25/11.
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
 pb-orm-common.h
 protobuf-orm
 
 Contains common declarations and macros for protobuf-orm
 *****************************************************************************/

#ifndef pb_orm_common_h
#define pb_orm_common_h

#include "config.h"

//////////////////////////
// PROTOBUF
//////////////////////////

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

namespace pb = ::google::protobuf;


// Issue 119: Protocol Buffer TYPE_BOOL collides with MacOS macro TYPE_BOOL
#ifdef TYPE_BOOL
#undef TYPE_BOOL
#endif


//////////////////////////
// OPAQUE POINTERS
//////////////////////////

// Opaque handle type that contains information about the database
// connection including the actual type of the database being used.
typedef struct OrmConnT *OrmConn;

// Opaque handle type that contains information about the database
// result
typedef struct OrmResultT *OrmResult;

// Opaque type that contains the information from a call to OrmMessageRead 
// that is needed for subsequently updating the same messsage in the db.
typedef struct OrmContextT *OrmContext;

#endif
