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

//
//  pb-orm-transaction.cc
//  protobuf-orm
//

#include "pb-orm-transaction.h"
#include "pb-orm-database.h"
#include "pb-orm-log.h"

OrmTransactionBase::OrmTransactionBase(OrmConn conn_) : conn(conn_)
{
}

OrmTransactionBase::~OrmTransactionBase()
{
	rollback();
}

bool OrmTransactionBase::started()
{
	return conn != NULL;
}

bool OrmTransactionBase::commit()
{
	if (!conn)
		return false;

	// try to commit
	if (CONN->commit_transaction()) {
		// commit succeeded
		conn = NULL;
		return true;
	}
		
	// commit failed, are we still inside a transaction ?
	if (CONN->in_transaction())
		return false; // leave conn assigned so commit can be retried.

	// Oh oh, no longer inside a transaction, so no point in calling commit again.
	OrmLogError("error caused premature termination of transaction");
	conn = NULL;
	return false;
}

void OrmTransactionBase::rollback()
{
	if (conn) {
		CONN->rollback_transaction();
		conn = NULL;
	}
}

OrmTransaction::OrmTransaction(OrmConn conn_) : OrmTransactionBase(conn_)
{
	if (conn) {
		if (!CONN->begin_transaction())
			conn = NULL;
	}
	
}

OrmTransactionRW::OrmTransactionRW(OrmConn conn_) : OrmTransactionBase(conn_)
{
	if (conn) {
		if (!CONN->begin_transaction_rw())
			conn = NULL;
	}
}
