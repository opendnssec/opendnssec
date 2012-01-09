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
//  pb-orm-str.cc
//  protobuf-orm
//

#include "pb-orm-str.h"
#include "pb-orm-log.h"
#include "pb-orm-database.h"

#include <stdio.h> 
#include <stdarg.h>

bool OrmFormat(std::string &dest, const char *format, ...)
{
	char buf[128];
    va_list args;
    va_start(args, format);
	int cneeded = vsnprintf(buf,sizeof(buf),format,args);
    va_end(args);
	if (cneeded<sizeof(buf)) {
		dest.assign(buf,cneeded);
		return true;
	}
	char *pbuf = new char[cneeded+1];
	if (!pbuf) {
		OrmLogError("out of memory");
		return false;
	}
    va_start(args, format);
	bool ok = vsnprintf(pbuf,cneeded+1,format,args)==cneeded;
    va_end(args);
	if (ok)
		dest.assign(pbuf,cneeded);
	else
		OrmLogError("vsnprintf error");
	delete[] pbuf;
	return ok;
}

const std::string &OrmChain(std::string &dest,
							const std::string &text,
							const char sep)
{
	size_t dsize = dest.size();
	if (dsize>0 && dest[dsize-1]!=sep)
		dest.push_back(sep);
	dest += text;
	return dest;
}

bool OrmQuoteStringValue(OrmConn conn,
						 const std::string &value,
						 std::string &dest)
{
	return CONN->quote_string(value,dest);
}
