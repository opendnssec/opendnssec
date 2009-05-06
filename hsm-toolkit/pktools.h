/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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
 *
 */

#ifndef PKTOOLS_H
#define PKTOOLS_H 1

#include <pkcs11.h>

void InitAttributes(CK_ATTRIBUTE_PTR attr, unsigned int n);
void AddAttribute(CK_ATTRIBUTE_PTR attr, int type, const void *Value, size_t size);
void FlushAttributes(CK_ATTRIBUTE_PTR attr, unsigned int n);

const void* Get_Val(CK_ATTRIBUTE_PTR attr,unsigned type,unsigned int n);
CK_ULONG Get_Val_ul(CK_ATTRIBUTE_PTR attr,unsigned type,unsigned int n);
unsigned int Get_Val_Len(CK_ATTRIBUTE_PTR attr,unsigned int type,unsigned int n);
const char* get_rv_str(CK_RV rv);
void check_rv (const char *message,CK_RV rv);
CK_ULONG LabelExists(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label);
CK_ULONG IDExists(CK_SESSION_HANDLE ses, uuid_t uu);
CK_SLOT_ID GetSlot();
void bin2hex (int len, unsigned char *binnum, char *hexnum);

#endif /* PKTOOLS_H */
