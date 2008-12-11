/* $Id$ */

/*
 * Copyright (c) 2008 .SE (The Internet Infrastructure Foundation).
 * All rights reserved.
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

/************************************************************
*
* This class defines an object, which contains
* a crypto key, private or public.
*
* It also points to the next object in the chain.
*
* A new object is added by prepending it to the chain.
*
************************************************************/

#ifndef SOFTHSM_SOFTOBJECT_H
#define SOFTHSM_SOFTOBJECT_H 1

class SoftObject {
  public:
    SoftObject();
    ~SoftObject();

    CK_RV addAttributeFromData(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG ulValueLen);
    CK_RV getAttribute(CK_ATTRIBUTE *attTemplate);
    CK_BBOOL matchAttribute(CK_ATTRIBUTE *attTemplate);

    SoftObject* getObject(int searchIndex);
    CK_RV deleteObj(int searchIndex);
    SoftObject *nextObject;
    int index;

    CK_OBJECT_CLASS objectClass;
    CK_KEY_TYPE keyType;
    CK_ULONG keySizeBytes;

    Public_Key *key;

    SoftAttribute *attributes;
};

#endif /* SOFTHSM_SOFTOBJECT_H */
