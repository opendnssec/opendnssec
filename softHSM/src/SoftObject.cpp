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
************************************************************/

#include "main.h"

SoftObject::SoftObject() {
  attributes = new SoftAttribute();
}

SoftObject::~SoftObject() {
  if(attributes != NULL_PTR) {
    delete attributes;
    attributes = NULL_PTR;
  }
}

// Create an attribute with given data and assign to object

CK_RV SoftObject::addAttributeFromData(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG ulValueLen) {
  CK_ATTRIBUTE *oAttribute = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));

  if(!oAttribute) {
    return CKR_DEVICE_MEMORY;
  }

  oAttribute->pValue = malloc(ulValueLen);

  if(!oAttribute->pValue) {
    free(oAttribute);
    return CKR_DEVICE_MEMORY;
  }

  oAttribute->type = type;
  memcpy(oAttribute->pValue, pValue, ulValueLen);
  oAttribute->ulValueLen = ulValueLen;

  attributes->addAttribute(oAttribute);

  return CKR_OK;
}

// Get the attribute value for the object.

CK_RV SoftObject::getAttribute(CK_ATTRIBUTE *attTemplate) {
  CK_ATTRIBUTE *localAttribute = attributes->getAttribute(attTemplate->type);

  if(localAttribute == NULL_PTR) {
    attTemplate->ulValueLen = (CK_LONG)-1;
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  if(attTemplate->pValue == NULL_PTR) {
    attTemplate->ulValueLen = localAttribute->ulValueLen;
  } else if(attTemplate->ulValueLen < localAttribute->ulValueLen) {
    attTemplate->ulValueLen = (CK_LONG)-1;
    return CKR_BUFFER_TOO_SMALL;
  } else {
    memcpy(attTemplate->pValue, localAttribute->pValue, localAttribute->ulValueLen);
    attTemplate->ulValueLen = localAttribute->ulValueLen;
  }

  return CKR_OK;
}

CK_BBOOL SoftObject::matchAttribute(CK_ATTRIBUTE *attTemplate) {
  return attributes->matchAttribute(attTemplate);
}
