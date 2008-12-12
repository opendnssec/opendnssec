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
* This class handles an object's attributes.
* It creates a chain of object attributes.
*
************************************************************/

#include "SoftAttribute.h"

// Standard includes
#include <stdlib.h>
#include <string>

SoftAttribute::SoftAttribute() {
  next = NULL_PTR;
  objectAttribute = NULL_PTR;
}

SoftAttribute::~SoftAttribute() {
  if(next != NULL_PTR) {
    delete next;
    next = NULL_PTR;
  }
  if(objectAttribute != NULL_PTR) {
    if(objectAttribute->pValue != NULL_PTR) {
      free(objectAttribute->pValue);
      objectAttribute->pValue = NULL_PTR;
    }
    free(objectAttribute);
    objectAttribute = NULL_PTR;
  }
}

// Add the attribute if we are the last one in the chain.
// Or else pass it on the next one.

void SoftAttribute::addAttribute(CK_ATTRIBUTE *oAttribute) {
  if(next == NULL_PTR) {
    objectAttribute = oAttribute;
    next = new SoftAttribute();
  } else {
    next->addAttribute(oAttribute);
  }
}

// Search after a given attribute type.

CK_ATTRIBUTE* SoftAttribute::getAttribute(CK_ATTRIBUTE_TYPE type) {
  if(next != NULL_PTR) {
    if(objectAttribute != NULL_PTR && objectAttribute->type == type) {
      return objectAttribute;
    } else {
      return next->getAttribute(type);
    }
  } else {
    return NULL_PTR;
  }
}

CK_BBOOL SoftAttribute::matchAttribute(CK_ATTRIBUTE *attTemplate) {
  if(next != NULL_PTR) {
    if(objectAttribute->type == attTemplate->type &&
       objectAttribute->ulValueLen == attTemplate->ulValueLen &&
       memcmp(objectAttribute->pValue, attTemplate->pValue, 
         objectAttribute->ulValueLen) == 0) {
      return CK_TRUE;
    } else {
      return next->matchAttribute(attTemplate);
    }
  } else {
    return CK_FALSE;
  }
}
