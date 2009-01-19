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

#include "SoftObject.h"
#include "SoftDatabase.h"

#include <stdlib.h>

SoftObject::SoftObject() {
  nextObject = NULL_PTR;
  index = CK_INVALID_HANDLE;

  objectClass = CKO_VENDOR_DEFINED;
  keyType = CKK_VENDOR_DEFINED;
  keySizeBytes = 0;
  sensible = CK_TRUE;
  extractable = CK_FALSE;
  modifiable = CK_FALSE;
  attributes = new SoftAttribute();
}

SoftObject::~SoftObject() {
  if(attributes != NULL_PTR) {
    delete attributes;
    attributes = NULL_PTR;
  }

  if(nextObject != NULL_PTR) {
    delete nextObject;
    nextObject = NULL_PTR;
  }
}

// Return the object with the given index.

SoftObject* SoftObject::getObject(int searchIndex) {
  if(nextObject == NULL_PTR) {
    return NULL_PTR;
  } else {
    if(searchIndex == index) {
      return this;
    } else {
      return nextObject->getObject(searchIndex);
    }
  }
}

// Delete the content of the object with given index
// and replace it with the content of the
// next object. Thus collapsing this link
// in the chain.

CK_RV SoftObject::deleteObj(int searchIndex) {
  if(nextObject == NULL_PTR) {
    return CKR_OBJECT_HANDLE_INVALID;
  } else {
    if(searchIndex == index) {
      if(attributes != NULL_PTR) {
        delete attributes;
      }

      // Get the content of the next object
      attributes = nextObject->attributes;
      index = nextObject->index;
      objectClass = nextObject->objectClass;
      keyType = nextObject->keyType;
      keySizeBytes = nextObject->keySizeBytes;
      sensible = nextObject->sensible;
      extractable = nextObject->extractable;
      modifiable = nextObject->modifiable;
      SoftObject *tmpPtr = nextObject->nextObject;

      // Clear and delete the next container
      nextObject->attributes = NULL_PTR;
      nextObject->nextObject = NULL_PTR;
      delete nextObject;

      // Reconnect with the tail.
      nextObject = tmpPtr;

      return CKR_OK;
    } else {
      return nextObject->deleteObj(searchIndex);
    }
  }
}

// Create an attribute with given data and assign to this object

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

// Get the value of an attribute for this object.

CK_RV SoftObject::getAttribute(CK_ATTRIBUTE *attTemplate) {
  CK_ATTRIBUTE *localAttribute = attributes->getAttribute(attTemplate->type);

  // Can we reveal this attribute?
  switch(attTemplate->type) {
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
      if(sensible == CK_TRUE || extractable == CK_FALSE) {
        attTemplate->ulValueLen = (CK_LONG)-1;
        return CKR_ATTRIBUTE_SENSITIVE;
      }
      break;
    default:
      break;
  }

  // Do we have this attribute?
  if(localAttribute == NULL_PTR) {
    attTemplate->ulValueLen = (CK_LONG)-1;
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  // Do the user want the size of the attribute value?
  if(attTemplate->pValue == NULL_PTR) {
    attTemplate->ulValueLen = localAttribute->ulValueLen;
  // Is the given buffer to small?
  } else if(attTemplate->ulValueLen < localAttribute->ulValueLen) {
    attTemplate->ulValueLen = (CK_LONG)-1;
    return CKR_BUFFER_TOO_SMALL;
  // Return the attribute
  } else {
    memcpy(attTemplate->pValue, localAttribute->pValue, localAttribute->ulValueLen);
    attTemplate->ulValueLen = localAttribute->ulValueLen;
  }

  return CKR_OK;
}

// Returns a big int of a given attribute.
// We reveal anything, because this is used to create a key within the SoftHSM.

BigInt* SoftObject::getBigIntAttribute(CK_ATTRIBUTE_TYPE type) {
  CK_ATTRIBUTE *localAttribute = attributes->getAttribute(type);

  // Do we have this attribute?
  if(localAttribute == NULL_PTR) {
    return NULL_PTR;
  }

  return new BigInt((byte *)localAttribute->pValue, (u32bit)localAttribute->ulValueLen);
}

// Set the value of an attribute for this object.
// This function also performes a sanity check of the template

CK_RV SoftObject::setAttribute(CK_ATTRIBUTE *attTemplate, SoftDatabase *db) {
  // Can we modify the object?
  if(modifiable == CK_FALSE) {
    return CKR_ATTRIBUTE_READ_ONLY;
  }

  // Evaluate the template
  switch(attTemplate->type) {
    case CKA_CLASS:
    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_MODIFIABLE:
    case CKA_KEY_TYPE:
    case CKA_LOCAL:
    case CKA_KEY_GEN_MECHANISM:
      // We can not change this attribute
      return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_LABEL:
    case CKA_ID:
    case CKA_SUBJECT:
      // We can change
      break;
    case CKA_DERIVE:
      // We can change, but check size
      if(attTemplate->ulValueLen != sizeof(CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
    case CKA_WRAP:
      // We can change this for the public key
      // but invalid for other object classes
      if(objectClass != CKO_PUBLIC_KEY) {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      // Check size
      if(attTemplate->ulValueLen != sizeof(CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;
    case CKA_TRUSTED:
      // We can not set this for the public key
      if(objectClass == CKO_PUBLIC_KEY) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Invalid for other object classes
      return CKR_ATTRIBUTE_TYPE_INVALID;
    case CKA_DECRYPT:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_UNWRAP:
      // We can change this for the private key
      // but invalid for other object classes
      if(objectClass != CKO_PRIVATE_KEY) {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      // Check size
      if(attTemplate->ulValueLen != sizeof(CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;
    case CKA_ALWAYS_SENSITIVE:
    case CKA_NEVER_EXTRACTABLE:
    case CKA_ALWAYS_AUTHENTICATE:
    case CKA_WRAP_WITH_TRUSTED:
      // We can not set this for the private key
      if(objectClass == CKO_PRIVATE_KEY) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Invalid for other object classes
      return CKR_ATTRIBUTE_TYPE_INVALID;
    case CKA_SENSITIVE:
      // Attribute cannot be changed once set to CK_TRUE.
      if(sensible == CK_TRUE) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Check size
      if(attTemplate->ulValueLen != sizeof(CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      // The object has been non-sensitive
      addAttributeFromData(CKA_ALWAYS_SENSITIVE, &sensible, sizeof(sensible));
      // Save in database
      db->saveAttribute(index, CKA_ALWAYS_SENSITIVE, &sensible, sizeof(sensible));
      // Update internal variable
      sensible = *(CK_BBOOL*)attTemplate->pValue;
      break;
    case CKA_EXTRACTABLE:
      // Attribute cannot be changed once set to CK_FALSE.
      if(extractable == CK_FALSE) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Check size
      if(attTemplate->ulValueLen != sizeof(CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      // The object has be extractable
      addAttributeFromData(CKA_NEVER_EXTRACTABLE, &extractable, sizeof(extractable));
      // Save in database
      db->saveAttribute(index, CKA_NEVER_EXTRACTABLE, &extractable, sizeof(extractable));
      // Update internal variable
      extractable = *(CK_BBOOL*)attTemplate->pValue;
      break;
    case CKA_MODULUS_BITS:
      // We can not set this for the public rsa key
      if(objectClass == CKO_PUBLIC_KEY && keyType == CKK_RSA) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Invalid for other object classes
      return CKR_ATTRIBUTE_TYPE_INVALID;
    case CKA_PUBLIC_EXPONENT:
    case CKA_MODULUS:
      // We can not set this for the RSA key
      if(keyType == CKK_RSA) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Invalid for other objects
      return CKR_ATTRIBUTE_TYPE_INVALID;
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
      // We can not set this for the private RSA key
      if(objectClass == CKO_PRIVATE_KEY && keyType == CKK_RSA) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Invalid for other objects
      return CKR_ATTRIBUTE_TYPE_INVALID;
    default:
      // Invalid attribute
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  // Save/update the object attribute
  addAttributeFromData(attTemplate->type, attTemplate->pValue, attTemplate->ulValueLen);
  // Save/update in the database
  db->saveAttribute(index, attTemplate->type, attTemplate->pValue, attTemplate->ulValueLen);

  return CKR_OK;
}

// Does this object have a matching attribute?

CK_BBOOL SoftObject::matchAttribute(CK_ATTRIBUTE *attTemplate) {
  return attributes->matchAttribute(attTemplate);
}
