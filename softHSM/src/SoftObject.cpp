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
  key = NULL_PTR;
  objectClass = CKO_PUBLIC_KEY;
  keyType = CKK_RSA;
  fileName = NULL_PTR;
  attributes = new SoftAttribute();
}

SoftObject::~SoftObject() {
  if(key != NULL_PTR && objectClass == CKO_PRIVATE_KEY) {
    delete key;
    key = NULL_PTR;
  }
  key = NULL_PTR;

  if(fileName != NULL_PTR) {
    free(fileName);
    fileName = NULL_PTR;
  }

  if(attributes != NULL_PTR) {
    delete attributes;
    attributes = NULL_PTR;
  }
}

// Adds a key to the object.

CK_RV SoftObject::addKey(Private_Key *inKey, CK_OBJECT_CLASS oClass, char *pName) {
  if(pName == NULL_PTR || inKey == NULL_PTR) {
    return CKR_GENERAL_ERROR;
  }

  const char *algoName = (dynamic_cast<Public_Key*>(inKey))->algo_name().c_str();

  if(!strcmp(algoName, "RSA")) {
    keyType = CKK_RSA;
  } else {
    return CKR_GENERAL_ERROR;
  }

  key = inKey;
  objectClass = oClass;

  int strLength = strlen(pName);
  fileName = (char *)malloc(strLength+1);
  memset(fileName,0,strLength+1);
  strncpy(fileName, pName, strLength);

  CK_BBOOL oTrue = CK_TRUE;
  CK_BBOOL oFalse = CK_FALSE;

  this->addAttributeFromData(CKA_CLASS, &objectClass, sizeof(objectClass));
  this->addAttributeFromData(CKA_KEY_TYPE, &keyType, sizeof(keyType));
  this->addAttributeFromData(CKA_LABEL, fileName, strLength);
  this->addAttributeFromData(CKA_ID, fileName, strLength);
  this->addAttributeFromData(CKA_LOCAL, &oTrue, sizeof(oTrue));
  this->addAttributeFromData(CKA_PRIVATE, &oTrue, sizeof(oTrue));
  this->addAttributeFromData(CKA_TOKEN, &oTrue, sizeof(oTrue));
  this->addAttributeFromData(CKA_WRAP, &oFalse, sizeof(oFalse));
  this->addAttributeFromData(CKA_UNWRAP, &oFalse, sizeof(oFalse));
  this->addAttributeFromData(CKA_MODIFIABLE, &oFalse, sizeof(oFalse));
  this->addAttributeFromData(CKA_DERIVE, &oFalse, sizeof(oFalse));
  this->addAttributeFromData(CKA_VERIFY_RECOVER, &oFalse, sizeof(oFalse));
  this->addAttributeFromData(CKA_SIGN_RECOVER, &oFalse, sizeof(oFalse));

  if(objectClass == CKO_PRIVATE_KEY) {
    this->addAttributeFromData(CKA_ENCRYPT, &oFalse, sizeof(oFalse));
    this->addAttributeFromData(CKA_VERIFY, &oFalse, sizeof(oFalse));
    this->addAttributeFromData(CKA_DECRYPT, &oTrue, sizeof(oTrue));
    this->addAttributeFromData(CKA_SIGN, &oTrue, sizeof(oTrue));
    this->addAttributeFromData(CKA_SENSITIVE, &oTrue, sizeof(oTrue));
  } else {
    this->addAttributeFromData(CKA_ENCRYPT, &oTrue, sizeof(oTrue));
    this->addAttributeFromData(CKA_VERIFY, &oTrue, sizeof(oTrue));
    this->addAttributeFromData(CKA_DECRYPT, &oFalse, sizeof(oFalse));
    this->addAttributeFromData(CKA_SIGN, &oFalse, sizeof(oFalse));
    this->addAttributeFromData(CKA_SENSITIVE, &oFalse, sizeof(oFalse));
  }

  if(keyType == CKK_RSA) {
    // Key generation mechanism.
    CK_MECHANISM_TYPE mech = CKM_RSA_PKCS_KEY_PAIR_GEN;
    this->addAttributeFromData(CKA_KEY_GEN_MECHANISM, &mech, sizeof(mech));

    // The RSA modulus bits
    IF_Scheme_PublicKey *ifKey = dynamic_cast<IF_Scheme_PublicKey*>(key);
    BigInt bigModulus = ifKey->get_n();
    int bits = bigModulus.bits();
    keySizeBytes = (bits + 7) / 8;
    unsigned int modulusSize = bigModulus.bytes();
    this->addAttributeFromData(CKA_MODULUS_BITS, &bits, sizeof(bits));

    // The RSA modulus
    char *modulusBuf = (char *)malloc(modulusSize);
    for(unsigned int i = 0; i < modulusSize; i++) {
      modulusBuf[i] = bigModulus.byte_at(i);
    }
    this->addAttributeFromData(CKA_MODULUS, modulusBuf, sizeof(modulusSize));
    free(modulusBuf);

    // The RSA public exponent.
    BigInt bigExponent = ifKey->get_e();
    unsigned int exponentSize = bigModulus.bytes();
    char *exponentBuf = (char *)malloc(exponentSize);
    for(unsigned int i = 0; i < exponentSize; i++) {
      exponentBuf[i] = bigExponent.byte_at(i);
    }
    this->addAttributeFromData(CKA_PUBLIC_EXPONENT, exponentBuf, sizeof(exponentSize));
    free(exponentBuf);

/*
    // How should the CKA_VALUE be formated????
    // 1 and 2 results in the same values.
    // RAW_BER can be exchange for PEM for PEM encoding.
    // ans1parse understands the content, but not d2i_PublicKey.
    // d2i_PublicKey is used in pkcs11-tool

// 1:
    X509_Encoder *encoder = ifKey->x509_encoder();
    MemoryVector<byte> der =
            DER_Encoder()
              .start_cons(SEQUENCE)
                .encode(encoder->alg_id())
                .encode(encoder->key_bits(), BIT_STRING)
              .end_cons()
            .get_contents();

// 2:
    Pipe berPipe;
    berPipe.start_msg();
    X509::encode(*dynamic_cast<Public_Key*>(key), berPipe, RAW_BER);
    berPipe.end_msg();
    SecureVector<byte> berMsg = berPipe.read_all();

    this->addAttributeFromData(CKA_VALUE, berMsg.begin(), berMsg.size());
*/
  }

  return CKR_OK;
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

// Saves the key to the disk.
// But only if it is a private key.

CK_RV SoftObject::saveKey(SoftHSMInternal *pSoftH) {
  if(objectClass == CKO_PRIVATE_KEY) {
    if(!saveKeyFile(pSoftH, fileName, key)) {
      return CKR_GENERAL_ERROR;
    }
  }

  return CKR_OK;
}

// Removes the key file from the disk.

CK_RV SoftObject::removeFile(SoftHSMInternal *pSoftH) {
  if(objectClass == CKO_PRIVATE_KEY) {
    if(!removeKeyFile(pSoftH, fileName)) {
      return CKR_GENERAL_ERROR;
    }
  }

  return CKR_OK;
}

CK_OBJECT_CLASS SoftObject::getObjectClass() {
  return objectClass;
}

CK_KEY_TYPE SoftObject::getKeyType() {
  return keyType;
}

Private_Key* SoftObject::getKey() {
  return key;
}

char* SoftObject::getFileName() {
  return fileName;
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

int SoftObject::getKeySizeBytes() {
  return keySizeBytes;
}
