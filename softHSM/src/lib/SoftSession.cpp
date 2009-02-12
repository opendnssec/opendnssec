/* $Id$ */

/*
 * Copyright (c) 2008-2009 .SE (The Internet Infrastructure Foundation).
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
* This class defines a session
* It holds the current state of the session
*
************************************************************/

#include "SoftSession.h"

// Includes for the crypto library
#include <botan/if_algo.h>
#include <botan/rsa.h>
using namespace Botan;

SoftSession::SoftSession(int rwSession) {
  pApplication = NULL_PTR;
  Notify = NULL_PTR;

  if(rwSession == CKF_RW_SESSION) {
    readWrite = true;
  } else {
    readWrite = false;
  }

  findAnchor = NULL_PTR;
  findCurrent = NULL_PTR;
  findInitialized = false;

  digestPipe = NULL_PTR;
  digestSize = 0;
  digestInitialized = false;

  pkSigner = NULL_PTR;
  signSinglePart = false;
  signSize = 0;
  signInitialized = false;

  pkVerifier = NULL_PTR;
  verifySinglePart = false;
  verifySize = 0;
  verifyInitialized = false;

  keyStore = new SoftKeyStore();

  rng = new AutoSeeded_RNG();

  db = new SoftDatabase();
}

SoftSession::~SoftSession() {
  pApplication = NULL_PTR;
  Notify = NULL_PTR;

  if(findAnchor != NULL_PTR) {
    delete findAnchor;
    findAnchor = NULL_PTR;
  }

  findCurrent = NULL_PTR;

  if(digestPipe != NULL_PTR) {
    delete digestPipe;
    digestPipe = NULL_PTR;
  }

  if(pkSigner != NULL_PTR) {
    delete pkSigner;
    pkSigner = NULL_PTR;
  }

  if(pkVerifier != NULL_PTR) {
    delete pkVerifier;
    pkVerifier = NULL_PTR;
  }

  if(keyStore != NULL_PTR) {
    delete keyStore;
    keyStore = NULL_PTR;
  }

  if(rng != NULL_PTR) {
    delete rng;
  }

  if(db != NULL_PTR) {
    delete db;
    db = NULL_PTR;
  }
}

bool SoftSession::isReadWrite() {
  return readWrite;
}

// Get the key from the session key store
// If it is not chached then create a clone
// of it and store it in the cache.

Public_Key* SoftSession::getKey(SoftObject *object) {
  if(object == NULL_PTR) {
    return NULL_PTR;
  }

  Public_Key* tmpKey = keyStore->getKey(object->index);

  // If the key is not in the session cache
  if(tmpKey == NULL_PTR) {
    if(object->keyType == CKK_RSA) {
      // Clone the key
      if(object->objectClass == CKO_PRIVATE_KEY) {
        BigInt bigN = object->getBigIntAttribute(CKA_MODULUS);
        BigInt bigE = object->getBigIntAttribute(CKA_PUBLIC_EXPONENT);
        BigInt bigD = object->getBigIntAttribute(CKA_PRIVATE_EXPONENT);
        BigInt bigP = object->getBigIntAttribute(CKA_PRIME_1);
        BigInt bigQ = object->getBigIntAttribute(CKA_PRIME_2);

        if(bigN.is_zero () || bigE.is_zero() || bigD.is_zero() || bigP.is_zero() || bigQ.is_zero()) {
          return NULL_PTR;
        }

        tmpKey = new RSA_PrivateKey(*rng, bigP, bigQ, bigE, bigD, bigN);
      } else {
        BigInt bigN = object->getBigIntAttribute(CKA_MODULUS);
        BigInt bigE = object->getBigIntAttribute(CKA_PUBLIC_EXPONENT);

        if(bigN.is_zero() || bigE.is_zero()) {
          return NULL_PTR;
        }

        tmpKey = new RSA_PublicKey(bigN, bigE);
      }

      // Create a new key store object.
      SoftKeyStore *newKeyLink = new SoftKeyStore();
      newKeyLink->next = keyStore;
      newKeyLink->botanKey = tmpKey;
      newKeyLink->index = object->index;

      // Add it first in the chain.
      keyStore = newKeyLink;
    }
  }

  return tmpKey;
}
