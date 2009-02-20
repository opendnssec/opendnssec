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
* This class handles the slots
*
************************************************************/

#include "SoftSlot.h"
#include "log.h"
#include "SoftDatabase.h"

#include <stdlib.h>

#include <botan/rsa.h>
#include <botan/bigint.h>
#include <botan/pkcs8.h>
#include <botan/x509_obj.h>
#include <botan/auto_rng.h>
using namespace Botan;

SoftSlot::SoftSlot() {
  dbPath = NULL_PTR;
  userPIN = NULL_PTR;
  soPIN = NULL_PTR;
  slotFlags = CKF_REMOVABLE_DEVICE;
  tokenLabel = NULL_PTR;
  slotID = 0;
  nextSlot = NULL_PTR;
  objects = new SoftObject();
  hashedUserPIN = NULL_PTR;
  hashedSOPIN = NULL_PTR;
}

SoftSlot::~SoftSlot() {
  if(dbPath != NULL_PTR) {
    free(dbPath);
    dbPath = NULL_PTR;
  }
  if(userPIN != NULL_PTR) {
    free(userPIN);
    userPIN = NULL_PTR;
  }
  if(soPIN != NULL_PTR) {
    free(soPIN);
    soPIN = NULL_PTR;
  }
  if(tokenLabel != NULL_PTR) {
    free(tokenLabel);
    tokenLabel = NULL_PTR;
  }
  if(nextSlot != NULL_PTR) {
    delete nextSlot;
    nextSlot = NULL_PTR;
  }
  if(objects != NULL_PTR) {
    delete objects;
    objects = NULL_PTR;
  }
  if(hashedUserPIN != NULL_PTR) {
    free(hashedUserPIN);
    hashedUserPIN = NULL_PTR;
  }
  if(hashedSOPIN != NULL_PTR) {
    free(hashedSOPIN);
    hashedSOPIN = NULL_PTR;
  }
}

// Add a new slot

void SoftSlot::addSlot(CK_SLOT_ID newSlotID, char *newDBPath) {
  if(nextSlot == NULL_PTR) {
    nextSlot = new SoftSlot();
    slotID = newSlotID;
    dbPath = newDBPath;
    readDB();
  } else {
    nextSlot->addSlot(newSlotID, newDBPath);
  }
}

// Find the slot with a given ID

SoftSlot* SoftSlot::getSlot(CK_SLOT_ID getID) {
  if(nextSlot != NULL_PTR) {
    if(getID == slotID) {
      return this;
    } else {
      return nextSlot->getSlot(getID);
    }
  } else {
    return NULL_PTR;
  }
}

// Return the slot after this one.

SoftSlot* SoftSlot::getNextSlot() {
  return nextSlot;
}

// Return the SlotID of the current slot.

CK_SLOT_ID SoftSlot::getSlotID() {
  return slotID;
}

// Reads the content of the database.

void SoftSlot::readDB() {
  SoftDatabase *db = new SoftDatabase();
  CK_RV rv = db->init(dbPath);
  if(rv != CKR_OK) {
    delete db;
    return;
  }

  if(tokenLabel != NULL_PTR) {
    free(tokenLabel);
  }
  tokenLabel = db->getTokenLabel();

  if(hashedSOPIN != NULL_PTR) {
    free(hashedSOPIN);
  }
  hashedSOPIN = db->getSOPIN();

  if(hashedUserPIN != NULL_PTR) {
    free(hashedUserPIN);
  }
  hashedUserPIN = db->getUserPIN();

  if(objects != NULL_PTR) {
    delete objects;
  }
  objects = db->readAllObjects();
  delete db;

  slotFlags |= CKF_TOKEN_PRESENT;

  loadUnencryptedKeys();
}

// Decrypt the keys and store the attributes

void SoftSlot::login(RandomNumberGenerator *rng) {
  SoftObject *currentObject = objects;
  while(currentObject->nextObject != NULL_PTR) {
    if(currentObject->isPrivate == CK_TRUE &&
       currentObject->isToken == CK_TRUE) {
      switch(currentObject->objectClass) {
        case CKO_PRIVATE_KEY:
          if(currentObject->keyType == CKK_RSA) {
            loadRSAPrivate(currentObject, rng, userPIN);
          }
          break;
        default:
          break;
      }
    }

    currentObject = currentObject->nextObject;
  }
}

// Load the private RSA key. Decrypt with given PIN.
// If no PIN is given, then no decryption is performed.

void SoftSlot::loadRSAPrivate(SoftObject *currentObject, RandomNumberGenerator *rng, char *userPIN) {
  if(currentObject->encodedKey == NULL_PTR) {
    return;
  }

  DataSource *dsMem = new DataSource_Memory((byte *)currentObject->encodedKey, strlen(currentObject->encodedKey));
  Private_Key *rsaKey = NULL_PTR;

  try {
    if(userPIN == NULL_PTR) {
      rsaKey = PKCS8::load_key(*dsMem, *rng);
    } else {
      rsaKey = PKCS8::load_key(*dsMem, *rng, userPIN);
    }
  }
  catch(...) {
    if(dsMem != NULL_PTR) {
      delete dsMem;
    }
    if(rsaKey != NULL_PTR) {
      delete rsaKey;
    }

    #if SOFTLOGLEVEL >= SOFTERROR
      logError("loadRSAPrivate", "Could not load the encoded key");
    #endif

    return;
  }

  delete dsMem;

  // The RSA modulus bits
  IF_Scheme_PrivateKey *ifKeyPriv = dynamic_cast<IF_Scheme_PrivateKey*>(rsaKey);
  BigInt bigMod = ifKeyPriv->get_n();
  CK_ULONG bits = bigMod.bits();
  currentObject->keySizeBytes = (bits + 7) / 8;
  currentObject->addAttributeFromData(CKA_MODULUS_BITS, &bits, sizeof(bits));

  // The RSA modulus
  CK_ULONG size = bigMod.bytes();
  CK_VOID_PTR buf = (CK_VOID_PTR)malloc(size);
  bigMod.binary_encode((byte *)buf);
  currentObject->addAttributeFromData(CKA_MODULUS, buf, size);
  free(buf);

  // The RSA public exponent
  BigInt bigExp = ifKeyPriv->get_e();
  size = bigExp.bytes();
  buf = (CK_VOID_PTR)malloc(size);
  bigExp.binary_encode((byte *)buf);
  currentObject->addAttributeFromData(CKA_PUBLIC_EXPONENT, buf, size);
  free(buf);

  // The RSA private exponent
  BigInt bigPrivExp = ifKeyPriv->get_d();
  size = bigPrivExp.bytes();
  buf = (CK_VOID_PTR)malloc(size);
  bigPrivExp.binary_encode((byte *)buf);
  currentObject->addAttributeFromData(CKA_PRIVATE_EXPONENT, buf, size);
  free(buf);

  // The RSA prime p
  BigInt bigPrime1 = ifKeyPriv->get_p();
  size = bigPrime1.bytes();
  buf = (CK_VOID_PTR)malloc(size);
  bigPrime1.binary_encode((byte *)buf);
  currentObject->addAttributeFromData(CKA_PRIME_1, buf, size);
  free(buf);

  // The RSA prime q
  BigInt bigPrime2 = ifKeyPriv->get_q();
  size = bigPrime2.bytes();
  buf = (CK_VOID_PTR)malloc(size);
  bigPrime2.binary_encode((byte *)buf);
  currentObject->addAttributeFromData(CKA_PRIME_2, buf, size);
  free(buf);

  delete rsaKey;
  free(currentObject->encodedKey);
  currentObject->encodedKey = NULL_PTR;
}

void SoftSlot::loadUnencryptedKeys() {
  AutoSeeded_RNG *rng = new AutoSeeded_RNG();

  SoftObject *currentObject = objects;
  while(currentObject->nextObject != NULL_PTR) {
    switch(currentObject->objectClass) {
      case CKO_PUBLIC_KEY:
        if(currentObject->keyType == CKK_RSA) {
          loadRSAPublic(currentObject);
        }
        break;
      case CKO_PRIVATE_KEY:
        if(currentObject->isPrivate != CK_TRUE || 
           currentObject->isToken != CK_TRUE) {
          if(currentObject->keyType == CKK_RSA) {
            loadRSAPrivate(currentObject, rng);
          }
        }
      default:
        break;
    }

    currentObject = currentObject->nextObject;
  }

  delete rng;
}

void SoftSlot::loadRSAPublic(SoftObject *currentObject) {
  if(currentObject->encodedKey == NULL_PTR) {
    return;
  }

  DataSource *dsMem = new DataSource_Memory((byte*)currentObject->encodedKey, strlen(currentObject->encodedKey));
  Public_Key *rsaKey = NULL_PTR;

  try {
    rsaKey = X509::load_key(*dsMem);
  }
  catch(...) {
    if(dsMem != NULL_PTR) {
      delete dsMem;
    }
    if(rsaKey != NULL_PTR) {
      delete rsaKey;
    }

    #if SOFTLOGLEVEL >= SOFTERROR
      logError("loadRSAPublic", "Could not load the encoded key");
    #endif

    return;
  }

  delete dsMem;

  // The RSA modulus bits
  IF_Scheme_PublicKey *ifKey = dynamic_cast<IF_Scheme_PublicKey*>(rsaKey);
  BigInt bigModulus = ifKey->get_n();
  CK_ULONG bits = bigModulus.bits();
  currentObject->keySizeBytes = (bits + 7) / 8;
  currentObject->addAttributeFromData(CKA_MODULUS_BITS, &bits, sizeof(bits));

  // The RSA modulus
  CK_ULONG size = bigModulus.bytes();
  CK_VOID_PTR buf = (CK_VOID_PTR)malloc(size);
  bigModulus.binary_encode((byte *)buf);
  currentObject->addAttributeFromData(CKA_MODULUS, buf, size);
  free(buf);

  // The RSA public exponent
  BigInt bigExponent = ifKey->get_e();
  size = bigExponent.bytes();
  buf = (CK_VOID_PTR)malloc(size);
  bigExponent.binary_encode((byte *)buf);
  currentObject->addAttributeFromData(CKA_PUBLIC_EXPONENT, buf, size);
  free(buf);

  delete rsaKey;
  free(currentObject->encodedKey);
  currentObject->encodedKey = NULL_PTR;
}

void SoftSlot::getObjectFromDB(SoftSession *session, CK_OBJECT_HANDLE objRef) {
  SoftObject *newObject = session->db->populateObj(objRef);

  if(newObject == NULL_PTR) {
    return;
  }

  newObject->nextObject = objects;
  objects = newObject;

  newObject->createdBySession = session;

  if(newObject->objectClass == CKO_PUBLIC_KEY && newObject->keyType == CKK_RSA) {
    loadRSAPublic(newObject);
  } else if(newObject->objectClass == CKO_PRIVATE_KEY && newObject->keyType == CKK_RSA) {
    if(newObject->isToken == CK_TRUE && newObject->isPrivate == CK_TRUE) {
      loadRSAPrivate(newObject, session->rng, userPIN);
    } else {
      loadRSAPrivate(newObject, session->rng);
    }
  }
}
