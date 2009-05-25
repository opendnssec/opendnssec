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
#include "util.h"

#include <stdlib.h>

SoftSlot::SoftSlot() {
  dbPath = NULL_PTR;
  userPIN = NULL_PTR;
  soPIN = NULL_PTR;
  slotFlags = CKF_REMOVABLE_DEVICE;
  tokenFlags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_CLOCK_ON_TOKEN;
  tokenLabel = NULL_PTR;
  slotID = 0;
  nextSlot = NULL_PTR;
  hashedUserPIN = NULL_PTR;
  hashedSOPIN = NULL_PTR;
}

SoftSlot::~SoftSlot() {
  FREE_PTR(dbPath);
  FREE_PTR(userPIN);
  FREE_PTR(soPIN);
  FREE_PTR(tokenLabel);
  DELETE_PTR(nextSlot);
  FREE_PTR(hashedUserPIN);
  FREE_PTR(hashedSOPIN);
}

// Add a new slot last in the chain

void SoftSlot::addSlot(CK_SLOT_ID newSlotID, char *newDBPath) {
  if(nextSlot == NULL_PTR) {
    nextSlot = new SoftSlot();
    slotID = newSlotID;
    dbPath = newDBPath;
    readDB();
  } else {
    // Slots may not share the same ID
    if(newSlotID == slotID) {
      FREE_PTR(newDBPath);
      return;
    }

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
  tokenFlags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_CLOCK_ON_TOKEN;

  SoftDatabase *db = new SoftDatabase();
  CK_RV rv = db->init(dbPath);

  if(rv == CKR_TOKEN_NOT_PRESENT) {
    delete db;
    return;
  }

  slotFlags |= CKF_TOKEN_PRESENT;

  if(rv == CKR_OK) {
    FREE_PTR(tokenLabel);
    tokenLabel = db->getTokenLabel();
    FREE_PTR(hashedSOPIN);
    hashedSOPIN = db->getSOPIN();
    if(tokenLabel != NULL_PTR && hashedSOPIN != NULL_PTR) {
      tokenFlags |= CKF_TOKEN_INITIALIZED;
    }

    FREE_PTR(hashedUserPIN);
    hashedUserPIN = db->getUserPIN();
    if(hashedUserPIN != NULL_PTR) {
      tokenFlags |= CKF_USER_PIN_INITIALIZED;
    }
  }

  delete db;
}
