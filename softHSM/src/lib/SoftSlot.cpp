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
#include "SoftDatabase.h"

#include <stdlib.h>

SoftSlot::SoftSlot() {
  dbPath = NULL_PTR;
  userPIN = NULL_PTR;
  slotFlags = CKF_REMOVABLE_DEVICE;
  tokenLabel = NULL_PTR;
  slotID = 0;
  nextSlot = NULL_PTR;
  objects = new SoftObject();
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

void SoftSlot:readDB() {
  SoftDatabase db = new SoftDatabase();
  CK_RV rv = db->init(dbPath);
  if(rv != CKR_OK) {
    delete db;
    return;
  }

  if(objects != NULL_PTR) {
    delete objects;
  }
  objects = db->readAllObjects();
  delete db;

  slotFlags |= CKF_TOKEN_PRESENT;
}
