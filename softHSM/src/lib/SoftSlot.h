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

#ifndef SOFTHSM_SOFTSLOT_H
#define SOFTHSM_SOFTSLOT_H 1

#include "SoftObject.h"

#include "pkcs11_unix.h"

class SoftSlot {
  public:
    SoftSlot();
    ~SoftSlot();

    void addSlot(CK_SLOT_ID newSlotID, char *newDBPath);
    SoftSlot *getSlot(CK_SLOT_ID getID);
    SoftSlot *getNextSlot();
    CK_SLOT_ID getSlotID();

    char *dbPath;
    char *userPIN;

    CK_FLAGS slotFlags;
    char *tokenLabel;

    SoftObject *objects;

  private:
    CK_SLOT_ID slotID;
    SoftSlot *nextSlot;
};

#endif /* SOFTHSM_SOFTSLOT_H */
