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
* This class handles the internal state.
* Mainly session and object handling.
*
************************************************************/

#ifndef SOFTHSM_SOFTHSMINTERNAL_H
#define SOFTHSM_SOFTHSMINTERNAL_H 1

#include "pkcs11_unix.h"
#include "SoftFind.h"
#include "SoftObject.h"
#include "SoftDatabase.h"
#include "SoftSession.h"
#include "SoftSlot.h"
#include "config.h"

class SoftFind;
class SoftObject;
class SoftDatabase;
class SoftSession;
class SoftSlot;

class SoftHSMInternal {
  public:
    SoftHSMInternal(bool threading, CK_CREATEMUTEX cMutex = NULL_PTR, 
      CK_DESTROYMUTEX dMutex = NULL_PTR, CK_LOCKMUTEX lMutex = NULL_PTR, 
      CK_UNLOCKMUTEX uMutex = NULL_PTR);
    ~SoftHSMInternal();

    // Session Handling
    int getSessionCount();
    CK_RV openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, 
      CK_SESSION_HANDLE_PTR phSession);
    CK_RV closeSession(CK_SESSION_HANDLE hSession);
    CK_RV closeAllSessions(CK_SLOT_ID slotID);
    CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
    SoftSession* getSession(CK_SESSION_HANDLE hSession);

    // User handling
    CK_RV login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, 
      CK_ULONG ulPinLen);
    CK_RV logout(CK_SESSION_HANDLE hSession);

    // Object handling
    void destroySessObj(SoftSession *session);
    CK_RV destroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
    CK_RV getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, 
      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV setAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, 
      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, 
      CK_ULONG ulCount);

    // Mutex handling
    CK_RV lockMutex();
    CK_RV unlockMutex();

    // Slots
    SoftSlot *slots;

  private:
    int openSessions;
    SoftSession *sessions[MAX_SESSION_COUNT];

    CK_CREATEMUTEX createMutexFunc;
    CK_DESTROYMUTEX destroyMutexFunc;
    CK_LOCKMUTEX lockMutexFunc;
    CK_UNLOCKMUTEX unlockMutexFunc;
    bool usesThreading;

    CK_RV createMutex(CK_VOID_PTR_PTR newMutex);
    CK_RV destroyMutex(CK_VOID_PTR mutex);
    CK_VOID_PTR pHSMMutex;
};

#endif /* SOFTHSM_SOFTHSMINTERNAL_H */
