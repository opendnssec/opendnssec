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
* This class handles the internal state.
* Mainly session and object handling.
*
************************************************************/

#include "main.h"

SoftHSMInternal::SoftHSMInternal() {
  openSessions = 0;
  openObjects = 0;

  for(int i = 0; i < MAX_SESSION_COUNT; i++) {
    sessions[i] = NULL_PTR;
  }

  for(int i = 0; i < MAX_OBJECTS; i++) {
    objects[i] = NULL_PTR;
  }

  pin = NULL_PTR;
  rng = new AutoSeeded_RNG();
}

SoftHSMInternal::~SoftHSMInternal() {
  for(int i = 0; i < MAX_SESSION_COUNT; i++) {
    if(sessions[i] != NULL_PTR) {
      delete sessions[i];
      sessions[i] = NULL_PTR;
    }
  }

  for(int i = 0; i < MAX_OBJECTS; i++) {
    if(objects[i] != NULL_PTR) {
      delete objects[i];
      objects[i] = NULL_PTR;
    }
  }

  if(pin != NULL_PTR) {
    free(pin);
    pin = NULL_PTR;
  }

  if(rng != NULL_PTR) {
    delete rng;
    rng = NULL_PTR;
  }

  openSessions = 0;
  openObjects = 0;
}

int SoftHSMInternal::getSessionCount() {
  return openSessions;
}

// Creates a new session if there is enough space available.

CK_RV SoftHSMInternal::openSession(CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
  if(openSessions >= MAX_SESSION_COUNT) {
    return CKR_SESSION_COUNT;
  }

  if((flags & CKF_SERIAL_SESSION) == 0) {
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }

  if(!phSession) {
    return CKR_ARGUMENTS_BAD;
  }

  for(int i = 0; i < MAX_SESSION_COUNT; i++) {
    if(sessions[i] == NULL_PTR) {
      openSessions++;
      sessions[i] = new SoftSession();
      sessions[i]->pApplication = pApplication;
      sessions[i]->Notify = Notify;
      *phSession = (CK_SESSION_HANDLE)(i+1);
      return CKR_OK;
    }
  }

  return CKR_SESSION_COUNT;
}

// Closes the specific session.

CK_RV SoftHSMInternal::closeSession(CK_SESSION_HANDLE hSession) {
  if(hSession > MAX_SESSION_COUNT || hSession < 1) {
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(sessions[hSession-1] == NULL_PTR) {
    return CKR_SESSION_CLOSED;
  }

  delete sessions[hSession-1];
  sessions[hSession-1] = NULL_PTR;

  openSessions--;

  return CKR_OK;
}

// Closes all the sessions.

CK_RV SoftHSMInternal::closeAllSessions() {
  for (int i = 0; i < MAX_SESSION_COUNT; i++) {
    if(sessions[i] != NULL_PTR) {
      delete sessions[i];
      sessions[i] = NULL_PTR;
    }
  }

  openSessions = 0;

  return CKR_OK;
}

// Return information about the session.

CK_RV SoftHSMInternal::getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  SoftSession *session;
  CK_RV result = getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  pInfo->slotID = 1;

  if(pin) {
    pInfo->state = CKS_RW_USER_FUNCTIONS;
  } else {
    pInfo->state = CKS_RW_PUBLIC_SESSION;
  }

  pInfo->flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
  pInfo->ulDeviceError = 0;

  return CKR_OK;
}

// Logs the user into the token.

CK_RV SoftHSMInternal::login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  SoftSession *session;
  CK_RV result = getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(ulPinLen < 4 || ulPinLen > 8000) {
    return CKR_PIN_INCORRECT;
  }

  if(pin != NULL_PTR) {
    // Should we allow multiple login?
    // Yes, but should we clear the object buffer?
    free(pin);
    pin = NULL_PTR;
  }

  pin = (char *)malloc(ulPinLen+1);
  if (!pin) {
    return CKR_DEVICE_MEMORY;
  }
  memset(pin, 0, ulPinLen+1);
  memcpy(pin, pPin, ulPinLen);

  readAllKeyFiles(this);

  return CKR_OK;
}

// Retrieves the session pointer associated with the session handle.

CK_RV SoftHSMInternal::getSession(CK_SESSION_HANDLE hSession, SoftSession *&session) {
  if(hSession > MAX_SESSION_COUNT || hSession < 1) {
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(sessions[hSession-1] == NULL_PTR) {
    return CKR_SESSION_CLOSED;
  }

  session = sessions[hSession-1];

  return CKR_OK;
}

// Retrieves the object pointer associated with the object handle.

CK_RV SoftHSMInternal::getObject(CK_OBJECT_HANDLE hObject, SoftObject *&object) {
  if(hObject > MAX_OBJECTS || hObject < 1 || objects[hObject-1] == NULL_PTR) {
    return CKR_OBJECT_HANDLE_INVALID;
  }

  object = objects[hObject-1];

  return CKR_OK;
}

// Checks if the user is logged in.

bool SoftHSMInternal::isLoggedIn() {
  if(pin == NULL_PTR) {
    return false;
  } else {
    return true;
  }
}

char* SoftHSMInternal::getPIN() {
  return pin;
}

// Add an object to the token.
// Returns an object handle.

CK_OBJECT_HANDLE SoftHSMInternal::addObject(SoftObject *inObject) {
  for(int i = 0; i < MAX_OBJECTS; i++) {
    if(objects[i] == NULL_PTR) {
      objects[i] = inObject;
      openObjects++;
      return i+1;
    }
  }
  return 0;
}

// Retrieves the attributes specified by the template.
// There can be different error states depending on 
// if the given buffer is too small, the attribute is 
// sensitive, or not supported by the object.
// If there is an error, then the most recent one is
// returned.

CK_RV SoftHSMInternal::getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  SoftSession *session;
  CK_RV result = getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  SoftObject *object;
  result = getObject(hObject, object);

  if(result != CKR_OK) {
    return result;
  }

  result = CKR_OK;
  CK_RV objectResult = CKR_OK;

  for(unsigned int i = 0; i < ulCount; i++) {
    objectResult = object->getAttribute(&pTemplate[i]);
    if(objectResult != CKR_OK) {
      result = objectResult;
    }
  }

  return result;
}

// Initialize the search for objects.
// The template specifies the search pattern.

CK_RV SoftHSMInternal::findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  SoftSession *session;
  CK_RV result = getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(session->findInitialized) {
    return CKR_OPERATION_ACTIVE;
  }

  if(session->findAnchor != NULL_PTR) {
    delete session->findAnchor;
  }

  // Creates the search result chain.
  session->findAnchor = new SoftFind();
  session->findCurrent = session->findAnchor;

  int counter = 0;

  // Check with all objects.
  for(int i = 0; i < MAX_OBJECTS && counter < openObjects; i++) {
    if(objects[i] != NULL_PTR) {
      CK_BBOOL findObject = CK_TRUE;

      // See if the object match all attributes.
      for(unsigned int j = 0; j < ulCount; j++) {
        if(objects[i]->matchAttribute(&pTemplate[j]) == CK_FALSE) {
          findObject = CK_FALSE;
        }
      }

      if(findObject == CK_TRUE) {
        session->findAnchor->addFind(i+1);
      }

      counter++;
    }
  }

  session->findInitialized = true;

  return CKR_OK;
}

// Destroys the object.
//
// Private key:
//   Only when the user is correctly logged in.
//   The associated key file will also be removed.
//   The corresponding public key can thereby not be recreated at the next start up.
//
// Public key:
//   The key will only be softly removed, since it will be recreated from the
//   private key file at the next start up.

CK_RV SoftHSMInternal::destroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  SoftSession *session;
  CK_RV result = getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  int objectHandle = hObject-1;

  if(hObject > MAX_OBJECTS || hObject < 1 || objects[objectHandle] == NULL_PTR) {
    return CKR_OBJECT_HANDLE_INVALID;
  }

  if(objects[objectHandle]->getObjectClass() == CKO_PUBLIC_KEY) {
    delete objects[objectHandle];
    objects[objectHandle] = NULL_PTR;
    openObjects--;
  } else if(objects[objectHandle]->getObjectClass() == CKO_PRIVATE_KEY) {
    if(objects[objectHandle]->removeFile(this) != CKR_OK) {
      return CKR_GENERAL_ERROR;
    }
    delete objects[objectHandle];
    objects[objectHandle] = NULL_PTR;
    openObjects--;
  } else {
    return CKR_GENERAL_ERROR;
  }

  return CKR_OK;
}
