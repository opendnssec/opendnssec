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
* SoftHSM
*
* Implements parts of the PKCS11 interface defined by
* RSA Labratories, PKCS11 v2.20, called Cryptoki.
*
************************************************************/

#include "main.h"
#include "mutex.h"
#include "log.h"
#include "file.h"
#include "SoftHSMInternal.h"
#include "userhandling.h"
#include "util.h"

// Standard includes
#include <stdio.h>
#include <stdlib.h>

// C POSIX library header
#include <sys/time.h>

// Includes for the crypto library
#include <botan/init.h>
#include <botan/md5.h>
#include <botan/rmd160.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>
#include <botan/filters.h>
#include <botan/pipe.h>
#include <botan/emsa3.h>
#include <botan/pk_keys.h>
#include <botan/bigint.h>
#include <botan/rsa.h>
using namespace Botan;

// Keeps the internal state
SoftHSMInternal *softHSM = NULL_PTR;

// A list with Cryptoki version number
// and pointers to the API functions.
CK_FUNCTION_LIST function_list = {
  { 2, 20 },
  C_Initialize,
  C_Finalize,
  C_GetInfo,
  C_GetFunctionList,
  C_GetSlotList,
  C_GetSlotInfo,
  C_GetTokenInfo,
  C_GetMechanismList,
  C_GetMechanismInfo,
  C_InitToken,
  C_InitPIN,
  C_SetPIN,
  C_OpenSession,
  C_CloseSession,
  C_CloseAllSessions,
  C_GetSessionInfo,
  C_GetOperationState,
  C_SetOperationState,
  C_Login,
  C_Logout,
  C_CreateObject,
  C_CopyObject,
  C_DestroyObject,
  C_GetObjectSize,
  C_GetAttributeValue,
  C_SetAttributeValue,
  C_FindObjectsInit,
  C_FindObjects,
  C_FindObjectsFinal,
  C_EncryptInit,
  C_Encrypt,
  C_EncryptUpdate,
  C_EncryptFinal,
  C_DecryptInit,
  C_Decrypt,
  C_DecryptUpdate,
  C_DecryptFinal,
  C_DigestInit,
  C_Digest,
  C_DigestUpdate,
  C_DigestKey,
  C_DigestFinal,
  C_SignInit,
  C_Sign,
  C_SignUpdate,
  C_SignFinal,
  C_SignRecoverInit,
  C_SignRecover,
  C_VerifyInit,
  C_Verify,
  C_VerifyUpdate,
  C_VerifyFinal,
  C_VerifyRecoverInit,
  C_VerifyRecover,
  C_DigestEncryptUpdate,
  C_DecryptDigestUpdate,
  C_SignEncryptUpdate,
  C_DecryptVerifyUpdate,
  C_GenerateKey,
  C_GenerateKeyPair,
  C_WrapKey,
  C_UnwrapKey,
  C_DeriveKey,
  C_SeedRandom,
  C_GenerateRandom,
  C_GetFunctionStatus,
  C_CancelFunction,
  C_WaitForSlotEvent
};
extern CK_FUNCTION_LIST function_list;

// Initialize the labrary

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  DEBUG_MSG("C_Initialize", "Calling");

  CHECK_DEBUG_RETURN(softHSM != NULL_PTR, "C_Initialize", "Already initialized",
                     CKR_CRYPTOKI_ALREADY_INITIALIZED);

  CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

  // Do we have any arguments?
  if(args != NULL_PTR) {
    // Reserved for future use. Must be NULL_PTR
    CHECK_DEBUG_RETURN(args->pReserved != NULL_PTR, "C_Initialize",
                       "pReserved must be NULL_PTR", CKR_ARGUMENTS_BAD);

    // Are we not supplied with mutex functions?
    if(args->CreateMutex == NULL_PTR &&
       args->DestroyMutex == NULL_PTR &&
       args->LockMutex == NULL_PTR &&
       args->UnlockMutex == NULL_PTR) {

      // Can we create our own mutex functions?
      if(args->flags & CKF_OS_LOCKING_OK) {
        softHSM = new SoftHSMInternal(true,
                                      softHSMCreateMutex,
                                      softHSMDestroyMutex,
                                      softHSMLockMutex,
                                      softHSMUnlockMutex);
      } else {
        // The external application is not using threading
        softHSM = new SoftHSMInternal(false);
      }
    } else {
      // We must have all mutex functions
      CHECK_DEBUG_RETURN(args->CreateMutex == NULL_PTR || args->DestroyMutex == NULL_PTR ||
                         args->LockMutex == NULL_PTR || args->UnlockMutex == NULL_PTR,
                         "C_Initialize", "Not all mutex functions are supplied", CKR_ARGUMENTS_BAD);

      softHSM = new SoftHSMInternal(true,
                                    args->CreateMutex,
                                    args->DestroyMutex,
                                    args->LockMutex,
                                    args->UnlockMutex);
    }
  } else {
    // No concurrent access by multiple threads
    softHSM = new SoftHSMInternal(false);
  }

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_Initialize", "Coult not allocate memory", CKR_HOST_MEMORY);

  CK_RV rv = readConfigFile();
  if(rv != CKR_OK) {
    delete softHSM;
    DEBUG_MSG("C_Initialize", "Error in config file");
    return rv;
  }

  // Init the Botan crypto library 
  LibraryInitializer::initialize("thread_safe=true");

  DEBUG_MSG("C_Initialize", "OK");
  return CKR_OK;
}

// Finalizes the library. Clears out any memory allocations.

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  DEBUG_MSG("C_Finalize", "Calling");

  // Reserved for future use.
  CHECK_DEBUG_RETURN(pReserved != NULL_PTR, "C_Finalize", "pReserved must be NULL_PTR",
                     CKR_ARGUMENTS_BAD);

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_Finalize", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  delete softHSM;
  softHSM = NULL_PTR;

  // Deinitialize the Botan crypto lib
  LibraryInitializer::deinitialize();

  DEBUG_MSG("C_Finalize", "OK");
  return CKR_OK;
}

// Returns general information about SoftHSM.

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
  DEBUG_MSG("C_GetInfo", "Calling");

  CHECK_DEBUG_RETURN(pInfo == NULL_PTR, "C_GetInfo", "pInfo must not be a NULL_PTR",
                     CKR_ARGUMENTS_BAD);

  pInfo->cryptokiVersion.major = 2;
  pInfo->cryptokiVersion.minor = 20;
  memset(pInfo->manufacturerID, ' ', 32);
  memcpy(pInfo->manufacturerID, "SoftHSM", 7);
  pInfo->flags = 0;
  memset(pInfo->libraryDescription, ' ', 32);
  memcpy(pInfo->libraryDescription, "Implementation of PKCS11", 24);
  pInfo->libraryVersion.major = VERSION_MAJOR;
  pInfo->libraryVersion.minor = VERSION_MINOR;

  DEBUG_MSG("C_GetInfo", "OK");
  return CKR_OK;
}

// Returns the function list.

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  DEBUG_MSG("C_GetFunctionList", "Calling");

  CHECK_DEBUG_RETURN(ppFunctionList == NULL_PTR, "C_GetFunctionList", 
                     "ppFunctionList must not be a NULL_PTR", CKR_ARGUMENTS_BAD);

  *ppFunctionList = &function_list;

  DEBUG_MSG("C_GetFunctionList", "OK");
  return CKR_OK;
}

// Returns a list of all the slots.
// Only one slot is available, SlotID 1.
// And the token is present.

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  DEBUG_MSG("C_GetSlotList", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_GetSlotList", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);
  CHECK_DEBUG_RETURN(pulCount == NULL_PTR, "C_GetSlotList", "pulCount must not be a NULL_PTR",
                     CKR_ARGUMENTS_BAD);

  int nrToken = 0;
  int nrTokenPresent = 0;

  // Count the number of slots
  SoftSlot *slotToken = softHSM->slots;
  while(slotToken->getNextSlot() != NULL_PTR) {
    if((slotToken->slotFlags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT) {
      nrTokenPresent++;
    }
    nrToken++;

    slotToken = slotToken->getNextSlot();
  }

  // What buffer size should we use?
  unsigned int bufSize = 0;
  if(tokenPresent == CK_TRUE) {
    bufSize = nrTokenPresent;
  } else {
    bufSize = nrToken;
  }

  // The user wants the buffer size
  if(pSlotList == NULL_PTR) {
    *pulCount = bufSize;

    DEBUG_MSG("C_GetSlotList", "OK, returning list length");
    return CKR_OK;
  }

  // Is the given buffer to small?
  if(*pulCount < bufSize) {
    *pulCount = bufSize;

    DEBUG_MSG("C_GetSlotList", "The buffer is too small");
    return CKR_BUFFER_TOO_SMALL;
  }

  slotToken = softHSM->slots;
  int counter = 0;

  // Get all slotIDs
  while(slotToken->getNextSlot() != NULL_PTR) {
    if(tokenPresent == CK_FALSE || (slotToken->slotFlags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT) {
      pSlotList[counter++] = slotToken->getSlotID();
    }
    slotToken = slotToken->getNextSlot();
  }
  *pulCount = bufSize;

  DEBUG_MSG("C_GetSlotList", "OK, returning list");
  return CKR_OK;
}

// Returns information about the slot.

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  DEBUG_MSG("C_GetSlotInfo", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_GetSlotInfo", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);
  CHECK_DEBUG_RETURN(pInfo == NULL_PTR, "C_GetSlotInfo", "pInfo must not be a NULL_PTR",
                     CKR_ARGUMENTS_BAD);

  SoftSlot *currentSlot = softHSM->slots->getSlot(slotID);

  CHECK_DEBUG_RETURN(currentSlot == NULL_PTR, "C_GetSlotInfo", "The given slotID does not exist",
                     CKR_SLOT_ID_INVALID);

  memset(pInfo->slotDescription, ' ', 64);
  memcpy(pInfo->slotDescription, "SoftHSM", 7);
  memset(pInfo->manufacturerID, ' ', 32);
  memcpy(pInfo->manufacturerID, "SoftHSM", 7);

  pInfo->flags = currentSlot->slotFlags;
  pInfo->hardwareVersion.major = VERSION_MAJOR;
  pInfo->hardwareVersion.minor = VERSION_MINOR;
  pInfo->firmwareVersion.major = VERSION_MAJOR;
  pInfo->firmwareVersion.minor = VERSION_MINOR;

  DEBUG_MSG("C_GetSlotInfo", "OK");
  return CKR_OK;
}

// Returns information about the token.

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  DEBUG_MSG("C_GetTokenInfo", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_GetTokenInfo", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);
  CHECK_DEBUG_RETURN(pInfo == NULL_PTR, "C_GetTokenInfo", "pInfo must not be a NULL_PTR",
                     CKR_ARGUMENTS_BAD);

  SoftSlot *currentSlot = softHSM->slots->getSlot(slotID);

  CHECK_DEBUG_RETURN(currentSlot == NULL_PTR, "C_GetTokenInfo", "The given slotID does not exist",
                     CKR_SLOT_ID_INVALID);
  CHECK_DEBUG_RETURN((currentSlot->slotFlags & CKF_TOKEN_PRESENT) == 0, "C_GetTokenInfo",
                     "The token is not present", CKR_TOKEN_NOT_PRESENT);

  if(currentSlot->tokenLabel == NULL_PTR) {
    memset(pInfo->label, ' ', 32);
  } else {
    memcpy(pInfo->label, currentSlot->tokenLabel, 32);
  }
  memset(pInfo->manufacturerID, ' ', 32);
  memcpy(pInfo->manufacturerID, "SoftHSM", 7);
  memset(pInfo->model, ' ', 16);
  memcpy(pInfo->model, "SoftHSM", 7);
  memset(pInfo->serialNumber, ' ', 16);
  memcpy(pInfo->serialNumber, "1", 1);

  pInfo->flags = currentSlot->tokenFlags;
  pInfo->ulMaxSessionCount = MAX_SESSION_COUNT;
  pInfo->ulSessionCount = softHSM->getSessionCount();
  pInfo->ulMaxRwSessionCount = MAX_SESSION_COUNT;
  pInfo->ulRwSessionCount = softHSM->getSessionCount();
  pInfo->ulMaxPinLen = 255;
  pInfo->ulMinPinLen = 4;
  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->hardwareVersion.major = VERSION_MAJOR;
  pInfo->hardwareVersion.minor = VERSION_MINOR;
  pInfo->firmwareVersion.major = VERSION_MAJOR;
  pInfo->firmwareVersion.minor = VERSION_MINOR;

  time_t rawtime;
  time(&rawtime);
  char dateTime[17];
  strftime(dateTime, 17, "%Y%m%d%H%M%S00", gmtime(&rawtime));
  memcpy(pInfo->utcTime, dateTime, 16);

  DEBUG_MSG("C_GetTokenInfo", "OK");
  return CKR_OK;
}

// Returns the supported mechanisms.

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  DEBUG_MSG("C_GetMechanismList", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_GetMechanismList", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);
  CHECK_DEBUG_RETURN(pulCount == NULL_PTR, "C_GetMechanismList", "pulCount must not be a NULL_PTR",
                     CKR_ARGUMENTS_BAD);

  SoftSlot *currentSlot = softHSM->slots->getSlot(slotID);

  CHECK_DEBUG_RETURN(currentSlot == NULL_PTR, "C_GetMechanismList", "The given slotID does note exist",
                     CKR_SLOT_ID_INVALID);

  if(pMechanismList == NULL_PTR) {
    *pulCount = 14;

    DEBUG_MSG("C_GetMechanismList", "OK, returning list length");
    return CKR_OK;
  }

  if(*pulCount < 14) {
    *pulCount = 14;

    DEBUG_MSG("C_GetMechanismList", "Buffer to small");
    return CKR_BUFFER_TOO_SMALL;
  }

  *pulCount = 14;

  pMechanismList[0] = CKM_RSA_PKCS_KEY_PAIR_GEN;
  pMechanismList[1] = CKM_RSA_PKCS;
  pMechanismList[2] = CKM_MD5;
  pMechanismList[3] = CKM_RIPEMD160;
  pMechanismList[4] = CKM_SHA_1;
  pMechanismList[5] = CKM_SHA256;
  pMechanismList[6] = CKM_SHA384;
  pMechanismList[7] = CKM_SHA512;
  pMechanismList[8] = CKM_MD5_RSA_PKCS;
  pMechanismList[9] = CKM_RIPEMD160_RSA_PKCS;
  pMechanismList[10] = CKM_SHA1_RSA_PKCS;
  pMechanismList[11] = CKM_SHA256_RSA_PKCS;
  pMechanismList[12] = CKM_SHA384_RSA_PKCS;
  pMechanismList[13] = CKM_SHA512_RSA_PKCS;

  DEBUG_MSG("C_GetMechanismList", "OK, returning list");
  return CKR_OK;
}

// Returns information about a mechanism.

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  DEBUG_MSG("C_GetMechanismInfo", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_GetMechanismInfo", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);
  CHECK_DEBUG_RETURN(pInfo == NULL_PTR, "C_GetMechanismInfo", "pInfo must not be a NULL_PTR",
                     CKR_ARGUMENTS_BAD);

  SoftSlot *currentSlot = softHSM->slots->getSlot(slotID);

  CHECK_DEBUG_RETURN(currentSlot == NULL_PTR, "C_GetMechanismInfo", "The given slotID does not exist",
                     CKR_SLOT_ID_INVALID);

  switch(type) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
      pInfo->ulMinKeySize = 512;
      pInfo->ulMaxKeySize = 4096;
      pInfo->flags = CKF_GENERATE_KEY_PAIR | CKF_HW;
      break;
    case CKM_RSA_PKCS:
      pInfo->ulMinKeySize = 512;
      pInfo->ulMaxKeySize = 4096;
      pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_HW;
      break;
    case CKM_MD5:
    case CKM_RIPEMD160:
    case CKM_SHA_1:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
      pInfo->flags = CKF_DIGEST | CKF_HW;
      break;
    case CKM_MD5_RSA_PKCS:
    case CKM_RIPEMD160_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
      pInfo->ulMinKeySize = 512;
      pInfo->ulMaxKeySize = 4096;
      pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_HW;
      break;
    default:
      DEBUG_MSG("C_GetMechanismInfo", "The selected mechanism is not supported");
      return CKR_MECHANISM_INVALID;
      break;
  }

  DEBUG_MSG("C_GetMechanismInfo", "OK");
  return CKR_OK; 
}

CK_RV C_InitToken(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR) {
  DEBUG_MSG("C_InitToken", "Calling");
  DEBUG_MSG("C_InitToken", "The function is not implemented. Token is always initialized.");

  return CKR_FUNCTION_NOT_SUPPORTED; 
}

CK_RV C_InitPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) {
  DEBUG_MSG("C_InitPIN", "Calling");
  DEBUG_MSG("C_InitPIN", "The function is not implemented. The PIN is always initialized.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG) {
  DEBUG_MSG("C_SetPIN", "Calling");
  DEBUG_MSG("C_SetPIN", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Opens a new session.

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
  DEBUG_MSG("C_OpenSession", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_OpenSession", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();
  CK_RV rv = softHSM->openSession(slotID, flags, pApplication, Notify, phSession);
  softHSM->unlockMutex();

  return rv;
}

// Closes the session with a given handle.

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  DEBUG_MSG("C_CloseSession", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_CloseSession", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();
  CK_RV rv = softHSM->closeSession(hSession);
  softHSM->unlockMutex();

  return rv;
}

// Closes all sessions.

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
  DEBUG_MSG("C_CloseAllSessions", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_CloseAllSessions", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();
  CK_RV rv = softHSM->closeAllSessions(slotID);
  softHSM->unlockMutex();

  return rv;
}

// Returns information about the session.

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  DEBUG_MSG("C_GetSessionInfo", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_GetSessionInfo", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();
  CK_RV rv = softHSM->getSessionInfo(hSession, pInfo);
  softHSM->unlockMutex();

  return rv;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_GetOperationState", "Calling");
  DEBUG_MSG("C_GetOperationState", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
  DEBUG_MSG("C_SetOperationState", "Calling");
  DEBUG_MSG("C_SetOperationState", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Logs a user into the token.
// Only one login is needed, since it is a cross-session login.

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  DEBUG_MSG("C_Login", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_Login", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();
  CK_RV rv = softHSM->login(hSession, userType, pPin, ulPinLen);
  softHSM->unlockMutex();

  return rv;
}

// Logs out the user from the token.
// Closes all the objects.

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
  DEBUG_MSG("C_Logout", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_Logout", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();
  CK_RV rv = softHSM->logout(hSession);
  softHSM->unlockMutex();

  return rv;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) {
  DEBUG_MSG("C_CreateObject", "Calling");
  DEBUG_MSG("C_CreateObject", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) {
  DEBUG_MSG("C_CopyObject", "Calling");
  DEBUG_MSG("C_CopyObject", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Destroys the object.

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  DEBUG_MSG("C_DestroyObject", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_DestroyObject", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();
  CK_RV rv = softHSM->destroyObject(hSession, hObject);
  softHSM->unlockMutex();

  return rv;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) {
  DEBUG_MSG("C_GetObjectSize", "Calling");
  DEBUG_MSG("C_GetObjectSize", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Returns the attributes associated with an object.

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  DEBUG_MSG("C_GetAttributeValue", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_GetAttributeValue", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();
  CK_RV rv = softHSM->getAttributeValue(hSession, hObject, pTemplate, ulCount);
  softHSM->unlockMutex();

  return rv;
}

// Add or update attributes of an object. The template is validated in accordance with
// the PKCS#11 API. Some valid attributes are neglected due to their complexity.

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  DEBUG_MSG("C_SetAttributeValue", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_SetAttributeValue", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();
  CK_RV rv = softHSM->setAttributeValue(hSession, hObject, pTemplate, ulCount);
  softHSM->unlockMutex();

  return rv;
}

// Initialize the search for objects.
// The template specifies the search pattern.

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  DEBUG_MSG("C_FindObjectsInit", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_FindObjectsInit", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();
  CK_RV rv = softHSM->findObjectsInit(hSession, pTemplate, ulCount);
  softHSM->unlockMutex();

  return rv;
}

// Returns the result of the search.

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
  DEBUG_MSG("C_FindObjects", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_FindObjects", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_FindObjects", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->findInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_FindObjects", "Find is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(phObject == NULL_PTR || pulObjectCount == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_FindObjects", "The arguments must not be NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  CK_ULONG i = 0;

  while(i < ulMaxObjectCount && session->findCurrent->next != NULL_PTR) {
    phObject[i] = session->findCurrent->findObject;
    session->findCurrent = session->findCurrent->next;
    i++;
  }

  *pulObjectCount = i;

  softHSM->unlockMutex();

  DEBUG_MSG("C_FindObjects", "OK");
  return CKR_OK;
}

// Finalizes the search.

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  DEBUG_MSG("C_FindObjectsFinal", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_FindObjectsFinal", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_FindObjectsFinal", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->findInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_FindObjectsFinal", "Find is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  DELETE_PTR(session->findAnchor);
  session->findCurrent = NULL_PTR;
  session->findInitialized = false;

  softHSM->unlockMutex();

  DEBUG_MSG("C_FindObjectsFinal", "OK");
  return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) {
  DEBUG_MSG("C_EncryptInit", "Calling");
  DEBUG_MSG("C_EncryptInit", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_Encrypt", "Calling");
  DEBUG_MSG("C_Encrypt", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_EncryptUpdate", "Calling");
  DEBUG_MSG("C_EncryptUpdate", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_EncryptFinal", "Calling");
  DEBUG_MSG("C_EncryptFinal", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) {
  DEBUG_MSG("C_DecryptInit", "Calling");
  DEBUG_MSG("C_DecryptInit", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_Decrypt", "Calling");
  DEBUG_MSG("C_Decrypt", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_DecryptUpdate", "Calling");
  DEBUG_MSG("C_DecryptUpdate", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_DecryptFinal", "Calling");
  DEBUG_MSG("C_DecryptFinal", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialize the digest functionality.

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  DEBUG_MSG("C_DigestInit", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_DigestInit", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestInit", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(session->digestInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestInit", "Digest is already initialized");
    return CKR_OPERATION_ACTIVE;
  }

  if(pMechanism == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestInit", "pMechanism must not be NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  CK_ULONG mechSize = 0;
  HashFunction *hashFunc = NULL_PTR;

  // Selects the correct hash algorithm.
  switch(pMechanism->mechanism) {
    case CKM_MD5:
      mechSize = 16;
      hashFunc = new MD5;
      break;
    case CKM_RIPEMD160:
      mechSize = 20;
      hashFunc = new RIPEMD_160;
      break;
    case CKM_SHA_1:
      mechSize = 20;
      hashFunc = new SHA_160;
      break;
    case CKM_SHA256:
      mechSize = 32;
      hashFunc = new SHA_256;
      break;
    case CKM_SHA384:
      mechSize = 48;
      hashFunc = new SHA_384;
      break;
    case CKM_SHA512:
      mechSize = 64;
      hashFunc = new SHA_512;
      break;
    default:
      softHSM->unlockMutex();

      DEBUG_MSG("C_DigestInit", "The selected mechanism is not supported");
      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestInit", "Could not create the hash function");
    return CKR_DEVICE_MEMORY;
  }

  // Creates the digester with given hash algorithm.
  session->digestSize = mechSize;
  session->digestPipe = new Pipe(new Hash_Filter(hashFunc));

  if(!session->digestPipe) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestInit", "Could not create the digesting function");
    return CKR_DEVICE_MEMORY;
  }

  session->digestPipe->start_msg();
  session->digestInitialized = true;

  softHSM->unlockMutex();

  DEBUG_MSG("C_DigestInit", "OK");
  return CKR_OK;
}

// Add data and digest.

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
      CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  DEBUG_MSG("C_Digest", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_Digest", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Digest", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->digestInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Digest", "Digest is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pulDigestLen == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Digest", "pulDigestLen must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  if(pDigest == NULL_PTR) {
    *pulDigestLen = session->digestSize;
    softHSM->unlockMutex();

    DEBUG_MSG("C_Digest", "OK, returning the size of the digest");
    return CKR_OK;
  }

  if(*pulDigestLen < session->digestSize) {
    *pulDigestLen = session->digestSize;
    softHSM->unlockMutex();

    DEBUG_MSG("C_Digest", "The given buffer is too small");
    return CKR_BUFFER_TOO_SMALL;
  }

  if(pData == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Digest", "pData must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  // Digest
  session->digestPipe->write(pData, ulDataLen);
  session->digestPipe->end_msg();

  // Returns the result
  session->digestPipe->read(pDigest, session->digestSize);
  *pulDigestLen = session->digestSize;

  // Finalizing
  session->digestSize = 0;
  delete session->digestPipe;
  session->digestPipe = NULL_PTR;
  session->digestInitialized = false;

  softHSM->unlockMutex();

  DEBUG_MSG("C_Digest", "OK");
  return CKR_OK;
}

// Adds more data that will be digested

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  DEBUG_MSG("C_DigestUpdate", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_DigestUpdate", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestUpdate", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->digestInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestUpdate", "Digest is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pPart == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestUpdate", "pPart must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  // Digest
  session->digestPipe->write(pPart, ulPartLen);

  softHSM->unlockMutex();

  DEBUG_MSG("C_DigestUpdate", "OK");
  return CKR_OK;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) {
  DEBUG_MSG("C_DigestKey", "Calling");
  DEBUG_MSG("C_DigestKey", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Digest the data.

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  DEBUG_MSG("C_DigestFinal", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_DigestFinal", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestFinal", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->digestInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestFinal", "Digest is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pulDigestLen == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestFinal", "pulDigestLen must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  if(pDigest == NULL_PTR) {
    *pulDigestLen = session->digestSize;
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestFinal", "OK, returning the size of the digest");
    return CKR_OK;
  }

  if(*pulDigestLen < session->digestSize) {
    *pulDigestLen = session->digestSize;
    softHSM->unlockMutex();

    DEBUG_MSG("C_DigestFinal", "The given buffer is too small");
    return CKR_BUFFER_TOO_SMALL;
  }

  session->digestPipe->end_msg();

  // Returns the result
  session->digestPipe->read(pDigest, session->digestSize);
  *pulDigestLen = session->digestSize;

  // Finalizing
  session->digestSize = 0;
  delete session->digestPipe;
  session->digestPipe = NULL_PTR;
  session->digestInitialized = false;

  softHSM->unlockMutex();

  DEBUG_MSG("C_DigestFinal", "OK");
  return CKR_OK;
}

// Initialize the signature functionality

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  DEBUG_MSG("C_SignInit", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_SignInit", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignInit", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  CK_BBOOL hasObject = session->db->hasObject(hKey);

  // TODO:
  //   Should also add: session->db->getBooleanAttribute(hKey, CKA_SIGN, CK_TRUE) == CK_FALSE
  //   in the if-statement below. "If this key is allowed to sign data"
  //   Not doing this for now, because you get higher performance.

  if(hasObject == CK_FALSE || session->db->getObjectClass(hKey) != CKO_PRIVATE_KEY ||
     session->db->getKeyType(hKey) != CKK_RSA) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignInit", "This key can not be used");
    return CKR_KEY_HANDLE_INVALID;
  }

  CK_BBOOL userAuth = userAuthorization(session->getSessionState(), session->db->getBooleanAttribute(hKey, CKA_TOKEN, CK_TRUE),
                                        session->db->getBooleanAttribute(hKey, CKA_PRIVATE, CK_TRUE), 0);
  if(userAuth == CK_FALSE) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignInit", "User is not authorized");
    return CKR_KEY_HANDLE_INVALID;
  }

  if(session->signInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignInit", "Sign is already initialized");
    return CKR_OPERATION_ACTIVE;
  }

  if(pMechanism == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignInit", "pMechanism must not be NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  EMSA *hashFunc = NULL_PTR;
  session->signSinglePart = false;

  // Selects the correct padding and hash algorithm.
  switch(pMechanism->mechanism) {
    case CKM_RSA_PKCS:
      hashFunc = new EMSA3_Raw();
      session->signSinglePart = true;
      break;
    case CKM_MD5_RSA_PKCS:
      hashFunc = new EMSA3(new MD5);
      break;
    case CKM_RIPEMD160_RSA_PKCS:
      hashFunc = new EMSA3(new RIPEMD_160);
      break;
    case CKM_SHA1_RSA_PKCS:
      hashFunc = new EMSA3(new SHA_160);
      break;
    case CKM_SHA256_RSA_PKCS:
      hashFunc = new EMSA3(new SHA_256);
      break;
    case CKM_SHA384_RSA_PKCS:
      hashFunc = new EMSA3(new SHA_384);
      break;
    case CKM_SHA512_RSA_PKCS:
      hashFunc = new EMSA3(new SHA_512);
      break;
    default:
      softHSM->unlockMutex();

      DEBUG_MSG("C_SignInit", "The selected mechanism is not supported");
      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignInit", "Could not create the hash function");
    return CKR_DEVICE_MEMORY;
  }

  // Get the key from the session key store.
  Public_Key *cryptoKey = session->getKey(hKey);
  if(cryptoKey == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignInit", "Could not load the crypto key");
    return CKR_GENERAL_ERROR;
  }

  // Creates the signer with given key and mechanism.
  PK_Signing_Key *signKey = dynamic_cast<PK_Signing_Key*>(cryptoKey);
  session->signSize = (cryptoKey->max_input_bits() + 7) / 8;
  session->pkSigner = new PK_Signer(*signKey, &*hashFunc);

  if(!session->pkSigner) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignInit", "Could not create the signing function");
    return CKR_DEVICE_MEMORY;
  }

  session->signInitialized = true;

  softHSM->unlockMutex();

  DEBUG_MSG("C_SignInit", "OK");
  return CKR_OK;
}

// Signs the data and return the results

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG_PTR pulSignatureLen) {
  DEBUG_MSG("C_Sign", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_Sign", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Sign", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->signInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Sign", "Sign is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pulSignatureLen == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Sign", "pulSignatureLen must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  if(pSignature == NULL_PTR) {
    *pulSignatureLen = session->signSize;
    softHSM->unlockMutex();

    DEBUG_MSG("C_Sign", "OK, returning the size of the signature");
    return CKR_OK;
  }

  if(*pulSignatureLen < session->signSize) {
    *pulSignatureLen = session->signSize;
    softHSM->unlockMutex();

    DEBUG_MSG("C_Sign", "The given buffer is too small");
    return CKR_BUFFER_TOO_SMALL;
  }

  if(pData == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Sign", "pData must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  // Sign 
  SecureVector<byte> signResult = session->pkSigner->sign_message(pData, ulDataLen, *session->rng);

  // Returns the result
  memcpy(pSignature, signResult.begin(), session->signSize);
  *pulSignatureLen = session->signSize;

  // Finalizing
  session->signSize = 0;
  delete session->pkSigner;
  session->pkSigner = NULL_PTR;
  session->signInitialized = false;

  softHSM->unlockMutex();

  DEBUG_MSG("C_Sign", "OK");
  return CKR_OK;
}

// Buffer the data before final signing

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  DEBUG_MSG("C_SignUpdate", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_SignUpdate", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignUpdate", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->signInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignUpdate", "Sign is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->signSinglePart) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignUpdate", "The mechanism can only sign single part of data");
    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pPart == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignUpdate", "pPart must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  // Buffer
  session->pkSigner->update(pPart, ulPartLen);

  softHSM->unlockMutex();

  DEBUG_MSG("C_SignUpdate", "OK");
  return CKR_OK;
}

// Signs the collected data and returns the signature.

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  DEBUG_MSG("C_SignFinal", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_SignFinal", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignFinal", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->signInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignFinal", "Sign is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->signSinglePart) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignFinal", "The mechanism can only sign single part of data");
    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pulSignatureLen == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignFinal", "pulSignatureLen must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  if(pSignature == NULL_PTR) {
    *pulSignatureLen = session->signSize;
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignFinal", "OK, returning the size of the signature");
    return CKR_OK;
  }

  if(*pulSignatureLen < session->signSize) {
    *pulSignatureLen = session->signSize;
    softHSM->unlockMutex();

    DEBUG_MSG("C_SignFinal", "The given buffer is to small");
    return CKR_BUFFER_TOO_SMALL;
  }

  // Sign
  SecureVector<byte> signResult = session->pkSigner->signature(*session->rng);

  // Returns the result
  memcpy(pSignature, signResult.begin(), session->signSize);
  *pulSignatureLen = session->signSize;

  // Finalizing
  session->signSize = 0;
  delete session->pkSigner;
  session->pkSigner = NULL_PTR;
  session->signInitialized = false;

  softHSM->unlockMutex();

  DEBUG_MSG("C_SignFinal", "OK");
  return CKR_OK;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) {
  DEBUG_MSG("C_SignRecoverInit", "Calling");
  DEBUG_MSG("C_SignRecoverInit", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_SignRecover", "Calling");
  DEBUG_MSG("C_SignRecover", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialize the verifing functionality.

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  DEBUG_MSG("C_VerifyInit", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_VerifyInit", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyInit", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  CK_BBOOL hasObject = session->db->hasObject(hKey);

  // TODO:
  //   Should also add: session->db->getBooleanAttribute(hKey, CKA_VERIFY, CK_TRUE) == CK_FALSE
  //   in the if-statement below. "If this key is allowed to verify signatures"
  //   Not doing this for now, because you get higher performance.

  if(hasObject == CK_FALSE || session->db->getObjectClass(hKey) != CKO_PUBLIC_KEY ||
     session->db->getKeyType(hKey) != CKK_RSA) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyInit", "This key can not be used");
    return CKR_KEY_HANDLE_INVALID;
  }

  CK_BBOOL userAuth = userAuthorization(session->getSessionState(), session->db->getBooleanAttribute(hKey, CKA_TOKEN, CK_TRUE),
                                        session->db->getBooleanAttribute(hKey, CKA_PRIVATE, CK_TRUE), 0);
  if(userAuth == CK_FALSE) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyInit", "User is not authorized");
    return CKR_KEY_HANDLE_INVALID;
  }

  if(session->verifyInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyInit", "Verify is already initialized");
    return CKR_OPERATION_ACTIVE;
  }

  if(pMechanism == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyInit", "pMechanism must not be NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  EMSA *hashFunc = NULL_PTR;
  session->verifySinglePart = false;

  // Selects the correct padding and hash algorithm.
  switch(pMechanism->mechanism) {
    case CKM_RSA_PKCS:
      hashFunc = new EMSA3_Raw();
      session->verifySinglePart = true;
      break;
    case CKM_MD5_RSA_PKCS:
      hashFunc = new EMSA3(new MD5);
      break;
    case CKM_RIPEMD160_RSA_PKCS:
      hashFunc = new EMSA3(new RIPEMD_160);
      break;
    case CKM_SHA1_RSA_PKCS:
      hashFunc = new EMSA3(new SHA_160);
      break;
    case CKM_SHA256_RSA_PKCS:
      hashFunc = new EMSA3(new SHA_256);
      break;
    case CKM_SHA384_RSA_PKCS:
      hashFunc = new EMSA3(new SHA_384);
      break;
    case CKM_SHA512_RSA_PKCS:
      hashFunc = new EMSA3(new SHA_512);
      break;
    default:
      softHSM->unlockMutex();

      DEBUG_MSG("C_VerifyInit", "The selected mechanism is not supported");
      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyInit", "Could not create the hash function");
    return CKR_DEVICE_MEMORY;
  }

  // Get the key from the session key store.
  Public_Key *cryptoKey = session->getKey(hKey);
  if(cryptoKey == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyInit", "Could not load the crypto key");
    return CKR_GENERAL_ERROR;
  }

  // Creates the verifier with given key and mechanism
  PK_Verifying_with_MR_Key *verifyKey = dynamic_cast<PK_Verifying_with_MR_Key*>(cryptoKey);
  session->verifySize = (cryptoKey->max_input_bits() + 7) / 8;
  session->pkVerifier = new PK_Verifier_with_MR(*verifyKey, &*hashFunc);

  if(!session->pkVerifier) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyInit", "Could not create the verifying function");
    return CKR_DEVICE_MEMORY;
  }

  session->verifyInitialized = true;

  softHSM->unlockMutex();

  DEBUG_MSG("C_VerifyInit", "OK");
  return CKR_OK;
}

// Verifies if the the signature matches the data

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG ulSignatureLen) {
  DEBUG_MSG("C_Verify", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_Verify", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Verify", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->verifyInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Verify", "Verify is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pData == NULL_PTR || pSignature == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_Verify", "pData and pSignature must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  // Add data
  session->pkVerifier->update(pData, ulDataLen);

  // Check signature length
  if(session->verifySize != ulSignatureLen) {
    // Finalizing
    delete session->pkVerifier;
    session->pkVerifier = NULL_PTR;
    session->verifyInitialized = false;

    softHSM->unlockMutex();

    DEBUG_MSG("C_Verify", "The signatures does not have the same length");
    return CKR_SIGNATURE_LEN_RANGE;
  }

  // Verify
  bool verResult = session->pkVerifier->check_signature(pSignature, ulSignatureLen);

  // Finalizing
  delete session->pkVerifier;
  session->pkVerifier = NULL_PTR;
  session->verifyInitialized = false;

  softHSM->unlockMutex();

  // Returns the result
  if(verResult) {
    DEBUG_MSG("C_Verify", "OK");
    return CKR_OK;
  } else {
    DEBUG_MSG("C_Verify", "The signature is invalid");
    return CKR_SIGNATURE_INVALID;
  }
}

// Collects the data before the final signature check.

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  DEBUG_MSG("C_VerifyUpdate", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_VerifyUpdate", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyUpdate", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->verifyInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyUpdate", "Verify is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->verifySinglePart) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyUpdate", "The mechanism can only verify single part of data");
    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pPart == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyUpdate", "pPart must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  // Add data
  session->pkVerifier->update(pPart, ulPartLen);

  softHSM->unlockMutex();

  DEBUG_MSG("C_VerifyUpdate", "OK");
  return CKR_OK;
}

// Verifies if the signature matches the collected data.

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  DEBUG_MSG("C_VerifyFinal", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_VerifyFinal", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyFinal", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->verifyInitialized) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyFinal", "Verify is not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->verifySinglePart) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyFinal", "The mechanism can only verify single part of data");
    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pSignature == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyFinal", "pSignature must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  // Check signature length
  if(session->verifySize != ulSignatureLen) {
    // Finalizing
    delete session->pkVerifier;
    session->pkVerifier = NULL_PTR;
    session->verifyInitialized = false;

    softHSM->unlockMutex();

    DEBUG_MSG("C_VerifyFinal", "The signatures does not have the same length");
    return CKR_SIGNATURE_LEN_RANGE;
  }

  // Verify
  bool verResult = session->pkVerifier->check_signature(pSignature, ulSignatureLen);

  // Finalizing
  delete session->pkVerifier;
  session->pkVerifier = NULL_PTR;
  session->verifyInitialized = false;

  softHSM->unlockMutex();

  // Returns the result
  if(verResult) {
    DEBUG_MSG("C_VerifyFinal", "OK");
    return CKR_OK;
  } else {
    DEBUG_MSG("C_VerifyFinal", "The signature is invalid");
    return CKR_SIGNATURE_INVALID;
  }
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) {
  DEBUG_MSG("C_VerifyRecoverInit", "Calling");
  DEBUG_MSG("C_VerifyRecoverInit", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_VerifyRecover", "Calling");
  DEBUG_MSG("C_VerifyRecover", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_DigestEncryptUpdate", "Calling");
  DEBUG_MSG("C_DigestEncryptUpdate", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_DecryptDigestUpdate", "Calling");
  DEBUG_MSG("C_DecryptDigestUpdate", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_SignEncryptUpdate", "Calling");
  DEBUG_MSG("C_SignEncryptUpdate", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_DecryptVerifyUpdate", "Calling");
  DEBUG_MSG("C_DecryptVerifyUpdate", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) {
  DEBUG_MSG("C_GenerateKey", "Calling");
  DEBUG_MSG("C_GenerateKey", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generates a key pair.
// For now, only RSA is supported.

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
      CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
      CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
  DEBUG_MSG("C_GenerateKeyPair", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_GenerateKeyPair", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_GenerateKeyPair", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(pMechanism == NULL_PTR || pPublicKeyTemplate == NULL_PTR || pPrivateKeyTemplate == NULL_PTR ||
     phPublicKey == NULL_PTR || phPrivateKey == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_GenerateKeyPair", "The arguments must not be NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  CK_BBOOL isToken = CK_FALSE;
  CK_BBOOL isPrivate = CK_TRUE;

  // Extract object information
  for(CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
    switch(pPrivateKeyTemplate[i].type) {
      case CKA_TOKEN:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          isToken = *(CK_BBOOL*)pPrivateKeyTemplate[i].pValue;
        }
        break;
      case CKA_PRIVATE:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          isPrivate = *(CK_BBOOL*)pPrivateKeyTemplate[i].pValue;
        }
        break;
      default:
        break;
    }
  }

  // Check user credentials
  CK_BBOOL userAuth = userAuthorization(session->getSessionState(), isToken, isPrivate, 1);
  if(userAuth == CK_FALSE) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_GenerateKeyPair", "User is not authorized");
    return CKR_USER_NOT_LOGGED_IN;
  }

  CK_RV rv;

  switch(pMechanism->mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
      rv = rsaKeyGen(session, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate,
                     ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
      softHSM->unlockMutex();
      return rv;
      break;
    default:
      break;
  }

  softHSM->unlockMutex();

  DEBUG_MSG("C_GenerateKeyPair", "The selected mechanism is not supported");
  return CKR_MECHANISM_INVALID;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, 
      CK_BYTE_PTR, CK_ULONG_PTR) {
  DEBUG_MSG("C_WrapKey", "Calling");
  DEBUG_MSG("C_WrapKey", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG,
      CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) {
  DEBUG_MSG("C_UnwrapKey", "Calling");
  DEBUG_MSG("C_UnwrapKey", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, 
      CK_ULONG, CK_OBJECT_HANDLE_PTR) {
  DEBUG_MSG("C_DeriveKey", "Calling");
  DEBUG_MSG("C_DeriveKey", "The function is not implemented.");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Reseeds the RNG

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
  DEBUG_MSG("C_SeedRandom", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_SeedRandom", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SeedRandom", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(pSeed == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_SeedRandom", "pSeed must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  session->rng->add_entropy(pSeed, ulSeedLen);
  session->rng->reseed();

  softHSM->unlockMutex();

  DEBUG_MSG("C_SeedRandom", "OK");
  return CKR_OK;
}

// Returns some random data.

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
  DEBUG_MSG("C_GenerateRandom", "Calling");

  CHECK_DEBUG_RETURN(softHSM == NULL_PTR, "C_GenerateRandom", "Library is not initialized",
                     CKR_CRYPTOKI_NOT_INITIALIZED);

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_GenerateRandom", "Can not find the session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(pRandomData == NULL_PTR) {
    softHSM->unlockMutex();

    DEBUG_MSG("C_GenerateRandom", "pRandomData must not be a NULL_PTR");
    return CKR_ARGUMENTS_BAD;
  }

  session->rng->randomize(pRandomData, ulRandomLen);

  softHSM->unlockMutex();

  DEBUG_MSG("C_GenerateRandom", "OK");
  return CKR_OK;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE) {
  DEBUG_MSG("C_GetFunctionStatus", "Calling");
  DEBUG_MSG("C_GetFunctionStatus", "Just returning. Is a legacy function.");

  return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE) {
  DEBUG_MSG("C_CancelFunction", "Calling");
  DEBUG_MSG("C_CancelFunction", "Just returning. Is a legacy function.");

  return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) {
  DEBUG_MSG("C_WaitForSlotEvent", "Calling");
  DEBUG_MSG("C_WaitForSlotEvent", "The function is not implemented");

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generates a RSA key pair with given templates.

CK_RV rsaKeyGen(SoftSession *session, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
      CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
      CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {

  CK_ULONG *modulusBits = NULL_PTR;
  // Defaults to an exponent with e = 65537
  BigInt *exponent = new Botan::BigInt("65537");;
  CHECK_DEBUG_RETURN(exponent == NULL_PTR, "C_GenerateKeyPair", "Could not allocate memory", CKR_HOST_MEMORY);

  // Extract desired key information
  for(CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch(pPublicKeyTemplate[i].type) {
      case CKA_MODULUS_BITS:
        if(pPublicKeyTemplate[i].ulValueLen != sizeof(CK_ULONG)) {
          delete exponent;

          DEBUG_MSG("C_GenerateKeyPair", "CKA_MODULUS_BITS does not have the size of CK_ULONG");
          return CKR_TEMPLATE_INCOMPLETE;
        }
        modulusBits = (CK_ULONG*)pPublicKeyTemplate[i].pValue;
        break;
      case CKA_PUBLIC_EXPONENT:
        delete exponent;
        exponent = new Botan::BigInt((byte*)pPublicKeyTemplate[i].pValue,(u32bit)pPublicKeyTemplate[i].ulValueLen);
        break;
      default:
        break;
    }
  }

  // CKA_MODULUS_BITS must be specified to be able to generate a key pair.
  if(modulusBits == NULL_PTR) {
    delete exponent;

    DEBUG_MSG("C_GenerateKeyPair", "Missing CKA_MODULUS_BITS in pPublicKeyTemplate");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  // Generate the key
  RSA_PrivateKey *rsaKey = NULL_PTR;
  try {
    rsaKey = new RSA_PrivateKey(*session->rng, (u32bit)*modulusBits, exponent->to_u32bit());
    delete exponent;
  }
  catch(...) {
    delete exponent;
    ERROR_MSG("C_GenerateKeyPair", "Could not generate key pair");
    return CKR_GENERAL_ERROR;
  }
  CHECK_DEBUG_RETURN(rsaKey == NULL_PTR, "C_GenerateKeyPair", "Could not allocate memory", CKR_HOST_MEMORY);

  // Add the private key to the database.
  CK_OBJECT_HANDLE privRef = session->db->addRSAKeyPriv(rsaKey, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);

  if(privRef == 0) {
    delete rsaKey;
    
    DEBUG_MSG("C_GenerateKeyPair", "Could not save private key in DB");
    return CKR_GENERAL_ERROR;
  }

  // Add the public key to the database.
  CK_OBJECT_HANDLE pubRef = session->db->addRSAKeyPub(rsaKey, pPublicKeyTemplate, ulPublicKeyAttributeCount);
  delete rsaKey;

  if(pubRef == 0) {
    session->db->deleteObject(privRef);

    DEBUG_MSG("C_GenerateKeyPair", "Could not save public key in DB");
    return CKR_GENERAL_ERROR;
  }

  // Returns the object handles to the application.
  *phPublicKey = pubRef;
  *phPrivateKey = privRef;

  INFO_MSG("C_GenerateKeyPair", "Key pair generated");
  DEBUG_MSG("C_GenerateKeyPair", "OK");
  return CKR_OK;
}
