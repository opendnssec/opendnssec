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
#include "config.h"
#include "log.h"
#include "file.h"
#include "SoftHSMInternal.h"
#include "userhandling.h"

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
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Initialize", "Calling");
  #endif

  CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

  if(softHSM != NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Initialize", "Already initialized");
    #endif

    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  }

  // Do we have any arguments?
  if(args != NULL_PTR) {
    // Reserved for future use. Must be NULL_PTR
    if(args->pReserved != NULL_PTR) {
      #if SOFTLOGLEVEL >= SOFTDEBUG
        logDebug("C_Initialize", "pReserved must be NULL_PTR");
      #endif

      return CKR_ARGUMENTS_BAD;
    }

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
      if(args->CreateMutex == NULL_PTR ||
         args->DestroyMutex == NULL_PTR ||
         args->LockMutex == NULL_PTR ||
         args->UnlockMutex == NULL_PTR) {

        #if SOFTLOGLEVEL >= SOFTDEBUG
          logDebug("C_Initialize", "Not all mutex functions are supplied");
        #endif

        return CKR_ARGUMENTS_BAD;
      }

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

  CK_RV rv = readConfigFile();
  if(rv != CKR_OK) {
    delete softHSM;

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Initialize", "Error in config file");
    #endif

    return rv;
  }

  // Init the Botan crypto library 
  LibraryInitializer::initialize("thread_safe=true");

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Initialize", "OK");
  #endif

  return CKR_OK;
}

// Finalizes the library. Clears out any memory allocations.

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Finalize", "Calling");
  #endif

  // Reserved for future use.
  if(pReserved != NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Finalize", "pReserved must be NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Finalize", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  } else {
    delete softHSM;
    softHSM = NULL_PTR;
  }

  // Deinitialize the Botan crypto lib
  LibraryInitializer::deinitialize();

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Finalize", "OK");
  #endif

  return CKR_OK;
}

// Returns general information about SoftHSM.

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetInfo", "Calling");
  #endif

  if(pInfo == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetInfo", "pInfo must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  pInfo->cryptokiVersion.major = 2;
  pInfo->cryptokiVersion.minor = 20;
  memset(pInfo->manufacturerID, ' ', 32);
  memcpy(pInfo->manufacturerID, "SoftHSM", 7);
  pInfo->flags = 0;
  memset(pInfo->libraryDescription, ' ', 32);
  memcpy(pInfo->libraryDescription, "Implementation of PKCS11", 24);
  pInfo->libraryVersion.major = VERSION_MAJOR;
  pInfo->libraryVersion.minor = VERSION_MINOR;

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetInfo", "OK");
  #endif

  return CKR_OK;
}

// Returns the function list.

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetFunctionList", "Calling");
  #endif

  if(ppFunctionList == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetFunctionList", "ppFunctionList must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  *ppFunctionList = &function_list;

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetFunctionList", "OK");
  #endif

  return CKR_OK;
}

// Returns a list of all the slots.
// Only one slot is available, SlotID 1.
// And the token is present.

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetSlotList", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetSlotList", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if(pulCount == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetSlotList", "pulCount must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

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
  int bufSize = 0;
  if(tokenPresent == CK_TRUE) {
    bufSize = nrTokenPresent;
  } else {
    bufSize = nrToken;
  }

  // The user wants the buffer size
  if(pSlotList == NULL_PTR) {
    *pulCount = bufSize;

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetSlotList", "OK, returning list length");
    #endif

    return CKR_OK;
  }

  // Is the given buffer to small?
  if(*pulCount < bufSize) {
    *pulCount = bufSize;

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetSlotList", "The buffer is too small");
    #endif

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

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetSlotList", "OK, returning list");
  #endif

  return CKR_OK;
}

// Returns information about the slot.

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetSlotInfo", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetSlotInfo", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if(pInfo == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetSlotInfo", "pInfo must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  SoftSlot *currentSlot = softHSM->slots->getSlot(slotID);

  if(currentSlot == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetSlotInfo", "The given slotID does not exist");
    #endif

    return CKR_SLOT_ID_INVALID;
  }

  memset(pInfo->slotDescription, ' ', 64);
  memcpy(pInfo->slotDescription, "SoftHSM", 7);
  memset(pInfo->manufacturerID, ' ', 32);
  memcpy(pInfo->manufacturerID, "SoftHSM", 7);

  pInfo->flags = currentSlot->slotFlags;
  pInfo->hardwareVersion.major = VERSION_MAJOR;
  pInfo->hardwareVersion.minor = VERSION_MINOR;
  pInfo->firmwareVersion.major = VERSION_MAJOR;
  pInfo->firmwareVersion.minor = VERSION_MINOR;

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetSlotInfo", "OK");
  #endif

  return CKR_OK;
}

// Returns information about the token.

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetTokenInfo", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetTokenInfo", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if(pInfo == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetTokenInfo", "pInfo must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  SoftSlot *currentSlot = softHSM->slots->getSlot(slotID);

  if(currentSlot == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetTokenInfo", "The given slotID does not exist");
    #endif

    return CKR_SLOT_ID_INVALID;
  }

  if((currentSlot->slotFlags & CKF_TOKEN_PRESENT) == 0) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetTokenInfo", "The token is not present");
    #endif

    return CKR_TOKEN_NOT_PRESENT;
  }

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

  pInfo->flags = CKF_RNG | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | 
                 CKF_LOGIN_REQUIRED | CKF_CLOCK_ON_TOKEN;

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

  char *dateTime = (char*)malloc(17);
  struct timeval now;
  gettimeofday(&now, NULL);
  struct tm *timeinfo = gmtime(&now.tv_sec);

  snprintf(dateTime, 17, "20%02u%02u%02u%02u%02u%02u00", timeinfo->tm_year - 100, timeinfo->tm_mon + 1, timeinfo->tm_mday,
           timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
  memcpy(pInfo->utcTime, dateTime, 16);
  free(dateTime);

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetTokenInfo", "OK");
  #endif

  return CKR_OK;
}

// Returns the supported mechanisms.

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetMechanismList", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetMechanismList", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if(pulCount == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
     logDebug("C_GetMechanismList", "pulCount must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  SoftSlot *currentSlot = softHSM->slots->getSlot(slotID);

  if(currentSlot == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
     logDebug("C_GetMechanismList", "The given slotID does note exist");
    #endif

    return CKR_SLOT_ID_INVALID;
  }

  if(pMechanismList == NULL_PTR) {
    *pulCount = 14;

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetMechanismList", "OK, returning list length");
    #endif

    return CKR_OK;
  }

  if(*pulCount < 14) {
    *pulCount = 14;

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetMechanismList", "Buffer to small");
    #endif

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

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetMechanismList", "OK, returning list");
  #endif

  return CKR_OK;
}

// Returns information about a mechanism.

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetMechanismInfo", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetMechanismInfo", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if(pInfo == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetMechanismInfo", "pInfo must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  SoftSlot *currentSlot = softHSM->slots->getSlot(slotID);

  if(currentSlot == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetMechanismInfo", "The given slotID does not exist");
    #endif

    return CKR_SLOT_ID_INVALID;
  }

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
      #if SOFTLOGLEVEL >= SOFTDEBUG
        logDebug("C_GetMechanismInfo", "The selected mechanism is not supported");
      #endif

      return CKR_MECHANISM_INVALID;
      break;
  }

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetMechanismInfo", "OK");
  #endif

  return CKR_OK; 
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_InitToken", "Calling");
    logDebug("C_InitToken", "The function is not implemented. Token is always initialized.");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED; 
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_InitPIN", "Calling");
    logDebug("C_InitPIN", "The function is not implemented. The PIN is always initialized.");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SetPIN", "Calling");
    logDebug("C_SetPIN", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Opens a new session.

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_OpenSession", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_OpenSession", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();
  CK_RV rv = softHSM->openSession(slotID, flags, pApplication, Notify, phSession);
  softHSM->unlockMutex();

  return rv;
}

// Closes the session with a given handle.

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_CloseSession", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_CloseSession", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();
  CK_RV rv = softHSM->closeSession(hSession);
  softHSM->unlockMutex();

  return rv;
}

// Closes all sessions.

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_CloseAllSessions", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_CloseAllSessions", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();
  CK_RV rv = softHSM->closeAllSessions(slotID);
  softHSM->unlockMutex();

  return rv;
}

// Returns information about the session.

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetSessionInfo", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetSessionInfo", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();
  CK_RV rv = softHSM->getSessionInfo(hSession, pInfo);
  softHSM->unlockMutex();

  return rv;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetOperationState", "Calling");
    logDebug("C_GetOperationState", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
      CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SetOperationState", "Calling");
    logDebug("C_SetOperationState", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Logs a user into the token.
// The login is needed to be able to load the correct crypto keys from the database.
// Only one login is needed, since it is a cross-session login.
// Each PIN creates a unique "user", meaning that all the crypto keys are connected to
// individual PINs.

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Login", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Login", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();
  CK_RV rv = softHSM->login(hSession, userType, pPin, ulPinLen);
  softHSM->unlockMutex();

  return rv;
}

// Logs out the user from the token.
// Closes all the objects.

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Logout", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Logout", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();
  CK_RV rv = softHSM->logout(hSession);
  softHSM->unlockMutex();

  return rv;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_CreateObject", "Calling");
    logDebug("C_CreateObject", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
      CK_OBJECT_HANDLE_PTR phNewObject) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_CopyObject", "Calling");
    logDebug("C_CopyObject", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Destroys the object.

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DestroyObject", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DestroyObject", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();
  CK_RV rv = softHSM->destroyObject(hSession, hObject);
  softHSM->unlockMutex();

  return rv;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetObjectSize", "Calling");
    logDebug("C_GetObjectSize", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Returns the attributes associated with an object.

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetAttributeValue", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GetAttributeValue", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();
  CK_RV rv = softHSM->getAttributeValue(hSession, hObject, pTemplate, ulCount);
  softHSM->unlockMutex();

  return rv;
}

// Add or update attributes of an object. The template is validated in accordance with
// the PKCS#11 API. Some valid attributes are neglected due to their complexity.

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SetAttributeValue", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SetAttributeValue", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();
  CK_RV rv = softHSM->setAttributeValue(hSession, hObject, pTemplate, ulCount);
  softHSM->unlockMutex();

  return rv;
}

// Initialize the search for objects.
// The template specifies the search pattern.

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_FindObjectsInit", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_FindObjectsInit", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();
  CK_RV rv = softHSM->findObjectsInit(hSession, pTemplate, ulCount);
  softHSM->unlockMutex();

  return rv;
}

// Returns the result of the search.

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_FindObjects", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_FindObjects", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_FindObjects", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->findInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_FindObjects", "Find is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(phObject == NULL_PTR || pulObjectCount == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_FindObjects", "The arguments must not be NULL_PTR");
    #endif

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

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_FindObjects", "OK");
  #endif

  return CKR_OK;
}

// Finalizes the search.

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_FindObjectsFinal", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_FindObjectsFinal", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_FindObjectsFinal", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->findInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_FindObjectsFinal", "Find is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->findAnchor != NULL_PTR) {
    delete session->findAnchor;
    session->findAnchor = NULL_PTR;
  }

  session->findCurrent = session->findAnchor;
  session->findInitialized = false;

  softHSM->unlockMutex();

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_FindObjectsFinal", "OK");
  #endif

  return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_EncryptInit", "Calling");
    logDebug("C_EncryptInit", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
      CK_ULONG_PTR pulEncryptedDataLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Encrypt", "Calling");
    logDebug("C_Encrypt", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
      CK_ULONG_PTR pulEncryptedPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_EncryptUpdate", "Calling");
    logDebug("C_EncryptUpdate", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_EncryptFinal", "Calling");
    logDebug("C_EncryptFinal", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DecryptInit", "Calling");
    logDebug("C_DecryptInit", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Decrypt", "Calling");
    logDebug("C_Decrypt", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DecryptUpdate", "Calling");
    logDebug("C_DecryptUpdate", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DecryptFinal", "Calling");
    logDebug("C_DecryptFinal", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialize the digest functionality.

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DigestInit", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestInit", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestInit", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(session->digestInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestInit", "Digest is already initialized");
    #endif

    return CKR_OPERATION_ACTIVE;
  }

  if(pMechanism == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestInit", "pMechanism must not be NULL_PTR");
    #endif

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

      #if SOFTLOGLEVEL >= SOFTDEBUG
        logDebug("C_DigestInit", "The selected mechanism is not supported");
      #endif

      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestInit", "Could not create the hash function");
    #endif

    return CKR_DEVICE_MEMORY;
  }

  // Creates the digester with given hash algorithm.
  session->digestSize = mechSize;
  session->digestPipe = new Pipe(new Hash_Filter(hashFunc));

  if(!session->digestPipe) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestInit", "Could not create the digesting function");
    #endif

    return CKR_DEVICE_MEMORY;
  }

  session->digestPipe->start_msg();
  session->digestInitialized = true;

  softHSM->unlockMutex();

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DigestInit", "OK");
  #endif

  return CKR_OK;
}

// Add data and digest.

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
      CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Digest", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Digest", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Digest", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->digestInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Digest", "Digest is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pulDigestLen == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Digest", "pulDigestLen must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  if(pDigest == NULL_PTR) {
    *pulDigestLen = session->digestSize;
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Digest", "OK, returning the size of the digest");
    #endif

    return CKR_OK;
  }

  if(*pulDigestLen < session->digestSize) {
    *pulDigestLen = session->digestSize;
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Digest", "The given buffer is too small");
    #endif

    return CKR_BUFFER_TOO_SMALL;
  }

  if(pData == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Digest", "pData must not be a NULL_PTR");
    #endif

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

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Digest", "OK");
  #endif

  return CKR_OK;
}

// Adds more data that will be digested

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DigestUpdate", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestUpdate", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestUpdate", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->digestInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestUpdate", "Digest is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pPart == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestUpdate", "pPart must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  // Digest
  session->digestPipe->write(pPart, ulPartLen);

  softHSM->unlockMutex();

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DigestUpdate", "OK");
  #endif

  return CKR_OK;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DigestKey", "Calling");
    logDebug("C_DigestKey", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Digest the data.

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DigestFinal", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestFinal", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestFinal", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->digestInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestFinal", "Digest is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pulDigestLen == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestFinal", "pulDigestLen must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  if(pDigest == NULL_PTR) {
    *pulDigestLen = session->digestSize;
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
     logDebug("C_DigestFinal", "OK, returning the size of the digest");
    #endif

    return CKR_OK;
  }

  if(*pulDigestLen < session->digestSize) {
    *pulDigestLen = session->digestSize;
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_DigestFinal", "The given buffer is too small");
    #endif

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

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DigestFinal", "OK");
  #endif

  return CKR_OK;
}

// Initialize the signature functionality

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SignInit", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignInit", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignInit", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  SoftObject *object = session->currentSlot->objects->getObject(hKey);

  if(object == NULL_PTR || object->objectClass != CKO_PRIVATE_KEY ||
     object->keyType != CKK_RSA) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignInit", "This key can not be used");
    #endif

    return CKR_KEY_HANDLE_INVALID;
  }

  CK_BBOOL userAuth = userAuthorization(session->getSessionState(), object->isToken, object->isPrivate, 0);
  if(userAuth == CK_FALSE) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignInit", "User is not authorized");
    #endif

    return CKR_KEY_HANDLE_INVALID;
  }

  if(session->signInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignInit", "Sign is already initialized");
    #endif

    return CKR_OPERATION_ACTIVE;
  }

  if(pMechanism == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignInit", "pMechanism must not be NULL_PTR");
    #endif

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

      #if SOFTLOGLEVEL >= SOFTDEBUG
        logDebug("C_SignInit", "The selected mechanism is not supported");
      #endif

      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignInit", "Could not create the hash function");
    #endif

    return CKR_DEVICE_MEMORY;
  }

  // Get the key from the session key store.
  Public_Key *cryptoKey = session->getKey(object);
  if(cryptoKey == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignInit", "Could not load the crypto key");
    #endif

    return CKR_GENERAL_ERROR;
  }

  // Creates the signer with given key and mechanism.
  PK_Signing_Key *signKey = dynamic_cast<PK_Signing_Key*>(cryptoKey);
  session->signSize = object->keySizeBytes;
  session->pkSigner = new PK_Signer(*signKey, &*hashFunc);

  if(!session->pkSigner) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignInit", "Could not create the signing function");
    #endif

    return CKR_DEVICE_MEMORY;
  }

  session->signInitialized = true;

  softHSM->unlockMutex();

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SignInit", "OK");
  #endif

  return CKR_OK;
}

// Signs the data and return the results

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG_PTR pulSignatureLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Sign", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Sign", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Sign", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->signInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Sign", "Sign is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pulSignatureLen == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Sign", "pulSignatureLen must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  if(pSignature == NULL_PTR) {
    *pulSignatureLen = session->signSize;
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Sign", "OK, returning the size of the signature");
    #endif

    return CKR_OK;
  }

  if(*pulSignatureLen < session->signSize) {
    *pulSignatureLen = session->signSize;
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Sign", "The given buffer is too small");
    #endif

    return CKR_BUFFER_TOO_SMALL;
  }

  if(pData == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Sign", "pData must not be a NULL_PTR");
    #endif

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

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Sign", "OK");
  #endif

  return CKR_OK;
}

// Buffer the data before final signing

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SignUpdate", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignUpdate", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignUpdate", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->signInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignUpdate", "Sign is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->signSinglePart) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignUpdate", "The mechanism can only sign single part of data");
    #endif

    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pPart == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignUpdate", "pPart must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  // Buffer
  session->pkSigner->update(pPart, ulPartLen);

  softHSM->unlockMutex();

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SignUpdate", "OK");
  #endif

  return CKR_OK;
}

// Signs the collected data and returns the signature.

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SignFinal", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignFinal", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignFinal", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->signInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignFinal", "Sign is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->signSinglePart) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignFinal", "The mechanism can only sign single part of data");
    #endif

    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pulSignatureLen == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignFinal", "pulSignatureLen must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  if(pSignature == NULL_PTR) {
    *pulSignatureLen = session->signSize;
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignFinal", "OK, returning the size of the signature");
    #endif

    return CKR_OK;
  }

  if(*pulSignatureLen < session->signSize) {
    *pulSignatureLen = session->signSize;
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SignFinal", "The given buffer is to small");
    #endif

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

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SignFinal", "OK");
  #endif

  return CKR_OK;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SignRecoverInit", "Calling");
    logDebug("C_SignRecoverInit", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG_PTR pulSignatureLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SignRecover", "Calling");
    logDebug("C_SignRecover", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialize the verifing functionality.

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_VerifyInit", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyInit", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyInit", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  SoftObject *object = session->currentSlot->objects->getObject(hKey);

  if(object == NULL_PTR || object->objectClass != CKO_PUBLIC_KEY ||
     object->keyType != CKK_RSA) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyInit", "This key can not be used");
    #endif

    return CKR_KEY_HANDLE_INVALID;
  }

  CK_BBOOL userAuth = userAuthorization(session->getSessionState(), object->isToken, object->isPrivate, 0);
  if(userAuth == CK_FALSE) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyInit", "User is not authorized");
    #endif

    return CKR_KEY_HANDLE_INVALID;
  }

  if(session->verifyInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyInit", "Verify is already initialized");
    #endif

    return CKR_OPERATION_ACTIVE;
  }

  if(pMechanism == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyInit", "pMechanism must not be NULL_PTR");
    #endif

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

      #if SOFTLOGLEVEL >= SOFTDEBUG
        logDebug("C_VerifyInit", "The selected mechanism is not supported");
      #endif

      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyInit", "Could not create the hash function");
    #endif

    return CKR_DEVICE_MEMORY;
  }

  // Get the key from the session key store.
  Public_Key *cryptoKey = session->getKey(object);
  if(cryptoKey == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyInit", "Could not load the crypto key");
    #endif

    return CKR_GENERAL_ERROR;
  }

  // Creates the verifier with given key and mechanism
  PK_Verifying_with_MR_Key *verifyKey = dynamic_cast<PK_Verifying_with_MR_Key*>(cryptoKey);
  session->verifySize = object->keySizeBytes;
  session->pkVerifier = new PK_Verifier_with_MR(*verifyKey, &*hashFunc);

  if(!session->pkVerifier) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyInit", "Could not create the verifying function");
    #endif

    return CKR_DEVICE_MEMORY;
  }

  session->verifyInitialized = true;

  softHSM->unlockMutex();

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_VerifyInit", "OK");
  #endif

  return CKR_OK;
}

// Verifies if the the signature matches the data

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG ulSignatureLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_Verify", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Verify", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Verify", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->verifyInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Verify", "Verify is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pData == NULL_PTR || pSignature == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Verify", "pData and pSignature must not be a NULL_PTR");
    #endif

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

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Verify", "The signatures does not have the same length");
    #endif

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
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Verify", "OK");
    #endif

    return CKR_OK;
  } else {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_Verify", "The signature is invalid");
    #endif

    return CKR_SIGNATURE_INVALID;
  }
}

// Collects the data before the final signature check.

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_VerifyUpdate", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyUpdate", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyUpdate", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->verifyInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyUpdate", "Verify is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->verifySinglePart) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyUpdate", "The mechanism can only verify single part of data");
    #endif

    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pPart == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyUpdate", "pPart must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  // Add data
  session->pkVerifier->update(pPart, ulPartLen);

  softHSM->unlockMutex();

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_VerifyUpdate", "OK");
  #endif

  return CKR_OK;
}

// Verifies if the signature matches the collected data.

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_VerifyFinal", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyFinal", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyFinal", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->verifyInitialized) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyFinal", "Verify is not initialized");
    #endif

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->verifySinglePart) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyFinal", "The mechanism can only verify single part of data");
    #endif

    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pSignature == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyFinal", "pSignature must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  // Check signature length
  if(session->verifySize != ulSignatureLen) {
    // Finalizing
    delete session->pkVerifier;
    session->pkVerifier = NULL_PTR;
    session->verifyInitialized = false;

    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyFinal", "The signatures does not have the same length");
    #endif

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
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyFinal", "OK");
    #endif

    return CKR_OK;
  } else {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_VerifyFinal", "The signature is invalid");
    #endif

    return CKR_SIGNATURE_INVALID;
  }
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_VerifyRecoverInit", "Calling");
    logDebug("C_VerifyRecoverInit", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_VerifyRecover", "Calling");
    logDebug("C_VerifyRecover", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
      CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DigestEncryptUpdate", "Calling");
    logDebug("C_DigestEncryptUpdate", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DecryptDigestUpdate", "Calling");
    logDebug("C_DecryptDigestUpdate", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
      CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SignEncryptUpdate", "Calling");
    logDebug("C_SignEncryptUpdate", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DecryptVerifyUpdate", "Calling");
    logDebug("C_DecryptVerifyUpdate", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
      CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GenerateKey", "Calling");
    logDebug("C_GenerateKey", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generates a key pair.
// For now, only RSA is supported.

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
      CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
      CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GenerateKeyPair", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GenerateKeyPair", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GenerateKeyPair", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(pMechanism == NULL_PTR || pPublicKeyTemplate == NULL_PTR || pPrivateKeyTemplate == NULL_PTR ||
     phPublicKey == NULL_PTR || phPrivateKey == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GenerateKeyPair", "The arguments must not be NULL_PTR");
    #endif

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

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GenerateKeyPair", "User is not authorized");
    #endif

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

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GenerateKeyPair", "The selected mechanism is not supported");
  #endif

  return CKR_MECHANISM_INVALID;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
      CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_WrapKey", "Calling");
    logDebug("C_WrapKey", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
      CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
      CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_UnwrapKey", "Calling");
    logDebug("C_UnwrapKey", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_DeriveKey", "Calling");
    logDebug("C_DeriveKey", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Reseeds the RNG

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SeedRandom", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SeedRandom", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SeedRandom", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(pSeed == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_SeedRandom", "pSeed must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  session->rng->add_entropy(pSeed, ulSeedLen);
  session->rng->reseed();

  softHSM->unlockMutex();

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_SeedRandom", "OK");
  #endif

  return CKR_OK;
}

// Returns some random data.

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GenerateRandom", "Calling");
  #endif

  if(softHSM == NULL_PTR) {
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GenerateRandom", "Library is not initialized");
    #endif

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  softHSM->lockMutex();

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GenerateRandom", "Can not find the session");
    #endif

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(pRandomData == NULL_PTR) {
    softHSM->unlockMutex();

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GenerateRandom", "pRandomData must not be a NULL_PTR");
    #endif

    return CKR_ARGUMENTS_BAD;
  }

  session->rng->randomize(pRandomData, ulRandomLen);

  softHSM->unlockMutex();

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GenerateRandom", "OK");
  #endif

  return CKR_OK;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GetFunctionStatus", "Calling");
    logDebug("C_GetFunctionStatus", "Just returning. Is a legacy function.");
  #endif

  return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_CancelFunction", "Calling");
    logDebug("C_CancelFunction", "Just returning. Is a legacy function.");
  #endif

  return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_WaitForSlotEvent", "Calling");
    logDebug("C_WaitForSlotEvent", "The function is not implemented");
  #endif

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generates a RSA key pair with given templates.

CK_RV rsaKeyGen(SoftSession *session, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
      CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
      CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {

  CK_ULONG *modulusBits = NULL_PTR;
  // Defaults to an exponent with e = 65537
  BigInt *exponent = new Botan::BigInt("65537");;

  // Extract desired key information
  for(CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch(pPublicKeyTemplate[i].type) {
      case CKA_MODULUS_BITS:
        if(pPublicKeyTemplate[i].ulValueLen != sizeof(CK_ULONG)) {
          delete exponent;

          #if SOFTLOGLEVEL >= SOFTDEBUG
            logDebug("C_GenerateKeyPair", "CKA_MODULUS_BITS does not have the size of CK_ULONG");
          #endif

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

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GenerateKeyPair", "Missing CKA_MODULUS_BITS in pPublicKeyTemplate");
    #endif

    return CKR_TEMPLATE_INCOMPLETE;
  }

  // Generate the key
  RSA_PrivateKey *rsaKey = new RSA_PrivateKey(*session->rng, (u32bit)*modulusBits, exponent->to_u32bit());
  delete exponent;

  // Default label/ID if nothing is specified by the user.
  char *labelID = getNewLabelAndID();

  // Add the private key to the database.
  CK_OBJECT_HANDLE privRef = session->db->addRSAKeyPriv(session->currentSlot->userPIN, rsaKey, pPrivateKeyTemplate, 
                                                        ulPrivateKeyAttributeCount, labelID, session->rng);

  if(privRef == 0) {
    free(labelID);
    delete rsaKey;
    
    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GenerateKeyPair", "Could not save private key in DB");
    #endif

    return CKR_GENERAL_ERROR;
  }

  // Add the public key to the database.
  CK_OBJECT_HANDLE pubRef = session->db->addRSAKeyPub(rsaKey, pPublicKeyTemplate, ulPublicKeyAttributeCount, labelID);
  free(labelID);
  delete rsaKey;

  if(pubRef == 0) {
    session->db->deleteObject(privRef);

    #if SOFTLOGLEVEL >= SOFTDEBUG
      logDebug("C_GenerateKeyPair", "Could not save public key in DB");
    #endif

    return CKR_GENERAL_ERROR;
  }

  // Update the internal states.
  session->currentSlot->getObjectFromDB(session, pubRef);
  session->currentSlot->getObjectFromDB(session, privRef);

  // Returns the object handles to the application.
  *phPublicKey = pubRef;
  *phPrivateKey = privRef;

  #if SOFTLOGLEVEL >= SOFTINFO
    logInfo("C_GenerateKeyPair", "Key pair generated");
  #endif

  #if SOFTLOGLEVEL >= SOFTDEBUG
    logDebug("C_GenerateKeyPair", "OK");
  #endif

  return CKR_OK;
}

// Return a new label/ID
// It is the current date/time down to microseconds
// This should be enough collision resistant.

char* getNewLabelAndID() {
  char *labelAndID = (char *)malloc(19);

  struct timeval now;
  gettimeofday(&now, NULL);
  struct tm *timeinfo = gmtime(&now.tv_sec);

  snprintf(labelAndID, 19, "%02u%02u%02u%02u%02u%02u%06u", timeinfo->tm_year - 100, timeinfo->tm_mon + 1, timeinfo->tm_mday,
           timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, (unsigned int)now.tv_usec);

  return labelAndID;
}
