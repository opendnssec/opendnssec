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
* SoftHSM
*
* Implements parts of the PKCS11 interface defined by
* RSA Labratories, PKCS11 v2.20, called Cryptoki.
*
************************************************************/

#include "main.h"
#include "SoftHSMInternal.h"
#include "mutex.h"
#include "config.h"
#include "syslog.h"

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
static SoftHSMInternal *softHSM = NULL_PTR;

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
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_Initialize");
  #endif /* SOFTDEBUG */

  CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

  if(softHSM != NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Initialize: Error: Already initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  }

  // Do we have any arguments?
  if(args != NULL_PTR) {
    // Reserved for future use. Must be NULL_PTR
    if(args->pReserved != NULL_PTR) {
      #ifdef SOFTDEBUG
        syslog(LOG_DEBUG, "C_Initialize: Error: pReserved must be NULL_PTR");
      #endif /* SOFTDEBUG */

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

        #ifdef SOFTDEBUG
          syslog(LOG_DEBUG, "C_Initialize: Error: Not all mutex functions are supplied");
        #endif /* SOFTDEBUG */

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

  // Init the Botan crypto library 
  LibraryInitializer::initialize("thread_safe=true");

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_Initialize: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Finalizes the library. Clears out any memory allocations.

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_Finalize");
  #endif /* SOFTDEBUG */

  // Reserved for future use.
  if(pReserved != NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Finalize: Error: pReserved must be NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
  }

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Finalize: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  } else {
    delete softHSM;
    softHSM = NULL_PTR;
  }

  // Deinitialize the Botan crypto lib
  LibraryInitializer::deinitialize();

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_Finalize: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Returns general information about SoftHSM.

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetInfo");
  #endif /* SOFTDEBUG */

  if(pInfo == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetInfo: Error: pInfo must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

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

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_GetInfo: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Returns the function list.

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetFunctionList");
  #endif /* SOFTDEBUG */

  *ppFunctionList = &function_list;

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_GetFunctionList: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Returns a list of all the slots.
// Only one slot is available, SlotID 1.
// And the token is present.

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetSlotList");
  #endif /* SOFTDEBUG */

  if(pSlotList != NULL_PTR) {
    pSlotList[0] = 1;
  }
  *pulCount = 1;

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_GetSlotList: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Returns information about the slot.

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetSlotInfo");
  #endif /* SOFTDEBUG */

  if(slotID != 1) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetSlotInfo: Error: slotID %i does not exist", slotID);
    #endif /* SOFTDEBUG */

    return CKR_SLOT_ID_INVALID;
  }

  if(pInfo == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetSlotInfo: Error: pInfo must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
  }

  memset(pInfo->slotDescription, ' ', 64);
  memcpy(pInfo->slotDescription, "SoftHSM", 7);
  memset(pInfo->manufacturerID, ' ', 32);
  memcpy(pInfo->manufacturerID, "SoftHSM", 7);

  pInfo->flags = CKF_TOKEN_PRESENT;
  pInfo->hardwareVersion.major = VERSION_MAJOR;
  pInfo->hardwareVersion.minor = VERSION_MINOR;
  pInfo->firmwareVersion.major = VERSION_MAJOR;
  pInfo->firmwareVersion.minor = VERSION_MINOR;

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_GetSlotInfo: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Returns information about the token.

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetTokenInfo");
  #endif /* SOFTDEBUG */

  if(slotID != 1) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetTokenInfo: Error: slotID %i does not exist", slotID);
    #endif /* SOFTDEBUG */

    return CKR_SLOT_ID_INVALID;
  }

  if(pInfo == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetTokenInfo: Error: pInfo must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
  }

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetTokenInfo: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  memset(pInfo->label, ' ', 32);
  memcpy(pInfo->label, "SoftHSM", 7);
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
  pInfo->ulMaxPinLen = 8000;
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

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_GetTokenInfo: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Returns the supported mechanisms.

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetMechanismList");
  #endif /* SOFTDEBUG */

  if(slotID != 1) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetMechanismList: Error: slotID %i does not exist", slotID);
    #endif /* SOFTDEBUG */

    return CKR_SLOT_ID_INVALID;
  }

  *pulCount = 14;

  if(pMechanismList == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetMechanismList: OK, Returning list length");
    #endif /* SOFTDEBUG */

    return CKR_OK;
  }

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

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_GetMechanismList: OK, Returning list");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Returns information about a mechanism.

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetMechanismInfo");
  #endif /* SOFTDEBUG */

  if(slotID != 1) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetMechanismInfo: Error: slotID %i does not exist", slotID);
    #endif /* SOFTDEBUG */

    return CKR_SLOT_ID_INVALID;
  }

  if(pInfo == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetMechanismInfo: Error: pInfo must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
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
      #ifdef SOFTDEBUG
        syslog(LOG_DEBUG, "C_GetMechanismInfo: Error: The selected mechanism is not supported");
      #endif /* SOFTDEBUG */

      return CKR_MECHANISM_INVALID;
      break;
  }

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_GetMechanismInfo: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK; 
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_InitToken");
    syslog(LOG_DEBUG, "C_InitToken: Error: The function is not implemented. Token is always initialized.");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED; 
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_InitPIN");
    syslog(LOG_DEBUG, "C_InitPIN: Error: The function is not implemented. The PIN is always initialized.");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_SetPIN");
    syslog(LOG_DEBUG, "C_SetPIN: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Opens a new session.

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_OpenSession");
  #endif /* SOFTDEBUG */

  if(slotID != 1) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_OpenSession: Error: slotID %i does not exist", slotID);
    #endif /* SOFTDEBUG */

    return CKR_SLOT_ID_INVALID;
  }

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_OpenSession: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->openSession(flags, pApplication, Notify, phSession);
}

// Closes the session with a given handle.

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_CloseSession");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_CloseSession: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->closeSession(hSession);
}

// Closes all sessions.

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_CloseAllSessions");
  #endif /* SOFTDEBUG */

  if(slotID != 1) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_CloseAllSessions: Error: slotID %i does not exist", slotID);
    #endif /* SOFTDEBUG */

    return CKR_SLOT_ID_INVALID;
  }

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_CloseAllSessions: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->closeAllSessions();
}

// Returns information about the session.

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetSessionInfo");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetSessionInfo: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->getSessionInfo(hSession, pInfo);
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetOperationState");
    syslog(LOG_DEBUG, "C_GetOperationState: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
      CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_SetOperationState");
    syslog(LOG_DEBUG, "C_SetOperationState: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Logs a user into the token.
// The login is needed to be able to load the correct crypto keys from the database.
// Only one login is needed, since it is a cross-session login.
// Each PIN creates a unique "user", meaning that all the crypto keys are connected to
// individual PINs.

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_Login");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Login: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->login(hSession, userType, pPin, ulPinLen);
}

// Logs out the user from the token.
// Closes all the objects.

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_Logout");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Logout: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->logout(hSession);
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_CreateObject");
    syslog(LOG_DEBUG, "C_CreateObject: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
      CK_OBJECT_HANDLE_PTR phNewObject) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_CopyObject");
    syslog(LOG_DEBUG, "C_CopyObject: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Destroys the object.

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DestroyObject");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DestroyObject: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->destroyObject(hSession, hObject);
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetObjectSize");
    syslog(LOG_DEBUG, "C_GetObjectSize: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Returns the attributes associated with an object.

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetAttributeValue");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GetAttributeValue: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->getAttributeValue(hSession, hObject, pTemplate, ulCount);
}

// Add or update attributes of an object. The template is validated in accordance with
// the PKCS#11 API. Some valid attributes are neglected due to their complexity.

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_SetAttributeValue");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SetAttributeValue: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->setAttributeValue(hSession, hObject, pTemplate, ulCount);
}

// Initialize the search for objects.
// The template specifies the search pattern.

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_FindObjectsInit");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_FindObjectsInit: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->findObjectsInit(hSession, pTemplate, ulCount);
}

// Returns the result of the search.

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_FindObjects");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_FindObjects: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_FindObjects: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->findInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_FindObjects: Error: Find is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  CK_ULONG i = 0;

  while(i < ulMaxObjectCount && session->findCurrent->next != NULL_PTR) {
    phObject[i] = session->findCurrent->findObject;
    session->findCurrent = session->findCurrent->next;
    i++;
  }

  *pulObjectCount = i;

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_FindObjects: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Finalizes the search.

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_FindObjectsFinal");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_FindObjectsFinal: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_FindObjectsFinal: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->findInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_FindObjectsFinal: Error: Find is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->findAnchor != NULL_PTR) {
    delete session->findAnchor;
    session->findAnchor = NULL_PTR;
  }

  session->findCurrent = session->findAnchor;
  session->findInitialized = false;

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_FindObjectsFinal: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_EncryptInit");
    syslog(LOG_DEBUG, "C_EncryptInit: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
      CK_ULONG_PTR pulEncryptedDataLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_Encrypt");
    syslog(LOG_DEBUG, "C_Encrypt: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
      CK_ULONG_PTR pulEncryptedPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_EncryptUpdate");
    syslog(LOG_DEBUG, "C_EncryptUpdate: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_EncryptFinal");
    syslog(LOG_DEBUG, "C_EncryptFinal: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DecryptInit");
    syslog(LOG_DEBUG, "C_DecryptInit: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_Decrypt");
    syslog(LOG_DEBUG, "C_Decrypt: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DecryptUpdate");
    syslog(LOG_DEBUG, "C_DecryptUpdate: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DecryptFinal");
    syslog(LOG_DEBUG, "C_DecryptFinal: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialize the digest functionality.

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DigestInit");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestInit: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestInit: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(session->digestInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestInit: Error: Digest is already initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_ACTIVE;
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
      #ifdef SOFTDEBUG
        syslog(LOG_DEBUG, "C_DigestInit: Error: The selected mechanism is not supported");
      #endif /* SOFTDEBUG */

      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestInit: Error: Could not create the hash function");
    #endif /* SOFTDEBUG */

    return CKR_DEVICE_MEMORY;
  }

  // Creates the digester with given hash algorithm.
  session->digestSize = mechSize;
  session->digestPipe = new Pipe(new Hash_Filter(hashFunc));

  if(!session->digestPipe) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestInit: Error: Could not create the digesting function");
    #endif /* SOFTDEBUG */

    return CKR_DEVICE_MEMORY;
  }

  session->digestPipe->start_msg();
  session->digestInitialized = true;

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_DigestInit: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Add data and digest.

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
      CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_Digest");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Digest: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Digest: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->digestInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Digest: Error: Digest is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pDigest == NULL_PTR) {
    *pulDigestLen = session->digestSize;

    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Digest: OK, returning the size of the digest");
    #endif /* SOFTDEBUG */

    return CKR_OK;
  }

  if(*pulDigestLen < session->digestSize) {
    *pulDigestLen = session->digestSize;

    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Digest: Error: The given buffer is to small");
    #endif /* SOFTDEBUG */

    return CKR_BUFFER_TOO_SMALL;
  }

  if(pData == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Digest: Error: pData must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

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

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_Digest: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Adds more data that will be digested

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DigestUpdate");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestUpdate: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestUpdate: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->digestInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestUpdate: Error: Digest is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pPart == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestUpdate: Error: pPart must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
  }

  // Digest
  session->digestPipe->write(pPart, ulPartLen);

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_DigestUpdate: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DigestKey");
    syslog(LOG_DEBUG, "C_DigestKey: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Digest the data.

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DigestFinal");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestFinal: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestFinal: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->digestInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestFinal: Error: Digest is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pDigest == NULL_PTR) {
    *pulDigestLen = session->digestSize;

    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestFinal: OK, returning the size of the digest");
    #endif /* SOFTDEBUG */

    return CKR_OK;
  }

  if(*pulDigestLen < session->digestSize) {
    *pulDigestLen = session->digestSize;

    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_DigestFinal: Error: The given buffer is to small");
    #endif /* SOFTDEBUG */

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

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_DigestFinal: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Initialize the signature functionality

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_SignInit");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignInit: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignInit: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  SoftObject *object = softHSM->getObject(hKey);

  if(object == NULL_PTR || object->objectClass != CKO_PRIVATE_KEY ||
     object->keyType != CKK_RSA) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignInit: Error: This key can not be used");
    #endif /* SOFTDEBUG */

    return CKR_KEY_HANDLE_INVALID;
  }

  if(session->signInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignInit: Error: Sign is already initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_ACTIVE;
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
      #ifdef SOFTDEBUG
        syslog(LOG_DEBUG, "C_SignInit: Error: The selected mechanism is not supported");
      #endif /* SOFTDEBUG */

      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignInit: Error: Could not create the hash function");
    #endif /* SOFTDEBUG */

    return CKR_DEVICE_MEMORY;
  }

  // Get the key from the session key store.
  Public_Key *cryptoKey = session->getKey(object);
  if(cryptoKey == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignInit: Error: Could not load the crypto key");
    #endif /* SOFTDEBUG */

    return CKR_GENERAL_ERROR;
  }

  // Creates the signer with given key and mechanism.
  PK_Signing_Key *signKey = dynamic_cast<PK_Signing_Key*>(cryptoKey);
  session->signSize = object->keySizeBytes;
  session->pkSigner = new PK_Signer(*signKey, &*hashFunc);

  if(!session->pkSigner) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignInit: Error: Could not create the signing function");
    #endif /* SOFTDEBUG */

    return CKR_DEVICE_MEMORY;
  }

  session->signInitialized = true;

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_SignInit: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Signs the data and return the results

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG_PTR pulSignatureLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_Sign");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Sign: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Sign: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->signInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Sign: Error: Sign is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pSignature == NULL_PTR) {
    *pulSignatureLen = session->signSize;

    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Sign: OK, returning the size of the signature");
    #endif /* SOFTDEBUG */

    return CKR_OK;
  }

  if(*pulSignatureLen < session->signSize) {
    *pulSignatureLen = session->signSize;

    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Sign: Error: The given buffer is to small");
    #endif /* SOFTDEBUG */

    return CKR_BUFFER_TOO_SMALL;
  }

  if(pData == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Sign: Error: pData must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

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

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_Sign: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Buffer the data before final signing

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_SignUpdate");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignUpdate: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignUpdate: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->signInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignUpdate: Error: Sign is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->signSinglePart) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignUpdate: Error: The mechanism can only sign single part of data");
    #endif /* SOFTDEBUG */

    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pPart == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignUpdate: Error: pPart must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
  }

  // Buffer
  session->pkSigner->update(pPart, ulPartLen);

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_SignUpdate: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Signs the collected data and returns the signature.

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_SignFinal");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignFinal: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignFinal: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->signInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignFinal: Error: Sign is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->signSinglePart) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignFinal: Error: The mechanism can only sign single part of data");
    #endif /* SOFTDEBUG */

    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pSignature == NULL_PTR) {
    *pulSignatureLen = session->signSize;

    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignFinal: OK, returning the size of the signature");
    #endif /* SOFTDEBUG */

    return CKR_OK;
  }

  if(*pulSignatureLen < session->signSize) {
    *pulSignatureLen = session->signSize;

    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SignFinal: Error: The given buffer is to small");
    #endif /* SOFTDEBUG */

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

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_SignFinal: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_SignRecoverInit");
    syslog(LOG_DEBUG, "C_SignRecoverInit: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG_PTR pulSignatureLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_SignRecover");
    syslog(LOG_DEBUG, "C_SignRecover: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialize the verifing functionality.

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_VerifyInit");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyInit: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyInit: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  SoftObject *object = softHSM->getObject(hKey);

  if(object == NULL_PTR || object->objectClass != CKO_PUBLIC_KEY ||
     object->keyType != CKK_RSA) {
    return CKR_KEY_HANDLE_INVALID;
  }

  if(session->verifyInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyInit: Error: Verify is already initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_ACTIVE;
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
      #ifdef SOFTDEBUG
        syslog(LOG_DEBUG, "C_VerifyInit: Error: The selected mechanism is not supported");
      #endif /* SOFTDEBUG */

      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyInit: Error: Could not create the hash function");
    #endif /* SOFTDEBUG */

    return CKR_DEVICE_MEMORY;
  }

  // Get the key from the session key store.
  Public_Key *cryptoKey = session->getKey(object);
  if(cryptoKey == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyInit: Error: Could not load the crypto key");
    #endif /* SOFTDEBUG */

    return CKR_GENERAL_ERROR;
  }

  // Creates the verifier with given key and mechanism
  PK_Verifying_with_MR_Key *verifyKey = dynamic_cast<PK_Verifying_with_MR_Key*>(cryptoKey);
  session->verifySize = object->keySizeBytes;
  session->pkVerifier = new PK_Verifier_with_MR(*verifyKey, &*hashFunc);

  if(!session->pkVerifier) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyInit: Error: Could not create the verifying function");
    #endif /* SOFTDEBUG */

    return CKR_DEVICE_MEMORY;
  }

  session->verifyInitialized = true;

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_VerifyInit: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Verifies if the the signature matches the data

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG ulSignatureLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_Verify");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Verify: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Verify: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->verifyInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Verify: Error: Verify is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pData == NULL_PTR || pSignature == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Verify: Error: pData and pSignature must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
  }

  // Add data
  session->pkVerifier->update(pData, ulDataLen);

  // Check signature length
  if(session->verifySize != ulSignatureLen) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Verify: The signatures does not have the same length");
    #endif /* SOFTDEBUG */

    return CKR_SIGNATURE_LEN_RANGE;
  }

  // Verify
  bool verResult = session->pkVerifier->check_signature(pSignature, ulSignatureLen);

  // Finalizing
  delete session->pkVerifier;
  session->pkVerifier = NULL_PTR;
  session->verifyInitialized = false;

  // Returns the result
  if(verResult) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Verify: OK");
    #endif /* SOFTDEBUG */

    return CKR_OK;
  } else {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_Verify: The signature is invalid");
    #endif /* SOFTDEBUG */

    return CKR_SIGNATURE_INVALID;
  }
}

// Collects the data before the final signature check.

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_VerifyUpdate");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyUpdate: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyUpdate: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->verifyInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyUpdate: Error: Verify is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->verifySinglePart) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyUpdate: Error: The mechanism can only verify single part of data");
    #endif /* SOFTDEBUG */

    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pPart == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyUpdate: Error: pPart must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
  }

  // Add data
  session->pkVerifier->update(pPart, ulPartLen);

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_VerifyUpdate: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Verifies if the signature matches the collected data.

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_VerifyFinal");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyFinal: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyFinal: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->verifyInitialized) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyFinal: Error: Verify is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->verifySinglePart) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyFinal: Error: The mechanism can only verify single part of data");
    #endif /* SOFTDEBUG */

    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pSignature == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyFinal: Error: pSignature must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
  }

  // Check signature length
  if(session->verifySize != ulSignatureLen) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyFinal: The signatures does not have the same length");
    #endif /* SOFTDEBUG */

    return CKR_SIGNATURE_LEN_RANGE;
  }

  // Verify
  bool verResult = session->pkVerifier->check_signature(pSignature, ulSignatureLen);

  // Finalizing
  delete session->pkVerifier;
  session->pkVerifier = NULL_PTR;
  session->verifyInitialized = false;

  // Returns the result
  if(verResult) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyFinal: OK");
    #endif /* SOFTDEBUG */

    return CKR_OK;
  } else {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_VerifyFinal: The signature is invalid");
    #endif /* SOFTDEBUG */

    return CKR_SIGNATURE_INVALID;
  }
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_VerifyRecoverInit");
    syslog(LOG_DEBUG, "C_VerifyRecoverInit: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_VerifyRecover");
    syslog(LOG_DEBUG, "C_VerifyRecover: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
      CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DigestEncryptUpdate");
    syslog(LOG_DEBUG, "C_DigestEncryptUpdate: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DecryptDigestUpdate");
    syslog(LOG_DEBUG, "C_DecryptDigestUpdate: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
      CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_SignEncryptUpdate");
    syslog(LOG_DEBUG, "C_SignEncryptUpdate: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DecryptVerifyUpdate");
    syslog(LOG_DEBUG, "C_DecryptVerifyUpdate: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
      CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GenerateKey");
    syslog(LOG_DEBUG, "C_GenerateKey: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generates a key pair.
// For now, only RSA is supported.

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
      CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
      CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GenerateKeyPair");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GenerateKeyPair: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GenerateKeyPair: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(!session->isReadWrite()) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GenerateKeyPair: Error: The session is read only");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_READ_ONLY;
  }

  if(softHSM->isLoggedIn() == false) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GenerateKeyPair: Error: The user is not logged in");
    #endif /* SOFTDEBUG */

    return CKR_USER_NOT_LOGGED_IN;
  }

  if(ulPublicKeyAttributeCount < 1 || ulPrivateKeyAttributeCount < 1) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GenerateKeyPair: Error: Must provide some templates");
    #endif /* SOFTDEBUG */

    return CKR_TEMPLATE_INCONSISTENT;
  }

  switch(pMechanism->mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
      return rsaKeyGen(session, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate,
             ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
      break;
    default:
      break;
  }

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_GenerateKeyPair: Error: The selected mechanism is not supported");
  #endif /* SOFTDEBUG */

  return CKR_MECHANISM_INVALID;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
      CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_WrapKey");
    syslog(LOG_DEBUG, "C_WrapKey: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
      CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
      CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_UnwrapKey");
    syslog(LOG_DEBUG, "C_UnwrapKey: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_DeriveKey");
    syslog(LOG_DEBUG, "C_DeriveKey: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Reseeds the RNG

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_SeedRandom");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SeedRandom: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SeedRandom: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(pSeed == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_SeedRandom: Error: pSeed must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
  }

  session->rng->add_entropy(pSeed, ulSeedLen);
  session->rng->reseed();

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_SeedRandom: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

// Returns some random data.

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GenerateRandom");
  #endif /* SOFTDEBUG */

  if(softHSM == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GenerateRandom: Error: Library is not initialized");
    #endif /* SOFTDEBUG */

    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session = softHSM->getSession(hSession);

  if(session == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GenerateRandom: Error: Can not find the session");
    #endif /* SOFTDEBUG */

    return CKR_SESSION_HANDLE_INVALID;
  }

  if(pRandomData == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GenerateRandom: Error: pRandomData must not be a NULL_PTR");
    #endif /* SOFTDEBUG */

    return CKR_ARGUMENTS_BAD;
  }

  session->rng->randomize(pRandomData, ulRandomLen);

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_SeedRandom: OK");
  #endif /* SOFTDEBUG */

  return CKR_OK;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_GetFunctionStatus");
    syslog(LOG_DEBUG, "C_GetFunctionStatus: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_CancelFunction");
    syslog(LOG_DEBUG, "C_CancelFunction: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "Calling C_WaitForSlotEvent");
    syslog(LOG_DEBUG, "C_WaitForSlotEvent: Error: The function is not implemented");
  #endif /* SOFTDEBUG */

  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generates a RSA key pair with given templates.

CK_RV rsaKeyGen(SoftSession *session, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
      CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
      CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {

  CK_ULONG *modulusBits = NULL_PTR;
  BigInt *exponent = NULL_PTR;

  // Extract desired key information
  for(CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch(pPublicKeyTemplate[i].type) {
      case CKA_MODULUS_BITS:
        if(pPublicKeyTemplate[i].ulValueLen != sizeof(CK_ULONG)) {
          #ifdef SOFTDEBUG
            syslog(LOG_DEBUG, "C_GenerateKeyPair: Error: CKA_MODULUS_BITS does not have the size of CK_ULONG");
          #endif /* SOFTDEBUG */

          return CKR_TEMPLATE_INCONSISTENT;
        }
        modulusBits = (CK_ULONG*)pPublicKeyTemplate[i].pValue;
        break;
      case CKA_PUBLIC_EXPONENT:
        exponent = new Botan::BigInt((byte*)pPublicKeyTemplate[i].pValue,(u32bit)pPublicKeyTemplate[i].ulValueLen);
        break;
      default:
        break;
    }
  }

  // CKA_MODULUS_BITS must be specified to be able to generate a key pair.
  if(modulusBits == NULL_PTR) {
    #ifdef SOFTDEBUG
      syslog(LOG_DEBUG, "C_GenerateKeyPair: Error: Missing CKA_MODULUS_BITS in pPublicKeyTemplate");
    #endif /* SOFTDEBUG */

    return CKR_TEMPLATE_INCOMPLETE;
  }

  // Defaults to an exponent with e = 65537
  if(exponent == NULL_PTR) {
    exponent = new Botan::BigInt("65537");
  }

  // Generate the key
  RSA_PrivateKey *rsaKey = new RSA_PrivateKey(*session->rng, (u32bit)*modulusBits, exponent->to_u32bit());

  // Default label/ID if nothing is specified by the user.
  char *labelID = getNewLabelAndID();

  // Add the key to the database.
  CK_OBJECT_HANDLE privRef = session->db->addRSAKeyPriv(softHSM->getPIN(), rsaKey, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, labelID);
  CK_OBJECT_HANDLE pubRef = session->db->addRSAKeyPub(softHSM->getPIN(), rsaKey, pPublicKeyTemplate, ulPublicKeyAttributeCount, labelID);

  // Update the internal states.
  softHSM->getObjectFromDB(privRef);
  softHSM->getObjectFromDB(pubRef);

  // Returns the object handles to the application.
  *phPublicKey = pubRef;
  *phPrivateKey = privRef;

  #ifdef SOFTDEBUG
    syslog(LOG_DEBUG, "C_GenerateKeyPair: OK");
  #endif /* SOFTDEBUG */

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
