/* $Id: main.cpp 65 2008-11-27 10:13:37Z jakob $ */

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

// Initialize the Botan library
Botan::LibraryInitializer init;

// Keeps the internal state
SoftHSMInternal *softHSM = NULL_PTR;

#include <file.cpp>
#include <SoftHSMInternal.cpp>
#include <SoftSession.cpp>
#include <SoftObject.cpp>
#include <SoftFind.cpp>
#include <SoftAttribute.cpp>

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
// Supply the function with NULL_PTR if no threading
// Threading not supported yet.

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  if(softHSM != NULL_PTR) {
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  }

  softHSM = new SoftHSMInternal();

  return CKR_OK;
}

// Finalizes the library. Clears out any memory allocations.

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  // Reserved for future use.
  if(pReserved != NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  } else {
    delete softHSM;
    softHSM = NULL_PTR;
  }

  // Should be finalize the Botan library?

  return CKR_OK;
}

// Returns general information about SoftHSM.

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
  if(sizeof(*pInfo) != sizeof(CK_INFO)) {
    return CKR_ARGUMENTS_BAD;
  }

  pInfo->cryptokiVersion.major = 2;
  pInfo->cryptokiVersion.minor = 20;
  snprintf((char *)pInfo->manufacturerID, sizeof(pInfo->manufacturerID), 
    "SoftHSM                         ");
    // 32 chars
  pInfo->flags = 0;
  snprintf((char *)pInfo->libraryDescription, sizeof(pInfo->libraryDescription), 
    "Implementation of PKCS11        ");
    // 32 chars
  pInfo->libraryVersion.major = VERSION_MAJOR;
  pInfo->libraryVersion.minor = VERSION_MINOR;

  return CKR_OK;
}

// Returns the function list.

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  *ppFunctionList = &function_list;
  return CKR_OK;
}

// Returns a list of all the slots.
// Only one slot is available, SlotID 1.
// And the token is present.

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  if(pSlotList != NULL_PTR) {
    pSlotList[0] = 1;
  }
  *pulCount = 1;
  return CKR_OK;
}

// Returns information about the slot.

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  if(slotID != 1) {
    return CKR_SLOT_ID_INVALID;
  }

  if(pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  snprintf((char *)pInfo->slotDescription, sizeof(pInfo->slotDescription), 
     "SoftHSM                                                         ");
     // 64 chars
  snprintf((char *)pInfo->manufacturerID, sizeof(pInfo->manufacturerID), 
    "SoftHSM                         ");
    // 32 chars
  pInfo->flags = CKF_TOKEN_PRESENT;
  pInfo->hardwareVersion.major = VERSION_MAJOR;
  pInfo->hardwareVersion.minor = VERSION_MINOR;
  pInfo->firmwareVersion.major = VERSION_MAJOR;
  pInfo->firmwareVersion.minor = VERSION_MINOR;

  return CKR_OK;
}

// Returns information about the token.

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  if(slotID != 1) {
    return CKR_SLOT_ID_INVALID;
  }

  if(pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  snprintf((char *)pInfo->label, sizeof(pInfo->label), 
    "SoftHSM                         ");
    // 32 chars
  snprintf((char *)pInfo->manufacturerID, sizeof(pInfo->manufacturerID), 
    "SoftHSM                         "); 
    // 32 chars
  snprintf((char *)pInfo->model, sizeof(pInfo->model), 
    "SoftHSM         "); 
    // 16 chars
  snprintf((char *)pInfo->serialNumber, sizeof(pInfo->serialNumber), 
    "1               "); 
    // 16 chars
  pInfo->flags = CKF_RNG | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | 
                 CKF_LOGIN_REQUIRED;

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

  return CKR_OK;
}

// Returns the supported mechanisms.

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  if(slotID != 1) {
    return CKR_SLOT_ID_INVALID;
  }

  *pulCount = 14;

  if(pMechanismList == NULL_PTR) {
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

  return CKR_OK;
}

// Returns information about a mechanism.

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  if(slotID != 1) {
    return CKR_SLOT_ID_INVALID;
  }

  if(pInfo == NULL_PTR) {
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
      pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT | CKF_HW;
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
      return CKR_MECHANISM_INVALID;
      break;
  }

  return CKR_OK; 
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
  return CKR_FUNCTION_NOT_SUPPORTED; 
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Opens a new session.

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
  if(slotID != 1) {
    return CKR_SLOT_ID_INVALID;
  }

  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->openSession(flags, pApplication, Notify, phSession);
}

// Closes the session with a given handle.

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->closeSession(hSession);
}

// Closes all sessions.

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
  if(slotID != 1) {
    return CKR_SLOT_ID_INVALID;
  }

  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->closeAllSessions();
}

// Returns information about the session.

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->getSessionInfo(hSession, pInfo);
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
      CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Logs a user into the token.
// The login is needed to decrypt the crypto keys when loading
// them from the disk and to generate crypto keys.
// Only one login is needed, since it is a cross-session login.

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->login(hSession, userType, pPin, ulPinLen);
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
      CK_OBJECT_HANDLE_PTR phNewObject) {
  return CKR_FUNCTION_NOT_SUPPORTED;
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

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->destroyObject(hSession, hObject);
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Returns the attributes associated with an object.

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->getAttributeValue(hSession, hObject, pTemplate, ulCount);
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialize the search for objects.
// The template specifies the search pattern.

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  return softHSM->findObjectsInit(hSession, pTemplate, ulCount);
}

// Returns the result of the search.

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(!session->findInitialized) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  unsigned int i = 0;

  while(i < ulMaxObjectCount && session->findCurrent->next != NULL_PTR) {
    phObject[i] = session->findCurrent->findObject;
    session->findCurrent = session->findCurrent->next;
    i++;
  }

  *pulObjectCount = i;

  return CKR_OK;
}

// Finalizes the search.

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(!session->findInitialized) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->findAnchor != NULL_PTR) {
    delete session->findAnchor;
    session->findAnchor = NULL_PTR;
  }

  session->findCurrent = session->findAnchor;
  session->findInitialized = false;

  return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
      CK_ULONG_PTR pulEncryptedDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
      CK_ULONG_PTR pulEncryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Initialize the digest functionality.

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(session->digestInitialized) {
    return CKR_OPERATION_ACTIVE;
  }

  unsigned int mechSize = 0;
  HashFunction *hashFunc = NULL_PTR;

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
      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    return CKR_DEVICE_MEMORY;
  }

  session->digestSize = mechSize;
  session->digestPipe = new Pipe(new Hash_Filter(hashFunc));

  if(!session->digestPipe) {
    return CKR_DEVICE_MEMORY;
  }

  session->digestPipe->start_msg();
  session->digestInitialized = true;

  return CKR_OK;
}

// Add data and digest.

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
      CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(!session->digestInitialized) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pDigest == NULL_PTR) {
    *pulDigestLen = session->digestSize;
    return CKR_OK;
  }

  if(*pulDigestLen < session->digestSize) {
    *pulDigestLen = session->digestSize;
    return CKR_BUFFER_TOO_SMALL;
  }

  if(pData == NULL_PTR) {
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

  return CKR_OK;
}

// Adds more data that will be digested

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(!session->digestInitialized) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pPart == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  // Digest
  session->digestPipe->write(pPart, ulPartLen);

  return CKR_OK;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Digest the data.

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(!session->digestInitialized) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pDigest == NULL_PTR) {
    *pulDigestLen = session->digestSize;
    return CKR_OK;
  }

  if(*pulDigestLen < session->digestSize) {
    *pulDigestLen = session->digestSize;
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

  return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  SoftObject *object;
  result = softHSM->getObject(hKey, object);

  if(result != CKR_OK || object->getObjectClass() != CKO_PRIVATE_KEY ||
     object->getKeyType() != CKK_RSA) {
    return CKR_ARGUMENTS_BAD;
  }

  if(session->signInitialized) {
    return CKR_OPERATION_ACTIVE;
  }

  EMSA *hashFunc = NULL_PTR;
  session->signSinglePart = false;

  switch(pMechanism->mechanism) {
    case CKM_RSA_PKCS:
      // Is not correct.
      // We do not want to use a hash function in this case...
      hashFunc = new EMSA_Raw();
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
      // Botan can verify itself, but the signature is not
      // the same as the one from OpenSSL.
      hashFunc = new EMSA3(new SHA_512);
      break;
    default:
      return CKR_MECHANISM_INVALID;
      break;
  }

  if(hashFunc == NULL_PTR) {
    return CKR_DEVICE_MEMORY;
  }

  PK_Signing_Key *signKey = dynamic_cast<PK_Signing_Key*>(object->getKey());
  session->signSize = object->getKeySizeBytes();
  session->pkSigner = new PK_Signer(*signKey, &*hashFunc);

  if(!session->pkSigner) {
      return CKR_DEVICE_MEMORY;
  }

  session->signInitialized = true;

  return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG_PTR pulSignatureLen) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(!session->signInitialized) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(pSignature == NULL_PTR) {
    *pulSignatureLen = session->signSize;
    return CKR_OK;
  }

  if(*pulSignatureLen < session->signSize) {
    *pulSignatureLen = session->signSize;
    return CKR_BUFFER_TOO_SMALL;
  }

  if(pData == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  // Sign 
  SecureVector<byte> signResult = session->pkSigner->sign_message(pData, ulDataLen, *softHSM->rng);

  // Returns the result
  memcpy(pSignature, signResult.begin(), session->signSize);
  *pulSignatureLen = session->signSize;

  // Finalizing
  session->signSize = 0;
  delete session->pkSigner;
  session->pkSigner = NULL_PTR;
  session->signInitialized = false;

  return CKR_OK;  
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(!session->signInitialized) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->signSinglePart) {
    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pPart == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  // Buffer
  session->pkSigner->update(pPart, ulPartLen);

  return CKR_OK;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(!session->signInitialized) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->signSinglePart) {
    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  if(pSignature == NULL_PTR) {
    *pulSignatureLen = session->signSize;
    return CKR_OK;
  }

  if(*pulSignatureLen < session->signSize) {
    *pulSignatureLen = session->signSize;
    return CKR_BUFFER_TOO_SMALL;
  }

  // Sign
  SecureVector<byte> signResult = session->pkSigner->signature(*softHSM->rng);

  // Returns the result
  memcpy(pSignature, signResult.begin(), session->signSize);
  *pulSignatureLen = session->signSize;

  // Finalizing
  session->signSize = 0;
  delete session->pkSigner;
  session->pkSigner = NULL_PTR;
  session->signInitialized = false;

  return CKR_OK;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG_PTR pulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG ulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
      CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
      CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
      CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Generates a key par.
// For now, only RSA is supported.

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
      CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
      CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(softHSM->isLoggedIn() == false) {
    return CKR_USER_NOT_LOGGED_IN;
  }

  if(pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN) {
    return CKR_MECHANISM_INVALID;
  }

  if(ulPublicKeyAttributeCount < 1 || ulPrivateKeyAttributeCount < 1) {
    return CKR_TEMPLATE_INCONSISTENT;
  }

  u32bit *modulusBits = NULL_PTR;
  BigInt *exponent = NULL_PTR;

  // Extract desired key information
  for(unsigned int i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch(pPublicKeyTemplate[i].type) {
      case CKA_MODULUS_BITS:
        if(pPublicKeyTemplate[i].ulValueLen != 4) {
          return CKR_TEMPLATE_INCONSISTENT;
        }
        modulusBits = (u32bit*)pPublicKeyTemplate[i].pValue;
        break;
      case CKA_PUBLIC_EXPONENT:
        exponent = new Botan::BigInt((Botan::byte*)pPublicKeyTemplate[i].pValue,pPublicKeyTemplate[i].ulValueLen);
        break;
      default:
        break;
    }
  }

  // CKA_MODULUS_BITS must be specified to be able to generate a key pair.
  if(modulusBits == NULL_PTR) {
    // Should we do any clean up?
    return CKR_MECHANISM_INVALID;
  }

  // Defaults to an exponent with e = 65537
  if(exponent == NULL_PTR) {
    exponent = new Botan::BigInt("65537");
  }

  // Creates new objects
  SoftObject *privateKey = new SoftObject();
  SoftObject *publicKey = new SoftObject();
  // Retrieves the internal RNG.
  AutoSeeded_RNG *rng = softHSM->rng;

  // Generate the key
  RSA_PrivateKey *rsaKey = new RSA_PrivateKey(*rng, *modulusBits, exponent->to_u32bit());

  // Get a new Label/ID based on the current date/time down to microseconds.
  char *fileName = getNewFileName();

  // Add the key to the private object.
  result = privateKey->addKey(rsaKey, CKO_PRIVATE_KEY, fileName);
  if(result != CKR_OK) {
    // Should we do any clean up?
    return result;
  }

  // Add the key to the public object.
  result = publicKey->addKey(rsaKey, CKO_PUBLIC_KEY, fileName);
  if(result != CKR_OK) {
    // Should we do any clean up?
    return result;
  }

  // Add the objects to the token.
  int privateRef = softHSM->addObject(privateKey);
  int publicRef = softHSM->addObject(publicKey);

  if(!publicRef || !privateRef) {
    // Should we do any clean up?
    return CKR_DEVICE_MEMORY;
  }

  // Save the private key on disk.
  result = privateKey->saveKey(softHSM);
  if(result != CKR_OK) {
    return result;
  }

  // Returns the object handles to the application.
  *phPrivateKey = (CK_OBJECT_HANDLE)privateRef;
  *phPublicKey = (CK_OBJECT_HANDLE)publicRef;

  return CKR_OK;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey,
      CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey,
      CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
      CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

// Reseeds the RNG

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(pSeed == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  softHSM->rng->add_entropy(pSeed, ulSeedLen);
  softHSM->rng->reseed();

  return CKR_OK;
}

// Returns some random data.

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
  if(softHSM == NULL_PTR) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  SoftSession *session;
  CK_RV result = softHSM->getSession(hSession, session);

  if(result != CKR_OK) {
    return result;
  }

  if(pRandomData == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  softHSM->rng->randomize(pRandomData, ulRandomLen);

  return CKR_OK;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}
