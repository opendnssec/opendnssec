/************************************************************
*
* SoftHSM
*
* Implements parts of the PKCS11 interface defined by
* RSA Labratories, PKCS11 v2.20, called Cryptoki.
*
************************************************************/

#include <main.h>

// Initialize the Botan library
Botan::LibraryInitializer init;

// Keeps the internal state
SoftHSMInternal *softHSM = NULL_PTR;

#include <file.cpp>
#include <SoftHSMInternal.cpp>
#include <SoftSession.cpp>
#include <SoftObject.cpp>
#include <SoftFind.cpp>

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

  *pulCount = 1;

  if(pMechanismList == NULL_PTR) {
    return CKR_OK;
  }

  pMechanismList[0] = CKM_RSA_PKCS_KEY_PAIR_GEN;
//  pMechanismList[1] = CKM_RSA_PKCS;
//  pMechanismList[2] = CKM_SHA1_RSA_PKCS;
//  pMechanismList[3] = CKM_SHA256_RSA_PKCS;
//  pMechanismList[4] = CKM_SHA384_RSA_PKCS;
//  pMechanismList[5] = CKM_SHA512_RSA_PKCS;
//  pMechanismList[6] = CKM_SHA_1;
//  pMechanismList[7] = CKM_SHA256;
//  pMechanismList[8] = CKM_SHA384;
//  pMechanismList[9] = CKM_SHA512;

  return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  return CKR_FUNCTION_NOT_SUPPORTED; 
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

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  return CKR_FUNCTION_NOT_SUPPORTED;
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
// If ulCount == 0, then all objects will be found.
// A search with attributs will only match objects
// if it specifies:
//    CKA_CLASS = (CKO_PRIVATE_KEY or CKO_PUBLIC_KEY)
// and
//    CKA_LABEL or CKA_ID

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

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
      CK_ULONG_PTR pulDigestLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG_PTR pulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
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

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
  return CKR_FUNCTION_NOT_SUPPORTED;
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
