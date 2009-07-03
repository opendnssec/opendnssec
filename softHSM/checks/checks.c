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

#include <config.h>
#include "checks.h"
#include "pkcs11_unix.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

CK_UTF8CHAR userPIN[] = {"123456"};
CK_UTF8CHAR soPIN[] = {"12345678"};

CK_ULONG slotWithToken = 1;
CK_ULONG slotWithNoToken = 0;
CK_ULONG slotWithNotInitToken = 2;
CK_ULONG slotInvalid = 9999;

void usage() {
  printf("Usage: checks [options]\n");
  printf("Options:\n");
  printf("-a\t\tTest init and finalization functions\n");
  printf("-b\t\tTest info functions\n");
  printf("-c\t\tTest session functions\n");
  printf("-d\t\tTest user functions\n");
  printf("-e\t\tTest random functions\n");
  printf("-f\t\tTest key generation and object creation/deletion\n");
  printf("-g\t\tTest object functions\n");
  printf("-h\t\tShow this help screen\n");
  printf("-i\t\tTest digest functions\n");
  printf("-j\t\tTest sign functions\n");
  printf("-k\t\tTest verify functions\n");
  printf("\n-z\t\tRun all tests\n");
}

int main(int argc, char **argv) {
  int c;

  setenv("SOFTHSM_CONF", CHECKS_SOFTHSM_CONF, 1);

  if(argc == 1) {
    usage();
  }

  /* Init token */
  inittoken();

  while ((c = getopt(argc, argv, "abcdefghijkz")) != -1) {
    switch(c) {
      case 'a':
        runInitCheck(5);
        break;
      case 'b':
        runInfoCheck(5);
        break;
      case 'c':
        runSessionCheck(5);
        break;
      case 'd':
        runUserCheck(5);
        break;
      case 'e':
        runRandomCheck(5);
        break;
      case 'f':
        runGenerateCheck(5);
        break;
      case 'g':
        runObjectCheck(5);
        break;
      case 'h':
        usage();
        break;
      case 'i':
        runDigestCheck(5);
        break;
      case 'j':
        runSignCheck(5);
        break;
      case 'k':
        runVerifyCheck(5);
        break;
      case 'z':
        runInitCheck(5);
        runInfoCheck(5);
        runSessionCheck(5);
        runUserCheck(5);
        runRandomCheck(5);
        runGenerateCheck(5);
        runObjectCheck(5);
        runDigestCheck(5);
        runSignCheck(5);
        runVerifyCheck(5);
        break;
      default:
        usage();
        break;
    }
  }

  return 0;
}

void inittoken() {
  CK_RV rv;
  CK_SESSION_HANDLE hSession;
  CK_UTF8CHAR paddedLabel[32];
  char *textLabel;

  rv = C_Initialize(NULL_PTR);
  if(rv != CKR_OK) {
    printf("\nCan not initialize SoftHSM.\n");
    printf("There are probably some problem with the token config file located at: %s\n", CHECKS_SOFTHSM_CONF);
    exit(1);
  }

  textLabel = "A token";
  memset(paddedLabel, ' ', sizeof(paddedLabel));
  memcpy(paddedLabel, textLabel, strlen(textLabel));
  rv = C_InitToken(slotWithToken, soPIN, sizeof(soPIN) - 1, paddedLabel);

  switch(rv) {
    case CKR_OK:
      break;
    case CKR_SLOT_ID_INVALID:
      printf("Error: The given slot does not exist. Make sure that slot nr %lu is in the softhsm.conf\n", slotWithToken);
      exit(1);
      break;
    case CKR_PIN_INCORRECT:
      printf("Error: The given SO PIN does not match the one in the token.\n");
      exit(1);
      break;
    default:
      printf("Error: The library could not initialize the token.\n");
      exit(1);
      break;
  }

  rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    printf("Error: Could not open a session with the library.\n");
    exit(1);
  }

  rv = C_Login(hSession, CKU_SO, soPIN, sizeof(soPIN) - 1);
  if(rv != CKR_OK) {
    printf("Error: Could not log in on the token.\n");
    exit(1);
  }

  rv = C_InitPIN(hSession, userPIN, sizeof(userPIN) - 1);
  if(rv != CKR_OK) {
    printf("Error: Could not initialize the user PIN.\n");
    exit(1);
  }

  rv = C_Finalize(NULL_PTR);
  if(rv != CKR_OK) {
    printf("Error: Could not finalize SoftHSM.\n");
    exit(1);
  }
}

void runInitCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_Initialize and C_Finalize: ");

  for(i = 0; i < counter; i++) {
    CK_C_INITIALIZE_ARGS InitArgs;
    CK_RV rv;

    InitArgs.CreateMutex = NULL_PTR;
    InitArgs.DestroyMutex = NULL_PTR;
    InitArgs.LockMutex = NULL_PTR;
    InitArgs.UnlockMutex = (CK_UNLOCKMUTEX)1;
    InitArgs.flags = CKF_OS_LOCKING_OK;
    InitArgs.pReserved = (CK_VOID_PTR)1;

    rv = C_Finalize((CK_VOID_PTR)1);
    assert(rv == CKR_ARGUMENTS_BAD);

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    rv = C_Initialize((CK_VOID_PTR)&InitArgs);
    assert(rv == CKR_ARGUMENTS_BAD);

    InitArgs.pReserved = NULL_PTR;
    rv = C_Initialize((CK_VOID_PTR)&InitArgs);
    assert(rv == CKR_ARGUMENTS_BAD);

    InitArgs.UnlockMutex = NULL_PTR;
    rv = C_Initialize((CK_VOID_PTR)&InitArgs);
    assert(rv == CKR_OK);

    rv = C_Initialize((CK_VOID_PTR)&InitArgs);
    assert(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);
  }

  printf("OK\n");
}

void runInfoCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_GetInfo, C_GetFunctionList, C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_INFO ckInfo;
    CK_FUNCTION_LIST_PTR ckFuncList;
    CK_ULONG ulSlotCount = 0;
    CK_SLOT_ID_PTR pSlotList;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
    CK_ULONG ulCount;
    CK_MECHANISM_TYPE_PTR pMechanismList;
    CK_MECHANISM_INFO info;

    /* No init */

    rv = C_GetSlotList(CK_FALSE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetSlotInfo(slotInvalid, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetTokenInfo(slotInvalid, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetMechanismList(slotInvalid, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetMechanismInfo(slotInvalid, CKM_VENDOR_DEFINED, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    /* C_GetInfo */

    rv = C_GetInfo(NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);

    rv = C_GetInfo(&ckInfo);
    assert(rv == CKR_OK);

    /* C_GetFunctionList */
    
    rv = C_GetFunctionList(NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);

    rv = C_GetFunctionList(&ckFuncList);
    assert(rv == CKR_OK);

    /* C_GetSlotList */

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_GetSlotList(CK_FALSE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
    assert(rv == CKR_OK);

    pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    ulSlotCount = 0;
    rv = C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    assert(rv == CKR_BUFFER_TOO_SMALL);
    rv = C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    assert(rv == CKR_OK);
    free(pSlotList);

    rv = C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotCount);
    assert(rv == CKR_OK);
    pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    ulSlotCount = 0;
    rv = C_GetSlotList(CK_TRUE, pSlotList, &ulSlotCount);
    assert(rv == CKR_BUFFER_TOO_SMALL);
    rv = C_GetSlotList(CK_TRUE, pSlotList, &ulSlotCount);
    assert(rv == CKR_OK);
    free(pSlotList);

    /* C_GetSlotInfo */

    rv = C_GetSlotInfo(slotInvalid, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GetSlotInfo(slotInvalid, &slotInfo);
    assert(rv == CKR_SLOT_ID_INVALID);
    rv = C_GetSlotInfo(slotWithToken, &slotInfo);
    assert(rv == CKR_OK);

    /* C_GetTokenInfo */

    rv = C_GetTokenInfo(slotInvalid, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GetTokenInfo(slotInvalid, &tokenInfo);
    assert(rv == CKR_SLOT_ID_INVALID);
    rv = C_GetTokenInfo(slotWithNoToken, &tokenInfo);
    assert(rv == CKR_TOKEN_NOT_PRESENT);
    rv = C_GetTokenInfo(slotWithToken, &tokenInfo);
    assert(rv == CKR_OK);

    /* C_GetMechanismList */

    rv = C_GetMechanismList(slotInvalid, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GetMechanismList(slotInvalid, NULL_PTR, &ulCount);
    assert(rv == CKR_SLOT_ID_INVALID);
    rv = C_GetMechanismList(slotWithToken, NULL_PTR, &ulCount);
    assert(rv == CKR_OK);
    pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(ulCount * sizeof(CK_MECHANISM_TYPE));
    ulCount = 0;
    rv = C_GetMechanismList(slotWithToken, pMechanismList, &ulCount);
    assert(rv == CKR_BUFFER_TOO_SMALL);
    rv = C_GetMechanismList(slotWithToken, pMechanismList, &ulCount);
    assert(rv == CKR_OK);
    free(pMechanismList);

    /* C_GetMechanismInfo */
    
    rv = C_GetMechanismInfo(slotInvalid, CKM_VENDOR_DEFINED, NULL_PTR);
    assert(rv == CKR_SLOT_ID_INVALID);
    rv = C_GetMechanismInfo(slotWithToken, CKM_VENDOR_DEFINED, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GetMechanismInfo(slotWithToken, CKM_VENDOR_DEFINED, &info);
    assert(rv == CKR_MECHANISM_INVALID);
    rv = C_GetMechanismInfo(slotWithToken, CKM_RSA_PKCS_KEY_PAIR_GEN, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_MD5, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_RIPEMD160, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA_1, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA256, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA384, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA512, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_MD5_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_RIPEMD160_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA1_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA256_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA384_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA512_RSA_PKCS, &info);
    assert(rv == CKR_OK);

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);
  }

  printf("OK\n");
}

void runSessionCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_OpenSession, C_CloseSession, C_CloseAllSessions, and C_GetSessionInfo: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    CK_SESSION_INFO info;

    /* No init */

    rv = C_OpenSession(slotInvalid, 0, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_CloseSession(CK_INVALID_HANDLE);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_CloseAllSessions(slotInvalid);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetSessionInfo(CK_INVALID_HANDLE, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    /* C_OpenSession */

    rv = C_OpenSession(slotInvalid, 0, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SLOT_ID_INVALID);
    rv = C_OpenSession(slotWithNoToken, 0, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_TOKEN_NOT_PRESENT);
    rv = C_OpenSession(slotWithNotInitToken, 0, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_TOKEN_NOT_RECOGNIZED);
    rv = C_OpenSession(slotWithToken, 0, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);

    /* C_CloseSession */

    rv = C_CloseSession(CK_INVALID_HANDLE);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_CloseSession(hSession[0]);
    assert(rv == CKR_OK);

    /* C_CloseAllSessions */

    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[2]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[3]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[4]);
    assert(rv == CKR_OK);
    rv = C_CloseSession(hSession[3]);
    assert(rv == CKR_OK);
    rv = C_CloseAllSessions(slotInvalid);
    assert(rv == CKR_SLOT_ID_INVALID);
    rv = C_CloseAllSessions(slotWithNoToken);
    assert(rv == CKR_OK);
    rv = C_CloseSession(hSession[2]);
    assert(rv == CKR_OK);
    rv = C_CloseAllSessions(slotWithToken);
    assert(rv == CKR_OK);
    
    /* C_GetSessionInfo */

    rv = C_GetSessionInfo(CK_INVALID_HANDLE, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);
    rv = C_GetSessionInfo(hSession[0], NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GetSessionInfo(hSession[0], &info);
    assert(rv == CKR_OK);
    rv = C_GetSessionInfo(hSession[1], &info);
    assert(rv == CKR_OK);

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

  }

  printf("OK\n");
}

void runUserCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_Login and C_Logout: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];

    /* No init */

    rv = C_Login(CK_INVALID_HANDLE, 9999, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_Logout(CK_INVALID_HANDLE);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);

    /* C_Login */

    rv = C_Login(CK_INVALID_HANDLE, 9999, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_Login(hSession[0], 9999, NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_Login(hSession[0], 9999, userPIN, MIN_PIN_LEN - 1);
    assert(rv == CKR_PIN_INCORRECT);
    rv = C_Login(hSession[0], 9999, userPIN, MAX_PIN_LEN + 1);
    assert(rv == CKR_PIN_INCORRECT);
    rv = C_Login(hSession[0], 9999, userPIN, sizeof(userPIN) - 2);
    assert(rv == CKR_USER_TYPE_INVALID);
    rv = C_Login(hSession[0], CKU_CONTEXT_SPECIFIC, userPIN, sizeof(userPIN) - 2);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_Login(hSession[0], CKU_USER, userPIN, sizeof(userPIN) - 2);
    assert(rv == CKR_PIN_INCORRECT);
    rv = C_Login(hSession[0], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[0], CKU_CONTEXT_SPECIFIC, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_SO, soPIN, sizeof(soPIN) - 2);
    assert(rv == CKR_USER_TOO_MANY_TYPES);
    rv = C_Logout(hSession[0]);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_SO, soPIN, sizeof(soPIN) - 2);
    assert(rv == CKR_SESSION_READ_ONLY_EXISTS);
    rv = C_CloseSession(hSession[0]);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_SO, soPIN, sizeof(soPIN) - 2);
    assert(rv == CKR_PIN_INCORRECT);
    rv = C_Login(hSession[1], CKU_SO, soPIN, sizeof(soPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_CONTEXT_SPECIFIC, soPIN, sizeof(soPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 2);
    assert(rv == CKR_USER_TOO_MANY_TYPES);

    /* C_Logout */

    rv = C_Logout(CK_INVALID_HANDLE);    
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_Logout(hSession[1]);
    assert(rv == CKR_OK);

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

  }

  printf("OK\n");
}

void runRandomCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_SeedRandom and C_GenerateRandom: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    CK_BYTE seed[] = {"Some random data"};
    CK_BYTE randomData[40];

    /* No init */

    rv = C_SeedRandom(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GenerateRandom(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);

    /* C_SeedRandom */

    rv = C_SeedRandom(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_SeedRandom(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_SeedRandom(hSession[0], seed, sizeof(seed));
    assert(rv == CKR_OK);

    /* C_GenerateRandom */

    rv = C_GenerateRandom(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_GenerateRandom(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GenerateRandom(hSession[0], randomData, 40);
    assert(rv == CKR_OK);

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

  }

  printf("OK\n");
}

void runGenerateCheck(unsigned int counter) {
  unsigned int i;
  static CK_ULONG modulusBits = 768;
  static CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
  static CK_BYTE modulus[] = { 0xcb, 0x12, 0x9d, 0xba, 0x22, 0xfa, 0x2b, 0x33, 0x7e, 0x2a, 0x24, 0x65, 0x09, 0xa9,
                               0xfb, 0x41, 0x1a, 0x0e, 0x2f, 0x89, 0x3a, 0xd6, 0x97, 0x49, 0x77, 0x6d, 0x2a, 0x6e, 0x98,
                               0x48, 0x6b, 0xa8, 0xc4, 0x63, 0x8e, 0x46, 0x90, 0x70, 0x2e, 0xd4, 0x10, 0xc0, 0xdd, 0xa3,
                               0x56, 0xcf, 0x97, 0x2f, 0x2f, 0xfc, 0x2d, 0xff, 0x2b, 0xf2, 0x42, 0x69, 0x4a, 0x8c, 0xf1,
                               0x6f, 0x76, 0x32, 0xc8, 0xe1, 0x37, 0x52, 0xc1, 0xd1, 0x33, 0x82, 0x39, 0x1a, 0xb3, 0x2a,
                               0xa8, 0x80, 0x4e, 0x19, 0x91, 0xa6, 0xa6, 0x16, 0x65, 0x30, 0x72, 0x80, 0xc3, 0x5c, 0x84,
                               0x9b, 0x7b, 0x2c, 0x6d, 0x2d, 0x75, 0x51, 0x9f, 0xc9, 0x6d, 0xa8, 0x4d, 0x8c, 0x41, 0x41,
                               0x12, 0xc9, 0x14, 0xc7, 0x99, 0x31, 0xe4, 0xcd, 0x97, 0x38, 0x2c, 0xca, 0x32, 0x2f, 0xeb,
                               0x78, 0x37, 0x17, 0x87, 0xc8, 0x09, 0x5a, 0x1a, 0xaf, 0xe4, 0xc4, 0xcc, 0x83, 0xe3, 0x79,
                               0x01, 0xd6, 0xdb, 0x8b, 0xd6, 0x24, 0x90, 0x43, 0x7b, 0xc6, 0x40, 0x57, 0x58, 0xe4, 0x49,
                               0x2b, 0x99, 0x61, 0x71, 0x52, 0xf4, 0x8b, 0xda, 0xb7, 0x5a, 0xbf, 0xf7, 0xc5, 0x2a, 0x8b,
                               0x1f, 0x25, 0x5e, 0x5b, 0xfb, 0x9f, 0xcc, 0x8d, 0x1c, 0x92, 0x21, 0xe9, 0xba, 0xd0, 0x54,
                               0xf6, 0x0d, 0xe8, 0x7e, 0xb3, 0x9d, 0x9a, 0x47, 0xba, 0x1e, 0x45, 0x4e, 0xdc, 0xe5, 0x20,
                               0x95, 0xd8, 0xe5, 0xe9, 0x51, 0xff, 0x1f, 0x9e, 0x9e, 0x60, 0x3c, 0x27, 0x1c, 0xf3, 0xc7,
                               0xf4, 0x89, 0xaa, 0x2a, 0x80, 0xd4, 0x03, 0x5d, 0xf3, 0x39, 0xa3, 0xa7, 0xe7, 0x3f, 0xa9,
                               0xd1, 0x31, 0x50, 0xb7, 0x0f, 0x08, 0xa2, 0x71, 0xcc, 0x6a, 0xb4, 0xb5, 0x8f, 0xcb, 0xf7,
                               0x1f, 0x4e, 0xc8, 0x16, 0x08, 0xc0, 0x03, 0x8a, 0xce, 0x17, 0xd1, 0xdd, 0x13, 0x0f, 0xa3,
                               0xbe, 0xa3 };
  static CK_BYTE id[] = { 123 };
  static CK_BBOOL true = CK_TRUE, false = CK_FALSE;
  static CK_BYTE label[] = "label";
  static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  static CK_KEY_TYPE keyType = CKK_RSA;
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_ENCRYPT, &true, sizeof(true)},
    {CKA_VERIFY, &true, sizeof(true)},
    {CKA_WRAP, &true, sizeof(true)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_PRIVATE, &true, sizeof(true)},
    {CKA_ID, id, sizeof(id)},
    {CKA_SENSITIVE, &true, sizeof(true)},
    {CKA_DECRYPT, &true, sizeof(true)},
    {CKA_SIGN, &true, sizeof(true)},
    {CKA_UNWRAP, &true, sizeof(true)},
    {CKA_TOKEN, &true, sizeof(true)}
  };
  CK_ATTRIBUTE pubTemplate[] = {
    {CKA_CLASS, &pubClass, sizeof(pubClass)},
    {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    {CKA_LABEL, label, sizeof(label)},
    {CKA_ID, id, sizeof(id)},
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_VERIFY, &true, sizeof(true)},
    {CKA_ENCRYPT, &false, sizeof(false)},
    {CKA_WRAP, &false, sizeof(false)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_MODULUS, modulus, sizeof(modulus)},
    {CKA_CERTIFICATE_CATEGORY, NULL_PTR, 0}
  };

  printf("Checking C_GenerateKeyPair, C_DestroyObject, and C_CreateObject: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey, hCreateKey;
    CK_MECHANISM mechanism = {CKM_VENDOR_DEFINED, NULL_PTR, 0};

    /* No init */

    rv = C_GenerateKeyPair(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_DestroyObject(CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_CreateObject(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);

    /* C_GenerateKeyPair */

    rv = C_GenerateKeyPair(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_GenerateKeyPair(hSession[0], NULL_PTR, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GenerateKeyPair(hSession[0], &mechanism, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 6, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_USER_NOT_LOGGED_IN);
    rv = C_Login(hSession[0], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_USER_NOT_LOGGED_IN);
    rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_MECHANISM_INVALID);
    mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 5, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_TEMPLATE_INCOMPLETE);
    rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_OK);

    /* C_DestroyObject */

    rv = C_DestroyObject(CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_DestroyObject(hSession[0], CK_INVALID_HANDLE);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);
    rv = C_DestroyObject(hSession[0], hPrivateKey);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);
    rv = C_DestroyObject(hSession[1], hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_DestroyObject(hSession[1], hPublicKey);
    assert(rv == CKR_OK);

    /* C_CreateObject */

    rv = C_Logout(hSession[0]);
    assert(rv == CKR_OK);
    rv = C_CreateObject(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_CreateObject(hSession[0], NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_CreateObject(hSession[0], pubTemplate, 0, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_CreateObject(hSession[0], pubTemplate, 5, &hCreateKey);
    assert(rv == CKR_SESSION_READ_ONLY);
    rv = C_CreateObject(hSession[1], pubTemplate, 5, &hCreateKey);
    assert(rv == CKR_USER_NOT_LOGGED_IN);
    rv = C_Login(hSession[0], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_CreateObject(hSession[1], pubTemplate, 0, &hCreateKey);
    assert(rv == CKR_ATTRIBUTE_VALUE_INVALID);
    rv = C_CreateObject(hSession[1], pubTemplate, 1, &hCreateKey);
    assert(rv == CKR_ATTRIBUTE_VALUE_INVALID);
    rv = C_CreateObject(hSession[1], pubTemplate, 2, &hCreateKey);
    assert(rv == CKR_TEMPLATE_INCOMPLETE);
    rv = C_CreateObject(hSession[1], pubTemplate, 11, &hCreateKey);
    assert(rv == CKR_ATTRIBUTE_TYPE_INVALID);
    rv = C_CreateObject(hSession[1], pubTemplate, 10, &hCreateKey);
    assert(rv == CKR_OK);
    rv = C_DestroyObject(hSession[1], hCreateKey);
    assert(rv == CKR_OK);
    
    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

  }

  printf("OK\n");
}

void runObjectCheck(unsigned int counter) {
  CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  static CK_ULONG modulusBits = 768;
  static CK_BYTE publicExponent[] = { 3 };
  static CK_BYTE id[] = {123};
  static CK_BBOOL true = CK_TRUE;
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_ENCRYPT, &true, sizeof(true)},
    {CKA_VERIFY, &true, sizeof(true)},
    {CKA_WRAP, &true, sizeof(true)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_PRIVATE, &true, sizeof(true)},
    {CKA_ID, id, sizeof(id)},
    {CKA_SENSITIVE, &true, sizeof(true)},
    {CKA_DECRYPT, &true, sizeof(true)},
    {CKA_SIGN, &true, sizeof(true)},
    {CKA_UNWRAP, &true, sizeof(true)},
    {CKA_TOKEN, &true, sizeof(true)}
  };

  unsigned int i;

  printf("Checking C_GetAttributeValue, C_SetAttributeValue, C_FindObjectsInit, C_FindObjects, and C_FindObjectsFinal: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    static CK_OBJECT_CLASS oClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE searchTemplate[] = {
      {CKA_CLASS, &oClass, sizeof(oClass)}
    };
    CK_OBJECT_HANDLE hObject;
    CK_ULONG ulObjectCount;
    CK_ATTRIBUTE getAttr = {CKA_PRIME_1, NULL_PTR, 0};
    CK_ULONG attValueLen;
    static CK_UTF8CHAR label[] = {"New label"};
    CK_ATTRIBUTE template1[] = {
      {CKA_LABEL, label, sizeof(label)-1}
    };
    CK_ATTRIBUTE template2[] = {
      {CKA_CLASS, NULL_PTR, 0}
    };


    /* No init */

    rv = C_FindObjectsInit(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_FindObjects(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_FindObjectsFinal(CK_INVALID_HANDLE);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetAttributeValue(CK_INVALID_HANDLE, CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_SetAttributeValue(CK_INVALID_HANDLE, CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    /* Initializing */

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_Logout(hSession[1]);
    assert(rv == CKR_OK);

    /* C_FindObjectsInit */

    rv = C_FindObjectsInit(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_FindObjectsInit(hSession[0], NULL_PTR, 1);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_FindObjectsInit(hSession[0], searchTemplate, 1);
    assert(rv == CKR_OK);
    rv = C_FindObjectsInit(hSession[0], searchTemplate, 1);
    assert(rv == CKR_OPERATION_ACTIVE);

    /* C_FindObjects */

    rv = C_FindObjects(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_FindObjects(hSession[1], NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_FindObjects(hSession[0], NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_FindObjects(hSession[0], &hObject, 0, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_FindObjects(hSession[0], &hObject, 1, &ulObjectCount);
    assert(rv == CKR_OK);

    /* C_FindObjectsFinal */

    rv = C_FindObjectsFinal(CK_INVALID_HANDLE);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_FindObjectsFinal(hSession[1]);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_FindObjectsFinal(hSession[0]);
    assert(rv == CKR_OK);

    /* C_GetAttributeValue */

    rv = C_GetAttributeValue(CK_INVALID_HANDLE, CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_GetAttributeValue(hSession[0], CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, NULL_PTR, 0);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, &getAttr, 1);
    assert(rv == CKR_ATTRIBUTE_SENSITIVE);
    getAttr.type = 45678; /* Not valid attribute? */
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, &getAttr, 1);
    assert(rv == CKR_ATTRIBUTE_TYPE_INVALID);
    getAttr.type = CKA_ID;
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, &getAttr, 1);
    assert(rv == CKR_OK);
    getAttr.pValue = (CK_BYTE_PTR)malloc(getAttr.ulValueLen);
    attValueLen = getAttr.ulValueLen;
    getAttr.ulValueLen = 0;
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, &getAttr, 1);
    assert(rv == CKR_BUFFER_TOO_SMALL);
    getAttr.ulValueLen = attValueLen;
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, &getAttr, 1);
    assert(rv == CKR_OK);
    free(getAttr.pValue);
    rv = C_Logout(hSession[1]);
    assert(rv == CKR_OK);

    /* C_SetAttributeValue */

    rv = C_SetAttributeValue(CK_INVALID_HANDLE, CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_SetAttributeValue(hSession[0], CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);
    rv = C_SetAttributeValue(hSession[0], hPrivateKey, NULL_PTR, 0);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_SetAttributeValue(hSession[0], hPrivateKey, NULL_PTR, 0);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);
    rv = C_SetAttributeValue(hSession[1], hPrivateKey, NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_SetAttributeValue(hSession[1], hPrivateKey, template2, 1);
    assert(rv == CKR_ATTRIBUTE_READ_ONLY);
    rv = C_SetAttributeValue(hSession[1], hPrivateKey, template1, 1);
    assert(rv == CKR_OK);

    /* Finalizing */

    rv = C_DestroyObject(hSession[1], hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_DestroyObject(hSession[1], hPublicKey);
    assert(rv == CKR_OK);
    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);
  }

  printf("OK\n");
}

void runDigestCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_DigestInit, C_Digest, C_DigestUpdate, and C_DigestFinal: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    CK_MECHANISM mechanism = {
      CKM_VENDOR_DEFINED, NULL_PTR, 0
    };
    CK_ULONG digestLen;
    CK_BYTE_PTR digest;
    CK_BYTE data[] = {"Text to digest"};

    /* No init */

    rv = C_DigestInit(CK_INVALID_HANDLE, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_Digest(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_DigestUpdate(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_DigestFinal(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    /* Initializing */

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);

    /* C_DigestInit */

    rv = C_DigestInit(CK_INVALID_HANDLE, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_DigestInit(hSession[0], NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_DigestInit(hSession[0], &mechanism);
    assert(rv == CKR_MECHANISM_INVALID);
    mechanism.mechanism = CKM_SHA512;
    rv = C_DigestInit(hSession[0], &mechanism);
    assert(rv == CKR_OK);
    rv = C_DigestInit(hSession[0], &mechanism);
    assert(rv == CKR_OPERATION_ACTIVE);

    /* C_Digest */

    rv = C_Digest(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_Digest(hSession[1], NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_Digest(hSession[0], NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_Digest(hSession[0], NULL_PTR, 0, NULL_PTR, &digestLen);
    assert(rv == CKR_OK);
    digest = (CK_BYTE_PTR)malloc(digestLen);
    digestLen = 0;
    rv = C_Digest(hSession[0], NULL_PTR, 0, digest, &digestLen);
    assert(rv == CKR_BUFFER_TOO_SMALL);
    rv = C_Digest(hSession[0], NULL_PTR, 0, digest, &digestLen);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_Digest(hSession[0], data, sizeof(data)-1, digest, &digestLen);
    assert(rv == CKR_OK);
    rv = C_Digest(hSession[0], data, sizeof(data)-1, digest, &digestLen);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    free(digest);

    /* C_DigestUpdate */

    rv = C_DigestUpdate(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_DigestUpdate(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_DigestInit(hSession[0], &mechanism);
    assert(rv == CKR_OK);
    rv = C_DigestUpdate(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_DigestUpdate(hSession[0], data, sizeof(data)-1);
    assert(rv == CKR_OK);

    /* C_DigestFinal */

    rv = C_DigestFinal(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_DigestFinal(hSession[1], NULL_PTR, NULL_PTR);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_DigestFinal(hSession[0], NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_DigestFinal(hSession[0], NULL_PTR, &digestLen);
    assert(rv == CKR_OK);
    digest = (CK_BYTE_PTR)malloc(digestLen);
    digestLen = 0;
    rv = C_DigestFinal(hSession[0], digest, &digestLen);
    assert(rv == CKR_BUFFER_TOO_SMALL);
    rv = C_DigestFinal(hSession[0], digest, &digestLen);
    assert(rv == CKR_OK);
    free(digest);

    /* Finalizing */

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);
  }

  printf("OK\n");
}

void runSignCheck(unsigned int counter) {
  CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
  CK_MECHANISM keyGenMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  static CK_ULONG modulusBits = 768;
  static CK_BYTE publicExponent[] = { 3 };
  static CK_BYTE id[] = {123};
  static CK_BBOOL true = CK_TRUE;
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_ENCRYPT, &true, sizeof(true)},
    {CKA_VERIFY, &true, sizeof(true)},
    {CKA_WRAP, &true, sizeof(true)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_PRIVATE, &true, sizeof(true)},
    {CKA_ID, id, sizeof(id)},
    {CKA_SENSITIVE, &true, sizeof(true)},
    {CKA_DECRYPT, &true, sizeof(true)},
    {CKA_SIGN, &true, sizeof(true)},
    {CKA_UNWRAP, &true, sizeof(true)},
    {CKA_TOKEN, &true, sizeof(true)}
  };

  unsigned int i;

  printf("Checking C_SignInit, C_Sign, C_SignUpdate, and C_SignFinal: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    CK_MECHANISM mechanism = {
      CKM_VENDOR_DEFINED, NULL_PTR, 0
    };
    CK_ULONG length;
    CK_BYTE_PTR pSignature;
    CK_BYTE data[] = {"Text"};

    /* No init */

    rv = C_SignInit(CK_INVALID_HANDLE, NULL_PTR, CK_INVALID_HANDLE);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_Sign(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_SignUpdate(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_SignFinal(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    /* Initializing */

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_GenerateKeyPair(hSession[1], &keyGenMechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_Logout(hSession[1]);
    assert(rv == CKR_OK);

    /* C_SignInit */

    rv = C_SignInit(CK_INVALID_HANDLE, NULL_PTR, CK_INVALID_HANDLE);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_SignInit(hSession[0], NULL_PTR, CK_INVALID_HANDLE);
    assert(rv == CKR_KEY_HANDLE_INVALID);
    rv = C_SignInit(hSession[0], NULL_PTR, hPrivateKey);
    assert(rv == CKR_KEY_HANDLE_INVALID);
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_SignInit(hSession[0], NULL_PTR, hPrivateKey);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_SignInit(hSession[0], &mechanism, hPrivateKey);
    assert(rv == CKR_MECHANISM_INVALID);
    mechanism.mechanism = CKM_SHA512_RSA_PKCS;
    rv = C_SignInit(hSession[0], &mechanism, hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_SignInit(hSession[0], &mechanism, hPrivateKey);
    assert(rv == CKR_OPERATION_ACTIVE);

    /* C_Sign */

    rv = C_Sign(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_Sign(hSession[1], NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_Sign(hSession[0], NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_Sign(hSession[0], NULL_PTR, 0, NULL_PTR, &length);
    assert(rv == CKR_OK);
    pSignature = (CK_BYTE_PTR)malloc(length);
    length = 0;
    rv = C_Sign(hSession[0], NULL_PTR, 0, pSignature, &length);
    assert(rv == CKR_BUFFER_TOO_SMALL);
    rv = C_Sign(hSession[0], NULL_PTR, 0, pSignature, &length);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_Sign(hSession[0], data, sizeof(data)-1, pSignature, &length);
    assert(rv == CKR_OK);
    rv = C_Sign(hSession[0], data, sizeof(data)-1, pSignature, &length);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    free(pSignature);

    /* C_SignUpdate */

    rv = C_SignUpdate(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_SignUpdate(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_SignInit(hSession[0], &mechanism, hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_SignUpdate(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_SignUpdate(hSession[0], data, sizeof(data)-1);
    assert(rv == CKR_OK);

    /* C_SignFinal */

    rv = C_SignFinal(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_SignFinal(hSession[1], NULL_PTR, NULL_PTR);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_SignFinal(hSession[0], NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_SignFinal(hSession[0], NULL_PTR, &length);
    assert(rv == CKR_OK);
    pSignature = (CK_BYTE_PTR)malloc(length);
    length = 0;
    rv = C_SignFinal(hSession[0], pSignature, &length);
    assert(rv == CKR_BUFFER_TOO_SMALL);
    rv = C_SignFinal(hSession[0], pSignature, &length);
    assert(rv == CKR_OK);
    free(pSignature);

    /* Finalizing */

    rv = C_DestroyObject(hSession[1], hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_DestroyObject(hSession[1], hPublicKey);
    assert(rv == CKR_OK);
    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);
  }

  printf("OK\n");
}

void runVerifyCheck(unsigned int counter) {
  CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
  CK_MECHANISM keyGenMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  static CK_ULONG modulusBits = 768;
  static CK_BYTE publicExponent[] = { 3 };
  static CK_BYTE id[] = {123};
  static CK_BBOOL true = CK_TRUE;
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_ENCRYPT, &true, sizeof(true)},
    {CKA_VERIFY, &true, sizeof(true)},
    {CKA_WRAP, &true, sizeof(true)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_PRIVATE, &true, sizeof(true)},
    {CKA_ID, id, sizeof(id)},
    {CKA_SENSITIVE, &true, sizeof(true)},
    {CKA_DECRYPT, &true, sizeof(true)},
    {CKA_SIGN, &true, sizeof(true)},
    {CKA_UNWRAP, &true, sizeof(true)},
    {CKA_TOKEN, &true, sizeof(true)}
  };

  unsigned int i;

  printf("Checking C_VerifyInit, C_Verify, C_VerifyUpdate, and C_VerifyFinal: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    CK_MECHANISM mechanism = {
      CKM_VENDOR_DEFINED, NULL_PTR, 0
    };
    CK_BYTE signature[] = {"Not a good signature"};
    CK_BYTE data[] = {"Text"};

    /* No init */

    rv = C_VerifyInit(CK_INVALID_HANDLE, NULL_PTR, CK_INVALID_HANDLE);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_Verify(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_VerifyUpdate(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_VerifyFinal(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    /* Initializing */

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_GenerateKeyPair(hSession[1], &keyGenMechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_Logout(hSession[1]);
    assert(rv == CKR_OK);

    /* C_VerifyInit */

    rv = C_VerifyInit(CK_INVALID_HANDLE, NULL_PTR, CK_INVALID_HANDLE);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_VerifyInit(hSession[0], NULL_PTR, CK_INVALID_HANDLE);
    assert(rv == CKR_KEY_HANDLE_INVALID);
    rv = C_VerifyInit(hSession[0], NULL_PTR, hPublicKey);
    assert(rv == CKR_KEY_HANDLE_INVALID);
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_VerifyInit(hSession[0], NULL_PTR, hPublicKey);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_VerifyInit(hSession[0], &mechanism, hPublicKey);
    assert(rv == CKR_MECHANISM_INVALID);
    mechanism.mechanism = CKM_SHA512_RSA_PKCS;
    rv = C_VerifyInit(hSession[0], &mechanism, hPublicKey);
    assert(rv == CKR_OK);
    rv = C_VerifyInit(hSession[0], &mechanism, hPublicKey);
    assert(rv == CKR_OPERATION_ACTIVE);

    /* C_Verify */

    rv = C_Verify(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_Verify(hSession[1], NULL_PTR, 0, NULL_PTR, 0);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_Verify(hSession[0], NULL_PTR, 0, NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_Verify(hSession[0], data, sizeof(data)-1, NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_Verify(hSession[0], data, sizeof(data)-1, signature, sizeof(signature)-1);
    assert(rv == CKR_SIGNATURE_LEN_RANGE);
    rv = C_Verify(hSession[0], data, sizeof(data)-1, signature, sizeof(signature)-1);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);

    /* C_VerifyUpdate */

    rv = C_VerifyUpdate(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_VerifyUpdate(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_VerifyInit(hSession[0], &mechanism, hPublicKey);
    assert(rv == CKR_OK);
    rv = C_VerifyUpdate(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_VerifyUpdate(hSession[0], data, sizeof(data)-1);
    assert(rv == CKR_OK);

    /* C_VerifyFinal */

    rv = C_VerifyFinal(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);
    rv = C_VerifyFinal(hSession[1], NULL_PTR, 0);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);
    rv = C_VerifyFinal(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);
    rv = C_VerifyFinal(hSession[0], signature, sizeof(signature)-1);
    assert(rv == CKR_SIGNATURE_LEN_RANGE);
    rv = C_VerifyFinal(hSession[0], signature, sizeof(signature)-1);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);

    /* Finalizing */

    rv = C_DestroyObject(hSession[1], hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_DestroyObject(hSession[1], hPublicKey);
    assert(rv == CKR_OK);
    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);
  }

  printf("OK\n");
}
