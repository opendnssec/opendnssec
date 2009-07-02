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
* This program is for creating and initializing tokens for
* the libsofthsm. libsofthsm implements parts of the PKCS#11 
* interface defined by RSA Labratories, PKCS11 v2.20, 
* called Cryptoki.
*
************************************************************/

#include <config.h>
#include "softhsm.h"
#include "pkcs11_unix.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>

// Includes for the crypto library
#include <botan/auto_rng.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/bigint.h>
#include <botan/if_algo.h>
using namespace Botan;

void usage() {
  printf("Usage: softhsm [OPTIONS]\n");
  printf("Support tool for libsofthsm\n");
  printf("Options:\n");
  printf("--show-slots             Display all the available slots.\n");
  printf("--init-token             Initialize the token at a given slot.\n");
  printf("                         Use with --slot, --label, --so-pin, and --pin.\n");
  printf("                         WARNING: Any content in token token will be erased.\n");
  printf("--import-key-pair <path> Import a key pair from the given path.\n");
  printf("                         The file must be in PKCS#8-format.\n");
  printf("                         Use with --slot, --object-label, --object-id, --file-pin, and --pin.\n");
  printf("--slot <number>          The slot where the token is located.\n");
  printf("--label <text>           Defines the label of the token. Max 32 chars.\n");
  printf("--object-label <text>    Defines the label of the object.\n");
  printf("--object-id <hex>        Defines the ID of the object. Hexadecimal characters.\n");
  printf("--so-pin <PIN>           The PIN for the Security Officer (SO).\n");
  printf("--pin <PIN>              The PIN for the normal user.\n");
  printf("--file-pin <PIN>         Supply a PIN if the file is encrypted.\n");
  printf("--help                   Shows this help.\n");
  printf("-h                       Shows this help.\n\n\n");
  printf("You also need to have a config file, which specifies the paths to the tokens.\n");
  printf("Example:\n");
  printf("  0:/home/user/my.db\n");
  printf("  # Comments can be added\n");
  printf("  4:/home/user/token.database\n\n");
  printf("The path to the config file should also be configured by:\n");
  printf("  export SOFTHSM_CONF=/home/user/config.file\n");
}

enum {
  OPT_SHOW_SLOTS = 0x100,
  OPT_INIT_TOKEN,
  OPT_IMPORT_KEY_PAIR,
  OPT_SLOT,
  OPT_LABEL,
  OPT_OBJECT_LABEL,
  OPT_OBJECT_ID,
  OPT_SO_PIN,
  OPT_PIN,
  OPT_FILE_PIN,
  OPT_HELP
};

static const struct option long_options[] = {
  { "show-slots",      0, NULL, OPT_SHOW_SLOTS },
  { "init-token",      0, NULL, OPT_INIT_TOKEN },
  { "import-key-pair", 1, NULL, OPT_IMPORT_KEY_PAIR },
  { "slot",            1, NULL, OPT_SLOT },
  { "label",           1, NULL, OPT_LABEL },
  { "object-label",    1, NULL, OPT_OBJECT_LABEL },
  { "object-id",       1, NULL, OPT_OBJECT_ID },
  { "so-pin",          1, NULL, OPT_SO_PIN },
  { "pin",             1, NULL, OPT_PIN },
  { "file-pin",        1, NULL, OPT_FILE_PIN },
  { "help",            0, NULL, OPT_HELP },
  { NULL,              0, NULL, 0 }
};

int main(int argc, char *argv[]) {
  int option_index = 0;
  int opt;

  char *filePath = NULL;
  char *soPIN = NULL;
  char *userPIN = NULL;
  char *filePIN = NULL;
  char *label = NULL;
  char *objectLabel = NULL;
  char *objectID = NULL;
  char *slot = NULL;

  int doInitToken = 0;
  int doShowSlots = 0;
  int doImportKeyPair = 0;

  while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
    switch (opt) {
      case OPT_SHOW_SLOTS:
        doShowSlots = 1;
        break;
      case OPT_INIT_TOKEN:
        doInitToken = 1;
        break;
      case OPT_IMPORT_KEY_PAIR:
        doImportKeyPair = 1;
        filePath = optarg;
        break;
      case OPT_SLOT:
        slot = optarg;
        break;
      case OPT_LABEL:
        label = optarg;
        break;
      case OPT_OBJECT_LABEL:
        objectLabel = optarg;
        break;
      case OPT_OBJECT_ID:
        objectID = optarg;
        break;
      case OPT_SO_PIN:
        soPIN = optarg;
        break;
      case OPT_PIN:
        userPIN = optarg;
        break;
      case OPT_FILE_PIN:
        filePIN = optarg;
        break;
      case OPT_HELP:
      case 'h':
      default:
        usage();
        exit(0);
        break;
    }
  }

  // No action given, display the usage.
  if(doInitToken == 0 && doShowSlots == 0 && doImportKeyPair == 0) {
    usage();
  }

  // We should create the token.
  if(doInitToken) {
    initToken(slot, label, soPIN, userPIN);
  }

  if(doShowSlots) {
    showSlots();
  }

  if(doImportKeyPair) {
    importKeyPair(filePath, filePIN, slot, userPIN, objectLabel, objectID);
  }

  return 0;
}

// Creates a SoftHSM token at the given location.

void initToken(char *slot, char *label, char *soPIN, char *userPIN) {
  // Keep a copy of the PINs because getpass/getpassphrase will overwrite the previous PIN.
  char so_pin_copy[MAX_PIN_LEN+1];
  char user_pin_copy[MAX_PIN_LEN+1];

  if(slot == NULL) {
    printf("Error: A slot number must be supplied. Use --slot <number>\n");
    exit(1);
  }

  if(label == NULL) {
    printf("Error: A label for the token must be supplied. Use --label <text>\n");
    exit(1);
  }

  if(strlen(label) > 32) {
    printf("Error: The label must not have a length greater than 32 chars.\n");
    exit(1);
  }

  if(soPIN == NULL) {
    printf("The SO PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
    #ifdef HAVE_GETPASSPHRASE
      soPIN = getpassphrase("Enter SO PIN: ");
    #else
      soPIN = getpass("Enter SO PIN: ");
    #endif
  }

  int soLength = strlen(soPIN);
  while(soLength < MIN_PIN_LEN || soLength > MAX_PIN_LEN) {
    printf("Wrong size! The SO PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
    #ifdef HAVE_GETPASSPHRASE
      soPIN = getpassphrase("Enter SO PIN: ");
    #else
      soPIN = getpass("Enter SO PIN: ");
    #endif
    soLength = strlen(soPIN);
  }
  strcpy(so_pin_copy, soPIN);

  if(userPIN == NULL) {
    printf("The user PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
    #ifdef HAVE_GETPASSPHRASE
      userPIN = getpassphrase("Enter user PIN: ");
    #else
      userPIN = getpass("Enter user PIN: ");
    #endif
  }
	
  int userLength = strlen(userPIN);
  while(userLength < MIN_PIN_LEN || userLength > MAX_PIN_LEN) {
    printf("Wrong size! The user PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
    #ifdef HAVE_GETPASSPHRASE
      userPIN = getpassphrase("Enter user PIN: ");
    #else
      userPIN = getpass("Enter user PIN: ");
    #endif
    userLength = strlen(userPIN);
  }
  strcpy(user_pin_copy, userPIN);

  // Load the variables
  CK_SLOT_ID slotID = atoi(slot);
  CK_UTF8CHAR paddedLabel[32];
  memset(paddedLabel, ' ', sizeof(paddedLabel));
  memcpy(paddedLabel, label, strlen(label));

  CK_RV rv = C_Initialize(NULL_PTR);
  if(rv != CKR_OK) {
    printf("Could not initialize libsofthsm. Probably missing the configuration file.\n");
    exit(1);
  }

  rv = C_InitToken(slotID, (CK_UTF8CHAR_PTR)so_pin_copy, soLength, paddedLabel);

  switch(rv) {
    case CKR_OK:
      break;
    case CKR_SLOT_ID_INVALID:
      printf("Error: The given slot does not exist.\n");
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

  CK_SESSION_HANDLE hSession;
  rv = C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    printf("Error: Could not open a session with the library.\n");
    exit(1);
  }

  rv = C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)so_pin_copy, soLength);
  if(rv != CKR_OK) {
    printf("Error: Could not log in on the token.\n");
    exit(1);
  }

  rv = C_InitPIN(hSession, (CK_UTF8CHAR_PTR)user_pin_copy, userLength);
  if(rv != CKR_OK) {
    printf("Error: Could not initialize the user PIN.\n");
    exit(1);
  }

  C_Finalize(NULL_PTR);

  printf("The token has been initialized.\n");
}

void showSlots() {
  CK_RV rv = C_Initialize(NULL_PTR);
  if(rv != CKR_OK) {
    printf("Could not initialize libsofthsm. Probably missing the configuration file.\n");
    exit(1);
  }

  CK_ULONG ulSlotCount;
  rv = C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
  if(rv != CKR_OK) {
    printf("Could not get the number of slots.\n");
    exit(1);
  }

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount*sizeof(CK_SLOT_ID));
  rv = C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
  if (rv != CKR_OK) {
    printf("Could not get the slot list.\n");
    exit(1);
  }

  printf("Available slots:\n");

  for(unsigned int i = 0; i < ulSlotCount; i++) {
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;

    rv = C_GetSlotInfo(pSlotList[i], &slotInfo);
    if(rv != CKR_OK) {  
      printf("Could not get the slot info.\n");
      exit(1);
    }

    printf("Slot %-2lu\n", pSlotList[i]);
    printf("           Token present: ");
    if((slotInfo.flags & CKF_TOKEN_PRESENT) == 0) {
      printf("no\n");
    } else {
      printf("yes\n");

      rv = C_GetTokenInfo(pSlotList[i], &tokenInfo);
      if(rv != CKR_OK) {
        printf("Could not get the token info.\n");
        exit(1);
      }

      printf("           Token initialized: ");
      if((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == 0) {
        printf("no\n");
      } else {
        printf("yes\n");
      }

      printf("           User PIN initialized: ");
      if((tokenInfo.flags & CKF_USER_PIN_INITIALIZED) == 0) {
        printf("no\n");
      } else {
        printf("yes\n");
      }
    }
  }

  free(pSlotList);
  C_Finalize(NULL_PTR);

}

void importKeyPair(char *filePath, char *filePIN, char *slot, char *userPIN, char *objectLabel, char *objectID) {
  char user_pin_copy[MAX_PIN_LEN+1];

  if(slot == NULL) {
    printf("Error: A slot number must be supplied. Use --slot <number>\n");
    exit(1);
  }

  if(objectLabel == NULL) {
    printf("Error: A label for the object must be supplied. Use --object-label <text>\n");
    exit(1);
  }

  if(objectID == NULL) {
    printf("Error: An ID for the object must be supplied. Use --object-id <hex>\n");
    exit(1);
  }
  int objIDLen = 0;
  char *objID = hexStrToBin(objectID, strlen(objectID), &objIDLen);

  if(userPIN == NULL) {
    printf("Error: An user PIN must be supplied. Use --pin <PIN>\n");
    free(objID);
    exit(1);
  }

  CK_RV rv = C_Initialize(NULL_PTR);
  if(rv != CKR_OK) {
    printf("Could not initialize libsofthsm. Probably missing the configuration file.\n");
    free(objID);
    exit(1);
  }

  CK_SLOT_ID slotID = atoi(slot);
  CK_SESSION_HANDLE hSession;
  rv = C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    if(rv == CKR_SLOT_ID_INVALID) {
      printf("Error: The given slot does not exist.\n");
    } else {
      printf("Error: Could not open a session on the given slot.\n");
    }
    free(objID);
    exit(1);
  }

  rv = C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)userPIN, strlen(userPIN));
  if(rv != CKR_OK) {
    if(rv == CKR_PIN_INCORRECT) {
      printf("Error: The given user PIN does not match the one in the token.\n");
    } else {
      printf("Error: Could not log in on the token.\n");
    }
    free(objID);
    exit(1);
  }

  AutoSeeded_RNG *rng = new AutoSeeded_RNG();
  Private_Key *rsaKey = NULL_PTR;

  try {
    if(filePIN == NULL) {
      rsaKey = PKCS8::load_key(filePath, *rng);
    } else {
      rsaKey = PKCS8::load_key(filePath, *rng, filePIN);
    } 
  } 
  catch(std::exception& e) { 
    printf("%s\n", e.what());
    delete rng;
    free(objID);
    exit(1); 
  }
  delete rng;

  IF_Scheme_PrivateKey *ifKeyPriv = dynamic_cast<IF_Scheme_PrivateKey*>(rsaKey);
  CK_ULONG size1 = ifKeyPriv->get_e().bytes();
  CK_ULONG size2 = ifKeyPriv->get_n().bytes();
  CK_ULONG size3 = ifKeyPriv->get_d().bytes();
  CK_ULONG size4 = ifKeyPriv->get_p().bytes();
  CK_ULONG size5 = ifKeyPriv->get_q().bytes();
  char *bigExp = (char*)malloc(size1);
  char *bigMod = (char*)malloc(size2);
  char *bigPrivExp = (char*)malloc(size3);
  char *bigPrime1 = (char*)malloc(size4);
  char *bigPrime2 = (char*)malloc(size5);
  ifKeyPriv->get_e().binary_encode((byte *)bigExp);
  ifKeyPriv->get_n().binary_encode((byte *)bigMod);
  ifKeyPriv->get_d().binary_encode((byte *)bigPrivExp);
  ifKeyPriv->get_p().binary_encode((byte *)bigPrime1);
  ifKeyPriv->get_q().binary_encode((byte *)bigPrime2);
  delete rsaKey;

  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
  CK_ATTRIBUTE pubTemplate[] = {
    { CKA_CLASS,            &pubClass,   sizeof(pubClass) },
    { CKA_KEY_TYPE,         &keyType,    sizeof(keyType) },
    { CKA_LABEL,            objectLabel, strlen(objectLabel) },
    { CKA_ID,               objID,       objIDLen },
    { CKA_TOKEN,            &ckTrue,     sizeof(ckTrue) },
    { CKA_VERIFY,           &ckTrue,     sizeof(ckTrue) },
    { CKA_ENCRYPT,          &ckFalse,    sizeof(ckFalse) },
    { CKA_WRAP,             &ckFalse,    sizeof(ckFalse) },
    { CKA_PUBLIC_EXPONENT,  bigExp,      size1 },
    { CKA_MODULUS,          bigMod,      size2 }
  };
  CK_ATTRIBUTE privTemplate[] = {
    { CKA_CLASS,            &privClass,  sizeof(privClass) },
    { CKA_KEY_TYPE,         &keyType,    sizeof(keyType) },
    { CKA_LABEL,            objectLabel, strlen(objectLabel) },
    { CKA_ID,               objID,       objIDLen },
    { CKA_SIGN,             &ckTrue,     sizeof(ckTrue) },
    { CKA_DECRYPT,          &ckFalse,    sizeof(ckFalse) },
    { CKA_UNWRAP,           &ckFalse,    sizeof(ckFalse) },
    { CKA_SENSITIVE,        &ckTrue,     sizeof(ckTrue) },
    { CKA_TOKEN,            &ckTrue,     sizeof(ckTrue) },
    { CKA_PRIVATE,          &ckTrue,     sizeof(ckTrue) },
    { CKA_EXTRACTABLE,      &ckFalse,    sizeof(ckFalse) },
    { CKA_PUBLIC_EXPONENT,  bigExp,      size1 },
    { CKA_MODULUS,          bigMod,      size2 },
    { CKA_PRIVATE_EXPONENT, bigPrivExp,  size3 },
    { CKA_PRIME_1,          bigPrime1,   size4 },
    { CKA_PRIME_2,          bigPrime2,   size5 }
  };

  CK_OBJECT_HANDLE hKey1, hKey2;
  rv = C_CreateObject(hSession, privTemplate, 16, &hKey1);
  if(rv != CKR_OK) {
    printf("%i\n", rv);
    delete bigExp;
    delete bigMod;
    delete bigPrivExp;
    delete bigPrime1;
    delete bigPrime2;
    free(objID);
    printf("Error: Could not save the private key in the token.\n");
    exit(1);
  }
  rv = C_CreateObject(hSession, pubTemplate, 10, &hKey2);
  if(rv != CKR_OK) {
    C_DestroyObject(hSession, hKey1);
    delete bigExp;
    delete bigMod;
    delete bigPrivExp;
    delete bigPrime1;
    delete bigPrime2;
    free(objID);
    printf("Error: Could not save the public key in the token.\n");
    exit(1);
  }

  delete bigExp;
  delete bigMod;
  delete bigPrivExp;
  delete bigPrime1;
  delete bigPrime2;
  free(objID);

  C_Finalize(NULL_PTR);

  printf("The key pair has been imported to the token in slot %i.\n", slotID);
}

char *hexStrToBin(char *objectID, int idLength, int *newLen) {
  char *bytes;

  if(idLength % 2 != 0) {
    printf("Error: Invalid length on hex string.\n");
    exit(1);
  }

  for(int i = 0; i < idLength; i++) {
    if(hexdigit_to_int(objectID[i]) == -1) {
      printf("Error: Invalid character in hex string.\n");
      exit(1);
    }
  }

  *newLen = idLength / 2;
  bytes = (char *)malloc(*newLen);
  for(int i = 0; i < *newLen; i++) {
    bytes[i] = hexdigit_to_int(objectID[2*i]) * 16 +
               hexdigit_to_int(objectID[2*i+1]);
  }
  return bytes;
}

int hexdigit_to_int(char ch) {
  switch (ch) {
    case '0':
      return 0;
    case '1':
      return 1;
    case '2':
      return 2;
    case '3':
      return 3;
    case '4':
      return 4;
    case '5':
      return 5;
    case '6':
      return 6;
    case '7':
      return 7;
    case '8':
      return 8;
    case '9':
      return 9;
    case 'a':
    case 'A':
      return 10;
    case 'b':
    case 'B':
      return 11;
    case 'c':
    case 'C':
      return 12;
    case 'd':
    case 'D':
      return 13;
    case 'e':
    case 'E':
      return 14;
    case 'f':
    case 'F':
      return 15;
    default:
      return -1;
  }
}
