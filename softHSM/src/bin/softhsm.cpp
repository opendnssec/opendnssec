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
  printf("Support tool for libsofthsm\n");
  printf("Usage: softhsm [OPTIONS]\n");
  printf("Options:\n");
  printf("  --show-slots             Display all the available slots.\n");
  printf("  --init-token             Initialize the token at a given slot.\n");
  printf("                           Use with --slot, --label, --so-pin, and --pin.\n");
  printf("                           WARNING: Any content in token token will be erased.\n");
  printf("  --import <path>          Import a key pair from the given path.\n");
  printf("                           The file must be in PKCS#8-format.\n");
  printf("                           Use with --file-pin, --slot, --label, --id, and --pin.\n");
  printf("  --export <path>          Export a key pair to the given path.\n");
  printf("                           The file will be written in PKCS#8-format.\n");
  printf("                           Use with --file-pin (will encrypt file), --slot, --id, and --pin.\n");
  printf("\n");
  printf("  --slot <number>          The slot where the token is located.\n");
  printf("  --label <text>           Defines the label of the object or the token.\n");
  printf("  --id <hex>               Defines the ID of the object. Hexadecimal characters.\n");
  printf("  --so-pin <PIN>           The PIN for the Security Officer (SO).\n");
  printf("  --pin <PIN>              The PIN for the normal user.\n");
  printf("  --file-pin <PIN>         Supply a PIN if the file is encrypted.\n");
  printf("  --help                   Shows this help screen.\n");
  printf("  -h                       Shows this help screen.\n");
  printf("\n");
  printf("\n");
  printf("  You also need to have a config file, which specifies the paths to the tokens.\n");
  printf("  It is located by default at %s\n", DEFAULT_SOFTHSM_CONF);
  printf("  The path to the config file can be change by using:\n");
  printf("      export SOFTHSM_CONF=/home/user/config.file\n");
  printf("\n");
  printf("  An example of a config file:\n");
  printf("      0:/home/user/my.db\n");
  printf("      # Comments can be added\n");
  printf("      # Format:\n");
  printf("      # <slot number>:<path>\n");
  printf("      4:/home/user/token.database\n");
}

enum {
  OPT_SHOW_SLOTS = 0x100,
  OPT_INIT_TOKEN,
  OPT_IMPORT,
  OPT_EXPORT,
  OPT_SLOT,
  OPT_LABEL,
  OPT_ID,
  OPT_SO_PIN,
  OPT_PIN,
  OPT_FILE_PIN,
  OPT_HELP
};

static const struct option long_options[] = {
  { "show-slots",      0, NULL, OPT_SHOW_SLOTS },
  { "init-token",      0, NULL, OPT_INIT_TOKEN },
  { "import",          1, NULL, OPT_IMPORT },
  { "export",          1, NULL, OPT_EXPORT },
  { "slot",            1, NULL, OPT_SLOT },
  { "label",           1, NULL, OPT_LABEL },
  { "id",              1, NULL, OPT_ID },
  { "so-pin",          1, NULL, OPT_SO_PIN },
  { "pin",             1, NULL, OPT_PIN },
  { "file-pin",        1, NULL, OPT_FILE_PIN },
  { "help",            0, NULL, OPT_HELP },
  { NULL,              0, NULL, 0 }
};

int main(int argc, char *argv[]) {
  int option_index = 0;
  int opt;

  char *inPath = NULL;
  char *outPath = NULL;
  char *soPIN = NULL;
  char *userPIN = NULL;
  char *filePIN = NULL;
  char *label = NULL;
  char *objectID = NULL;
  char *slot = NULL;

  int doInitToken = 0;
  int doShowSlots = 0;
  int doImport = 0;
  int doExport = 0;
  int action = 0;

  while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
    switch (opt) {
      case OPT_SHOW_SLOTS:
        doShowSlots = 1;
        action++;
        break;
      case OPT_INIT_TOKEN:
        doInitToken = 1;
        action++;
        break;
      case OPT_IMPORT:
        doImport = 1;
        action++;
        inPath = optarg;
        break;
      case OPT_EXPORT:
        doExport = 1;
        action++;
        outPath = optarg;
        break;
      case OPT_SLOT:
        slot = optarg;
        break;
      case OPT_LABEL:
        label = optarg;
        break;
      case OPT_ID:
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
  if(action == 0) {
    usage();
  } else {
    CK_RV rv = C_Initialize(NULL_PTR);
    if(rv != CKR_OK) {
      fprintf(stderr, "Error: Could not initialize libsofthsm. Probably missing the configuration file.\n");
      exit(1);
    }
  }

  // We should create the token.
  if(doInitToken) {
    initToken(slot, label, soPIN, userPIN);
  }

  // Show all available slots
  if(doShowSlots) {
    showSlots();
  }

  // Import a key pair from the given path
  if(doImport) {
    importKeyPair(inPath, filePIN, slot, userPIN, label, objectID);
  }

  // Export a key pair to the given path
  if(doExport) {
    exportKeyPair(outPath, filePIN, slot, userPIN, objectID);
  }

  if(action) {
    C_Finalize(NULL_PTR);
  }

  return 0;
}

// Creates a SoftHSM token at the given location.

void initToken(char *slot, char *label, char *soPIN, char *userPIN) {
  // Keep a copy of the PINs because getpass/getpassphrase will overwrite the previous PIN.
  char so_pin_copy[MAX_PIN_LEN+1];
  char user_pin_copy[MAX_PIN_LEN+1];

  if(slot == NULL) {
    fprintf(stderr, "Error: A slot number must be supplied. Use --slot <number>\n");
    return;
  }

  if(label == NULL) {
    fprintf(stderr, "Error: A label for the token must be supplied. Use --label <text>\n");
    return;
  }

  if(strlen(label) > 32) {
    fprintf(stderr, "Error: The token label must not have a length greater than 32 chars.\n");
    return;
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

  CK_RV rv = C_InitToken(slotID, (CK_UTF8CHAR_PTR)so_pin_copy, soLength, paddedLabel);

  switch(rv) {
    case CKR_OK:
      break;
    case CKR_SLOT_ID_INVALID:
      fprintf(stderr, "Error: The given slot does not exist.\n");
      return;
      break;
    case CKR_PIN_INCORRECT:
      fprintf(stderr, "Error: The given SO PIN does not match the one in the token.\n");
      return;
      break;
    default:
      fprintf(stderr, "Error: The library could not initialize the token.\n");
      return;
      break;
  }

  CK_SESSION_HANDLE hSession;
  rv = C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not open a session with the library.\n");
    return;
  }

  rv = C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)so_pin_copy, soLength);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not log in on the token.\n");
    return;
  }

  rv = C_InitPIN(hSession, (CK_UTF8CHAR_PTR)user_pin_copy, userLength);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not initialize the user PIN.\n");
    return;
  }

  printf("The token has been initialized.\n");
}

void showSlots() {
  CK_ULONG ulSlotCount;
  CK_RV rv = C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not get the number of slots.\n");
    return;
  }

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount*sizeof(CK_SLOT_ID));
  rv = C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
  if (rv != CKR_OK) {
    fprintf(stderr, "Error: Could not get the slot list.\n");
    return;
  }

  printf("Available slots:\n");

  for(unsigned int i = 0; i < ulSlotCount; i++) {
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;

    rv = C_GetSlotInfo(pSlotList[i], &slotInfo);
    if(rv != CKR_OK) {  
      fprintf(stderr, "Error: Could not get the slot info.\n");
      free(pSlotList);
      return;
    }

    printf("Slot %-2lu\n", pSlotList[i]);
    printf("           Token present: ");
    if((slotInfo.flags & CKF_TOKEN_PRESENT) == 0) {
      printf("no\n");
    } else {
      printf("yes\n");

      rv = C_GetTokenInfo(pSlotList[i], &tokenInfo);
      if(rv != CKR_OK) {
        fprintf(stderr, "Error: Could not get the token info.\n");
        return;
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
}

void importKeyPair(char *filePath, char *filePIN, char *slot, char *userPIN, char *label, char *objectID) {
  if(slot == NULL) {
    fprintf(stderr, "Error: A slot number must be supplied. Use --slot <number>\n");
    return;
  }

  if(label == NULL) {
    fprintf(stderr, "Error: A label for the object must be supplied. Use --label <text>\n");
    return;
  }

  if(userPIN == NULL) {
    fprintf(stderr, "Error: An user PIN must be supplied. Use --pin <PIN>\n");
    return;
  }

  if(objectID == NULL) {
    fprintf(stderr, "Error: An ID for the object must be supplied. Use --id <hex>\n");
    return;
  }
  int objIDLen = 0;
  char *objID = hexStrToBin(objectID, strlen(objectID), &objIDLen);
  if(objID == NULL) {
    return;
  }

  CK_SLOT_ID slotID = atoi(slot);
  CK_SESSION_HANDLE hSession;
  CK_RV rv = C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    if(rv == CKR_SLOT_ID_INVALID) {
      fprintf(stderr, "Error: The given slot does not exist.\n");
    } else {
      fprintf(stderr, "Error: Could not open a session on the given slot.\n");
    }
    free(objID);
    return;
  }

  rv = C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)userPIN, strlen(userPIN));
  if(rv != CKR_OK) {
    if(rv == CKR_PIN_INCORRECT) {
      fprintf(stderr, "Error: The given user PIN does not match the one in the token.\n");
    } else {
      fprintf(stderr, "Error: Could not log in on the token.\n");
    }
    free(objID);
    return;
  }

  key_material_t *keyMat = importKeyMat(filePath, filePIN);
  if(keyMat == NULL) {
    free(objID);
    return;
  }

  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
  CK_ATTRIBUTE pubTemplate[] = {
    { CKA_CLASS,            &pubClass,    sizeof(pubClass) },
    { CKA_KEY_TYPE,         &keyType,     sizeof(keyType) },
    { CKA_LABEL,            label,        strlen(label) },
    { CKA_ID,               objID,        objIDLen },
    { CKA_TOKEN,            &ckTrue,      sizeof(ckTrue) },
    { CKA_VERIFY,           &ckTrue,      sizeof(ckTrue) },
    { CKA_ENCRYPT,          &ckFalse,     sizeof(ckFalse) },
    { CKA_WRAP,             &ckFalse,     sizeof(ckFalse) },
    { CKA_PUBLIC_EXPONENT,  keyMat->bigE, keyMat->sizeE },
    { CKA_MODULUS,          keyMat->bigN, keyMat->sizeN }
  };
  CK_ATTRIBUTE privTemplate[] = {
    { CKA_CLASS,            &privClass,   sizeof(privClass) },
    { CKA_KEY_TYPE,         &keyType,     sizeof(keyType) },
    { CKA_LABEL,            label,        strlen(label) },
    { CKA_ID,               objID,        objIDLen },
    { CKA_SIGN,             &ckTrue,      sizeof(ckTrue) },
    { CKA_DECRYPT,          &ckFalse,     sizeof(ckFalse) },
    { CKA_UNWRAP,           &ckFalse,     sizeof(ckFalse) },
    { CKA_SENSITIVE,        &ckTrue,      sizeof(ckTrue) },
    { CKA_TOKEN,            &ckTrue,      sizeof(ckTrue) },
    { CKA_PRIVATE,          &ckTrue,      sizeof(ckTrue) },
    { CKA_EXTRACTABLE,      &ckFalse,     sizeof(ckFalse) },
    { CKA_PUBLIC_EXPONENT,  keyMat->bigE, keyMat->sizeE },
    { CKA_MODULUS,          keyMat->bigN, keyMat->sizeN },
    { CKA_PRIVATE_EXPONENT, keyMat->bigD, keyMat->sizeD },
    { CKA_PRIME_1,          keyMat->bigP, keyMat->sizeP },
    { CKA_PRIME_2,          keyMat->bigQ, keyMat->sizeQ }
  };

  CK_OBJECT_HANDLE hKey1, hKey2;
  rv = C_CreateObject(hSession, privTemplate, 16, &hKey1);
  if(rv != CKR_OK) {
    freeKeyMaterial(keyMat);
    free(objID);
    fprintf(stderr, "Error: Could not save the private key in the token.\n");
    return;
  }

  rv = C_CreateObject(hSession, pubTemplate, 10, &hKey2);

  freeKeyMaterial(keyMat);
  free(objID);

  if(rv != CKR_OK) {
    C_DestroyObject(hSession, hKey1);
    fprintf(stderr, "Error: Could not save the public key in the token.\n");
    return;
  }

  printf("The key pair has been imported to the token in slot %i.\n", slotID);
}

void exportKeyPair(char *filePath, char *filePIN, char *slot, char *userPIN, char *objectID) {
  if(filePIN != NULL) {
    int filePinLen = strlen(filePIN);
    if(filePinLen < MIN_PIN_LEN || filePinLen > MAX_PIN_LEN) {
      fprintf(stderr, "Error: The file PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
      return;
    }
  }

  if(slot == NULL) {
    fprintf(stderr, "Error: A slot number must be supplied. Use --slot <number>\n");
    return;
  }

  if(userPIN == NULL) {
    fprintf(stderr, "Error: An user PIN must be supplied. Use --pin <PIN>\n");
    return;
  }

  if(objectID == NULL) {
    fprintf(stderr, "Error: An ID for the object must be supplied. Use --id <hex>\n");
    return;
  }
  int objIDLen = 0;
  char *objID = hexStrToBin(objectID, strlen(objectID), &objIDLen);
  if(objID == NULL) {
    return;
  }

  CK_SLOT_ID slotID = atoi(slot);
  CK_SESSION_HANDLE hSession;
  CK_RV rv = C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    if(rv == CKR_SLOT_ID_INVALID) {
      fprintf(stderr, "Error: The given slot does not exist.\n");
    } else {
      fprintf(stderr, "Error: Could not open a session on the given slot.\n");
    }
    free(objID);
    return;
  }

  rv = C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)userPIN, strlen(userPIN));
  if(rv != CKR_OK) {
    if(rv == CKR_PIN_INCORRECT) {
      fprintf(stderr, "Error: The given user PIN does not match the one in the token.\n");
    } else {
      fprintf(stderr, "Error: Could not log in on the token.\n");
    }
    free(objID);
    return;
  }

  CK_OBJECT_HANDLE oHandle = searchObject(hSession, objID, objIDLen);
  if(oHandle == CK_INVALID_HANDLE) {
    free(objID);
    return;
  }

  printf("Function not fully implemented\n");
}

// Convert a char array of hexadecimal characters into a binary representation

char* hexStrToBin(char *objectID, int idLength, int *newLen) {
  char *bytes = NULL;

  if(idLength % 2 != 0) {
    fprintf(stderr, "Error: Invalid length on hex string.\n");
    return NULL;
  }

  for(int i = 0; i < idLength; i++) {
    if(hexdigit_to_int(objectID[i]) == -1) {
      fprintf(stderr, "Error: Invalid character in hex string.\n");
      return NULL;
    }
  }

  *newLen = idLength / 2;
  bytes = (char *)malloc(*newLen);
  if(bytes == NULL) {
    fprintf(stderr, "Error: Could not allocate memory.\n");
    return NULL;
  }

  for(int i = 0; i < *newLen; i++) {
    bytes[i] = hexdigit_to_int(objectID[2*i]) * 16 +
               hexdigit_to_int(objectID[2*i+1]);
  }
  return bytes;
}

// Return the integer value of a hexadecimal character

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

// Import key material from file

key_material_t* importKeyMat(char *filePath, char *filePIN) {
  AutoSeeded_RNG *rng = new AutoSeeded_RNG();
  Private_Key *privKey = NULL;

  try {
    if(filePIN == NULL) {
      privKey = PKCS8::load_key(filePath, *rng);
    } else {
      privKey = PKCS8::load_key(filePath, *rng, filePIN);
    }
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Perhaps wrong path to file, wrong file format, or wrong PIN to file (--file-pin <PIN>).\n");
    delete rng;
    return NULL;
  }
  delete rng;

  if(privKey->algo_name().compare("RSA") != 0) {
    fprintf(stderr, "Error: %s is not a supported algorithm. Only RSA is supported.\n", privKey->algo_name().c_str());
    delete privKey;
    return NULL;
  }

  IF_Scheme_PrivateKey *ifKeyPriv = dynamic_cast<IF_Scheme_PrivateKey*>(privKey);
  key_material_t *keyMat = (key_material_t *)malloc(sizeof(key_material_t));
  keyMat->sizeE = ifKeyPriv->get_e().bytes();
  keyMat->sizeN = ifKeyPriv->get_n().bytes();
  keyMat->sizeD = ifKeyPriv->get_d().bytes();
  keyMat->sizeP = ifKeyPriv->get_p().bytes();
  keyMat->sizeQ = ifKeyPriv->get_q().bytes();
  keyMat->bigE = (CK_VOID_PTR)malloc(keyMat->sizeE);
  keyMat->bigN = (CK_VOID_PTR)malloc(keyMat->sizeN);
  keyMat->bigD = (CK_VOID_PTR)malloc(keyMat->sizeD);
  keyMat->bigP = (CK_VOID_PTR)malloc(keyMat->sizeP);
  keyMat->bigQ = (CK_VOID_PTR)malloc(keyMat->sizeQ);
  ifKeyPriv->get_e().binary_encode((byte *)keyMat->bigE);
  ifKeyPriv->get_n().binary_encode((byte *)keyMat->bigN);
  ifKeyPriv->get_d().binary_encode((byte *)keyMat->bigD);
  ifKeyPriv->get_p().binary_encode((byte *)keyMat->bigP);
  ifKeyPriv->get_q().binary_encode((byte *)keyMat->bigQ);
  delete privKey;

  return keyMat;
}

// Free the memory for the key material container

void freeKeyMaterial(key_material_t *keyMaterial) {
  if(keyMaterial != NULL) {
    if(keyMaterial->bigE != NULL) {
      free(keyMaterial->bigE);
    }
    if(keyMaterial->bigN != NULL) {
      free(keyMaterial->bigN);
    }
    if(keyMaterial->bigD != NULL) {
      free(keyMaterial->bigD);
    }
    if(keyMaterial->bigP != NULL) {
      free(keyMaterial->bigP);
    }
    if(keyMaterial->bigQ != NULL) {
      free(keyMaterial->bigQ);
    }
    free(keyMaterial);
  }
}

// Search for an object

CK_OBJECT_HANDLE searchObject(CK_SESSION_HANDLE hSession, char *objID, int objIDLen) {
  if(objID == NULL) {
    return CK_INVALID_HANDLE;
  }
  CK_OBJECT_CLASS oClass = CKO_PRIVATE_KEY;
  CK_OBJECT_HANDLE hObject = 0;
  CK_ULONG objectCount = 0;

  CK_ATTRIBUTE objTemplate[] = {
    { CKA_CLASS, &oClass, sizeof(oClass) },
    { CKA_ID,    objID,      objIDLen }
  };

  CK_RV rv = C_FindObjectsInit(hSession, objTemplate, 2);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not prepare the object search.\n");
    return CK_INVALID_HANDLE;
  }

  rv = C_FindObjects(hSession, &hObject, 1, &objectCount);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could get the search results.\n");
    return CK_INVALID_HANDLE;
  }

  rv = C_FindObjectsFinal(hSession);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not finalize the search.\n");
    return CK_INVALID_HANDLE;
  }

  if(objectCount == 0) {
    fprintf(stderr, "Error: Could not find the private key.\n");
    return CK_INVALID_HANDLE;
  }

  return hObject;
}
