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

#define DB_TOKEN_LABEL 0
#define DB_TOKEN_SOPIN 1
#define DB_TOKEN_USERPIN 2

#include "softhsm.h"
#include "pkcs11_unix.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>

void usage() {
  printf("Usage: softhsm [OPTIONS]\n");
  printf("Support tool for libsofthsm\n");
  printf("Options:\n");
  printf("--show-slots         Display all the available slots.\n");
  printf("--init-token         Initialize the token at a given slot.\n");
  printf("                     Use with --slot, --label, --so-pin, and --pin.\n");
  printf("                     WARNING: Any content in token token will be erased.\n");
  printf("--slot <number>      The slot where the token is located.\n");
  printf("--label <text>       Defines the label of the token. Max 32 chars.\n");
  printf("--so-pin <PIN>       The PIN for the Security Officer (SO). 4-255 chars.\n");
  printf("--pin <PIN>          The PIN for the normal user. 4-255 chars.\n");
  printf("--help               Shows this help.\n");
  printf("-h                   Shows this help.\n\n\n");
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
  OPT_SLOT,
  OPT_LABEL,
  OPT_SO_PIN,
  OPT_PIN,
  OPT_HELP
};

static const struct option long_options[] = {
  { "show-slots", 0, NULL, OPT_SHOW_SLOTS },
  { "init-token", 0, NULL, OPT_INIT_TOKEN },
  { "slot",       1, NULL, OPT_SLOT },
  { "label",      1, NULL, OPT_LABEL },
  { "so-pin",     1, NULL, OPT_SO_PIN },
  { "pin",        1, NULL, OPT_PIN },
  { "help",       0, NULL, OPT_HELP },
  { NULL,         0, NULL, 0 }
};

int main(int argc, char *argv[]) {
  int option_index = 0;
  int opt;

  char *soPIN = NULL;
  char *userPIN = NULL;
  char *label = NULL;
  char *slot = NULL;

  int doInitToken = 0;
  int doShowSlots = 0;

  while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
    switch (opt) {
      case OPT_SHOW_SLOTS:
        doShowSlots = 1;
        break;
      case OPT_INIT_TOKEN:
        doInitToken = 1;
        break;
      case OPT_SLOT:
        slot = optarg;
        break;
      case OPT_LABEL:
        label = optarg;
        break;
      case OPT_SO_PIN:
        soPIN = optarg;
        break;
      case OPT_PIN:
        userPIN = optarg;
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
  if(doInitToken == 0 && doShowSlots == 0) {
    usage();
  }

  // We should create the token.
  if(doInitToken) {
    initToken(slot, label, soPIN, userPIN);
  }

  if(doShowSlots) {
    showSlots();
  }

  return 0;
}

// Creates a SoftHSM token at the given location.

void initToken(char *slot, char *label, char *soPIN, char *userPIN) {
  if(slot == NULL) {
    printf("Error: A slot number must be supplied.\n");
    exit(1);
  }

  if(label == NULL) {
    printf("Error: A label for the token must be supplied.\n");
    exit(1);
  }

  if(strlen(label) > 32) {
    printf("Error: The label must not have a length greater than 32 chars.\n");
    exit(1);
  }

  if(soPIN == NULL) {
    #ifdef HAVE_GETPASSPHRASE
      soPIN = getpassphrase("Enter SO PIN (4-255 chars): ");
    #else
      soPIN = getpass("Enter SO PIN (4-255 chars): ");
    #endif
  }

  int soLength = strlen(soPIN);
  while(soLength < 4 || soLength > 255) {
    #ifdef HAVE_GETPASSPHRASE
      soPIN = getpassphrase("Wrong size! Enter SO PIN (4-255 chars): ");
    #else
      soPIN = getpass("Wrong size! Enter SO PIN (4-255 chars): ");
    #endif
    soLength = strlen(soPIN);
  }

  if(userPIN == NULL) {
    #ifdef HAVE_GETPASSPHRASE
      userPIN = getpassphrase("Enter user PIN (4-255 chars): ");
    #else
      userPIN = getpass("Enter user PIN (4-255 chars): ");
    #endif
  }
	
  int userLength = strlen(userPIN);
  while(userLength < 4 || userLength > 255) {
    #ifdef HAVE_GETPASSPHRASE
      userPIN = getpassphrase("Wrong size! Enter user PIN (4-255 chars): ");
    #else
      userPIN = getpass("Wrong size! Enter user PIN (4-255 chars): ");
    #endif
    userLength = strlen(userPIN);
  }

  // Load the variables
  CK_SLOT_ID slotID = atoi(slot);
  CK_UTF8CHAR paddedLabel[32];
  memset(paddedLabel, ' ', sizeof(label));
  memcpy(paddedLabel, label, strlen(label));

  CK_RV rv = C_Initialize(NULL_PTR);
  if(rv != CKR_OK) {
    printf("Could not initialize libsofthsm. Probably missing the configuration file.\n");
    exit(1);
  }

  rv = C_InitToken(slotID, (CK_UTF8CHAR_PTR)soPIN, soLength, paddedLabel);

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

  rv = C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)soPIN, soLength);
  if(rv != CKR_OK) {
    printf("Error: Could not log in on the token.\n");
    exit(1);
  }

  rv = C_InitPIN(hSession, (CK_UTF8CHAR_PTR)userPIN, userLength);
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
