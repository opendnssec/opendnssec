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
* Functions for file handling.
* Many of the function calls are POSIX specific.
*
************************************************************/

#include "file.h"
#include "log.h"
#include "SoftHSMInternal.h"

// Standard includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

extern SoftHSMInternal *softHSM;

// Reads the config file

CK_RV readConfigFile() {
  FILE *fp;

  const char *confPath = getenv("SOFTHSM_CONF");

  if(confPath == NULL) {
    confPath = SOFT_CONFIG_FILE;
  }

  fp = fopen(confPath,"r");

  if(fp == NULL) {
    char errorMsg[1024];
    snprintf(errorMsg, sizeof(errorMsg), "Could not open the config file: %s", confPath);

    ERROR_MSG("C_Initialize", errorMsg);
    return CKR_GENERAL_ERROR;
  }

  char fileBuf[1024];

  // Format in config file
  //
  // slotID:dbPath
  // # Line is ignored
  
  while(fgets(fileBuf, sizeof(fileBuf), fp) != NULL) {
    // End the string at the first comment or newline
    fileBuf[strcspn(fileBuf, "#\n\r")] = '\0';

    // Get the first part of the line
    char *slotidstr = strtok(fileBuf, ":");

    // Check that we have a digit in the first position, so it can be parsed.
    if(slotidstr == NULL || !isdigit((int)*slotidstr)) {
      continue;
    }

    // Get the second part of the line
    char *dbPath = strtok(NULL, ":");
    if(dbPath == NULL) {
      continue;
    }

    int startPos = 0;
    int endPos = strlen(dbPath);

    // Find the first position without a space
    while(isspace((int)*(dbPath + startPos)) && startPos < endPos) {
      startPos++;
    }
    // Find the last position without a space
    while(isspace((int)*(dbPath + endPos)) && startPos < endPos) {
      endPos--;
    }

    // We must have a valid string
    int length = endPos - startPos;
    if(length <= 0) {
      continue;
    }

    // Create the real DB path
    char *realPath = (char *)malloc(length + 1);
    if(realPath == NULL_PTR) {
      continue;
    }
    realPath[length] = '\0';
    memcpy(realPath, dbPath + startPos, length);

    // Add the slot
    softHSM->slots->addSlot(atoi(slotidstr), realPath);
  }

  fclose(fp);

  return CKR_OK;
}
