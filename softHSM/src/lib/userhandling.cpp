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
* Functions for user handling.
*
************************************************************/

#include "userhandling.h"

// Standard includes
#include <stdlib.h>
#include <stdio.h>

// Includes for the crypto library
#include <botan/pipe.h>
#include <botan/filters.h>
#include <botan/hex.h>
#include <botan/sha2_32.h>
using namespace Botan;

// Checks if an action is allowed on a given object type.
//
//                                       Type of session
//  Type of object          R/O Public | R/W Public | R/O User | R/W User | R/W SO
//  ------------------------------------------------------------------------------
//  Public session object       R/W    |     R/W    |    R/W   |    R/W   |   R/W
//  Private session object             |            |    R/W   |    R/W   |
//  Public token object         R/O    |     R/W    |    R/O   |    R/W   |   R/W
//  Private token object               |            |    R/O   |    R/W   |
//
// int userAction = 0 (read)
//                  1 (write)

CK_BBOOL userAuthorization(CK_STATE sessionState, CK_BBOOL isTokenObject, CK_BBOOL isPrivateObject, int userAction) {
  switch(sessionState) {
    case CKS_RW_SO_FUNCTIONS:
      if(isPrivateObject == CK_FALSE) {
        return CK_TRUE;
      } else {
        return CK_FALSE;
      }
      break;
    case CKS_RW_USER_FUNCTIONS:
      return CK_TRUE;
      break;
    case CKS_RO_USER_FUNCTIONS:
      if(isTokenObject == CK_TRUE) {
        if(userAction == 1) {
          return CK_FALSE;
        } else {
          return CK_TRUE;
        }
      } else {
        return true;
      }
      break;
    case CKS_RW_PUBLIC_SESSION:
      if(isPrivateObject == CK_FALSE) {
        return CK_TRUE;
      } else {
        return CK_FALSE;
      }
      break;
    case CKS_RO_PUBLIC_SESSION:
      if(isPrivateObject == CK_FALSE) {
        if(isTokenObject == CK_TRUE && userAction == 1) {
          return CK_FALSE;
        } else {
          return CK_TRUE;
        }
      } else {
        return CK_FALSE;
      }

      break;
    default:
      break;
  }

  return CK_FALSE;
}

// Creates a digest of PIN

char* digestPIN(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  // We do not use any salt
  Pipe *digestPIN = new Pipe(new Hash_Filter(new SHA_256), new Hex_Encoder);
  digestPIN->start_msg();
  digestPIN->write((byte*)pPin, (u32bit)ulPinLen);
  digestPIN->write((byte*)pPin, (u32bit)ulPinLen);
  digestPIN->write((byte*)pPin, (u32bit)ulPinLen);
  digestPIN->end_msg();

  // Get the digested PIN
  SecureVector<byte> pinVector = digestPIN->read_all();
  int size = pinVector.size();
  char *tmpPIN = (char *)malloc(size + 1);
  if(tmpPIN != NULL_PTR) {
    tmpPIN[size] = '\0';
    memcpy(tmpPIN, pinVector.begin(), size);
  }
  delete digestPIN;

  return tmpPIN;
}
