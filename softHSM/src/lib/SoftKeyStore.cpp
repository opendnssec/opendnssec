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
* This class handles the key cache for each session
*
* A new key is added by prepending a new KeyStore object
* and making it first in the chain.
*
* A more recent cached key is more likely to be used,
* thus is it better to have it first in the chain.
*
************************************************************/

#include "SoftKeyStore.h"

SoftKeyStore::SoftKeyStore() {
  next = NULL_PTR;
  botanKey = NULL_PTR;
  index = 0;
}

SoftKeyStore::~SoftKeyStore() {
  if(next != NULL_PTR) {
    delete next;
    next = NULL_PTR;
  }

  if(botanKey != NULL_PTR) {
    delete botanKey;
    botanKey = NULL_PTR;
  }
}

// Remove the key with a given index

void SoftKeyStore::removeKey(CK_OBJECT_HANDLE removeIndex) {
  if(next != NULL_PTR) {
    if(removeIndex == index) {
      // Remove the key
      if(botanKey != NULL_PTR) {
        delete botanKey;
      }

      // Copy the information from the next key
      index = next->index;
      botanKey = next->botanKey;
      SoftKeyStore *tmpPtr = next->next;

      // Delete the next container
      next->botanKey = NULL_PTR;
      next->next = NULL_PTR;
      delete next;

      // Connect with the tail
      next = tmpPtr;
    } else {
      next->removeKey(removeIndex);
    }
  } else {
    return;
  }
}

// Find the key with a given index

Public_Key *SoftKeyStore::getKey(CK_OBJECT_HANDLE getIndex) {
  if(next != NULL_PTR) {
    if(getIndex == index) {
      return botanKey;
    } else {
      return next->getKey(getIndex);
    }
  } else {
    return NULL_PTR;
  }
}
