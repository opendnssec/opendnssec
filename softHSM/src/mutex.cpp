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
* These mutex functions are used if nothing is provided 
* by the external application.
* These function calls are POSIX specific.
*
************************************************************/

#include "main.h"

// Internal representation of CK_CREATEMUTEX

CK_RV softHSMCreateMutex(CK_VOID_PTR_PTR newMutex) {
  // Allocate memory
  pthread_mutex_t *mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));

  // If something went wrong
  if(mutex == NULL) {
    return CKR_HOST_MEMORY;
  }

  // Initialize the mutex and check that it went well
  if(pthread_mutex_init(mutex, NULL) != 0) {
    free(mutex);
    return CKR_GENERAL_ERROR;
  }

  // Return the mutex
  *newMutex = mutex;

  return CKR_OK;
}  

// Internal representation of CK_DESTROYMUTEX

CK_RV softHSMDestroyMutex(CK_VOID_PTR mutex) {
  // Destroy the mutex
  pthread_mutex_destroy((pthread_mutex_t *)mutex);
  free(mutex);

  return CKR_OK;
}

// Internal representation of CK_LOCKMUTEX

CK_RV softHSMLockMutex(CK_VOID_PTR mutex) {
  if(pthread_mutex_lock((pthread_mutex_t *)mutex) == 0) {
    return CKR_OK;
  } else {
    return CKR_GENERAL_ERROR;
  }
}

// Internal representation of CK_UNLOCKMUTEX

CK_RV softHSMUnlockMutex(CK_VOID_PTR mutex) {
  if(pthread_mutex_unlock((pthread_mutex_t *)mutex) == 0) {
    return CKR_OK;
  } else {
    return CKR_GENERAL_ERROR;
  }
}
