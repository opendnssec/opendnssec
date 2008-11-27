/* $Id: SoftSession.cpp 66 2008-11-27 10:14:26Z jakob $ */

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
* This class defines a session
* It holds the current state of the session
*
************************************************************/

SoftSession::SoftSession() {
  pApplication = NULL_PTR;
  Notify = NULL_PTR;
  readOnly = false;

  findAnchor = NULL_PTR;
  findCurrent = NULL_PTR;
  findInitialized = false;

  digestPipe = NULL_PTR;
  digestSize = 0;
  digestInitialized = false;

  pkSigner = NULL_PTR;
  signSinglePart = false;
  signSize = 0;
  signInitialized = false;
}

SoftSession::~SoftSession() {
  pApplication = NULL_PTR;
  Notify = NULL_PTR;

  if(findAnchor != NULL_PTR) {
    delete findAnchor;
    findAnchor = NULL_PTR;
  }

  findCurrent = NULL_PTR;

  if(digestPipe != NULL_PTR) {
    delete digestPipe;
    digestPipe = NULL_PTR;
  }

  if(pkSigner != NULL_PTR) {
    delete pkSigner;
    pkSigner = NULL_PTR;
  }

}

bool SoftSession::isReadOnly() {
  return readOnly;
}
