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

#ifndef SOFTHSM_MAIN_H
#define SOFTHSM_MAIN_H 1

// Version number for SoftHSM
#define VERSION_MAJOR 0
#define VERSION_MINOR 1

// Maximum number of concurrent sessions
#define MAX_SESSION_COUNT 2048

// Maximum number of objects in SoftHSM
#define MAX_OBJECTS 2000

// Standard includes
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <time.h>

// C POSIX library header
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>

// Includes for the crypto library
#include <botan/botan.h>
#include <botan/bigint.h>
#include <botan/md5.h>
#include <botan/rmd160.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>
#include <botan/rsa.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/x509_obj.h>
#include <botan/exceptn.h>
#include <botan/emsa3.h>
#include <botan/emsa_raw.h>
#include <botan/pubkey.h>
using namespace Botan;

// Unix specific. Defined by RSA Lab.
#include <pkcs11_unix.h>
// PKCS11. Defined by RSA Lab.
#include <pkcs11.h>

// Internal classes
class SoftHSMInternal;
class SoftSession;
class SoftObject;
class SoftFind;
class SoftAttribute;

// Internal definitions
#include "SoftHSMInternal.h"
#include "SoftSession.h"
#include "SoftObject.h"
#include "SoftFind.h"
#include "SoftAttribute.h"
#include "file.h"

#endif /* SOFTHSM_MAIN_H */
