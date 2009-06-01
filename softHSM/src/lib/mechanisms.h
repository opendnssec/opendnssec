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

#ifndef SOFTHSM_MECHANISMS_H
#define SOFTHSM_MECHANISMS_H 1

#include "pkcs11_unix.h"

// The number of supported mechanisms
#define NR_SUPPORTED_MECHANISMS 14

// A list with the supported mechanisms
static CK_MECHANISM_TYPE supportedMechanisms[] = {
	CKM_RSA_PKCS_KEY_PAIR_GEN,
	CKM_RSA_PKCS,
	CKM_MD5,
	CKM_RIPEMD160,
	CKM_SHA_1,
	CKM_SHA256,
	CKM_SHA384,
	CKM_SHA512,
	CKM_MD5_RSA_PKCS,
	CKM_RIPEMD160_RSA_PKCS,
	CKM_SHA1_RSA_PKCS,
	CKM_SHA256_RSA_PKCS,
	CKM_SHA384_RSA_PKCS,
	CKM_SHA512_RSA_PKCS
};

CK_RV getMechanismInfo(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);

#endif /* SOFTHSM_MECHANISMS_H */
