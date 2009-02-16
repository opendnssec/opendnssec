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
* This class handles the database.
*
************************************************************/

#ifndef SOFTHSM_SOFTDATABASE_H
#define SOFTHSM_SOFTDATABASE_H 1

#include "pkcs11_unix.h"
#include "SoftObject.h"

// The SQLite header
#include <sqlite3.h>

// Includes for the crypto library
#include <botan/bigint.h>
#include <botan/rsa.h>
using namespace Botan;

class SoftObject;

class SoftDatabase {
  public:
    SoftDatabase();
    ~SoftDatabase();

    CK_RV init(char *dbPath);

    SoftObject* readAllObjects();
    SoftObject* populateObj(CK_OBJECT_HANDLE keyRef);

    CK_OBJECT_HANDLE addRSAKeyPub(char *pin, RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
      CK_ULONG ulPublicKeyAttributeCount, char *labelID);
    CK_OBJECT_HANDLE addRSAKeyPriv(char *pin, RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
      CK_ULONG ulPrivateKeyAttributeCount, char *labelID);
    void deleteObject(char *pin, CK_OBJECT_HANDLE objRef);

    void saveAttribute(CK_OBJECT_HANDLE objectID, CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG ulValueLen);
    void saveAttributeBigInt(CK_OBJECT_HANDLE objectID, CK_ATTRIBUTE_TYPE type, BigInt *bigNumber);

  private:
    sqlite3 *db;
};

#endif /* SOFTHSM_SOFTDATABASE_H */
