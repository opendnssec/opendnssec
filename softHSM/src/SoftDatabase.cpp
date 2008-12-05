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
* This class handles the database.
*
************************************************************/

#include "main.h"

static char sqlCreateTableObjects[] = 
  "CREATE TABLE Objects ("
  "objectID INTEGER PRIMARY KEY,"
  "CKA_CLASS INTEGER DEFAULT NULL,"
  "CKA_TOKEN INTEGER DEFAULT 1,"
  "CKA_PRIVATE INTEGER DEFAULT 0,"
  "CKA_MODIFIABLE INTEGER DEFAULT 1,"
  "CKA_LABEL TEXT DEFAULT NULL,"
  "CKA_KEY_TYPE INTEGER DEFAULT NULL,"
  "CKA_ID BLOB DEFAULT NULL,"
  "CKA_DERIVE INTEGER DEFAULT 1,"
  "CKA_LOCAL INTEGER DEFAULT 1,"
  "CKA_KEY_GEN_MECHANISM INTEGER DEFAULT NULL,"
  "keyID INTEGER DEFAULT NULL);";

static char sqlCreateTablePublicKeys[] =
  "CREATE TABLE PublicKeys ("
  "publicKeyID INTEGER PRIMARY KEY,"
  "CKA_SUBJECT TEXT DEFAULT NULL,"
  "CKA_ENCRYPT INTEGER DEFAULT 1,"
  "CKA_VERIFY INTEGER DEFAULT 1,"
  "CKA_VERIFY_RECOVER INTEGER DEFAULT 1,"
  "CKA_WRAP INTEGER DEFAULT 1,"
  "CKA_TRUSTED INTEGER DEFAULT 1,"
  "X509_public_key TEXT DEFAULT NULL);";

static char sqlCreateTablePrivateKeys[] =
  "CREATE TABLE PrivateKeys ("
  "privateKeyID INTEGER PRIMARY KEY,"
  "CKA_SUBJECT TEXT DEFAULT NULL,"
  "CKA_SENSITIVE INTEGER DEFAULT 1,"
  "CKA_DECRYPT INTEGER DEFAULT 1,"
  "CKA_SIGN INTEGER DEFAULT 1,"
  "CKA_SIGN_RECOVER INTEGER DEFAULT 1,"
  "CKA_UNWRAP INTEGER DEFAULT 1,"
  "CKA_EXTRACTABLE INTEGER DEFAULT 0,"
  "CKA_ALWAYS_SENSITIVE INTEGER DEFAULT 1,"
  "CKA_NEVER_EXTRACTABLE INTEGER DEFAULT 1,"
  "CKA_WRAP_WITH_TRUSTED INTEGER DEFAULT 0,"
  "CKA_ALWAYS_AUTHENTICATE INTEGER DEFAULT 0,"
  "encrypted_PKCS8_private_key TEXT DEFAULT NULL);";

SoftDatabase::SoftDatabase() {
  char *sqlError;

  int result = sqlite3_open(getDatabasePath(), &db);
  if(result){
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    exit(1);
  }

  result = sqlite3_exec(db, "SELECT COUNT(objectID) FROM Objects;", NULL, NULL, NULL);
  if(result) {
    result = sqlite3_exec(db, sqlCreateTableObjects, NULL, NULL, &sqlError);
    if(result) {
      fprintf(stderr, "Can't create table Objects: %s\n", sqlError);
      sqlite3_close(db);
      exit(1);
    }
  }

  result = sqlite3_exec(db, "SELECT COUNT(publicKeyID) FROM PublicKeys;", NULL, NULL, NULL);
  if(result) {
    result = sqlite3_exec(db, sqlCreateTablePublicKeys, NULL, NULL, &sqlError);
    if(result) {
      fprintf(stderr, "Can't create table PublicKeys: %s\n", sqlError);
      sqlite3_close(db);
      exit(1);
    }
  }

  result = sqlite3_exec(db, "SELECT COUNT(privateKeyID) FROM PrivateKeys;", NULL, NULL, NULL);
  if(result) {
    result = sqlite3_exec(db, sqlCreateTablePrivateKeys, NULL, NULL, &sqlError);
    if(result) {
      fprintf(stderr, "Can't create table PrivateKeys: %s\n", sqlError);
      sqlite3_close(db);
      exit(1);
    }
  }
}

SoftDatabase::~SoftDatabase() {
  sqlite3_close(db);
}

int SoftDatabase::addRSAKeyPub(RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
    CK_ULONG ulPublicKeyAttributeCount) {

  std::string sqlInsertObj = "INSERT INTO Objects";
  std::string sqlInsertKey = "INSERT INTO PublicKeys";

  // CKA_CLASS = CKO_PUBLIC_KEY
  // CKA_KEY_TYPE = CKK_RSA
  // CKA_KEY_GEN_MECHANISM = CKM_RSA_PKCS_KEY_PAIR_GEN
  // CKA_LOCAL = CK_TRUE

  // Extract the attributes
  for(unsigned int i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch(pPublicKeyTemplate[i].type) {
      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_MODIFIABLE:
      case CKA_LABEL:
      case CKA_ID:
      case CKA_DERIVE:
      case CKA_SUBJECT:
      case CKA_ENCRYPT:
      case CKA_VERIFY:
      case CKA_VERIFY_RECOVER:
      case CKA_WRAP:
      case CKA_TRUSTED:
        break;
      default:
        break;
    }
  }

  return 0;
}

int SoftDatabase::addRSAKeyPriv(RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
    CK_ULONG ulPrivateKeyAttributeCount) {

  return 0;
}
