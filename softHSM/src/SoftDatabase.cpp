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

char ck_bbool_to_c(CK_VOID_PTR pValue) {
  if(*(CK_BBOOL*)pValue == 0) {
    return '0';
  } else {
    return '1';
  }
}

static char sqlCreateTableObjects[] = 
  "CREATE TABLE Objects ("
  "objectID INTEGER PRIMARY KEY,"
  "CKA_CLASS INTEGER DEFAULT NULL,"
  "CKA_TOKEN INTEGER DEFAULT 1,"
  "CKA_PRIVATE INTEGER DEFAULT 1,"
  "CKA_MODIFIABLE INTEGER DEFAULT 0,"
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
    CK_ULONG ulPublicKeyAttributeCount, char *labelID) {

  stringstream sqlInsertObj, sqlObjValue, sqlInsertKey, sqlKeyValue;

  sqlInsertObj << "INSERT INTO Objects (CKA_CLASS, CKA_KEY_TYPE, CKA_KEY_GEN_MECHANISM, CKA_LOCAL";
  // Values of CKO_PUBLIC_KEY, CKK_RSA, CKM_RSA_PKCS_KEY_PAIR_GEN, and CK_TRUE.
  sqlObjValue << "(2, 0, 0, 1";

  sqlInsertKey << "INSERT INTO PublicKeys (X509_public_key";
  sqlKeyValue << "('" << X509::PEM_encode(*rsaKey) << "'";

  int foundID = 0, foundLabel = 0;
  char *pValue;

  // Extract the attributes
  for(unsigned int i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch(pPublicKeyTemplate[i].type) {
      case CKA_TOKEN:
        sqlInsertObj << ", CKA_TOKEN";
        sqlObjValue << ", " << ck_bbool_to_c(pPublicKeyTemplate[i].pValue);
        break;
      case CKA_PRIVATE:
        sqlInsertObj << ", CKA_PRIVATE";
        sqlObjValue << ", " << ck_bbool_to_c(pPublicKeyTemplate[i].pValue);
        break;
      case CKA_MODIFIABLE:
        sqlInsertObj << ", CKA_MODIFIABLE";
        sqlObjValue << ", " << ck_bbool_to_c(pPublicKeyTemplate[i].pValue);
        break;
      case CKA_LABEL:
        foundLabel = 1;
        pValue = (char *)malloc(pPublicKeyTemplate[i].ulValueLen + 1);
        pValue[pPublicKeyTemplate[i].ulValueLen] = '\0';
        memcpy(pValue, pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
        sqlInsertObj << ", CKA_LABEL";
        sqlObjValue << ", '" << pValue << "'";
        break;
      case CKA_ID:
        foundID = 1;
        pValue = (char *)malloc(pPublicKeyTemplate[i].ulValueLen + 1);
        pValue[pPublicKeyTemplate[i].ulValueLen] = '\0';
        memcpy(pValue, pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
        sqlInsertObj << ", CKA_ID";
        sqlObjValue << ", '" << pValue << "'";
        break;
      case CKA_DERIVE:
        sqlInsertObj << ", CKA_DERIVE";
        sqlObjValue << ", " << ck_bbool_to_c(pPublicKeyTemplate[i].pValue);
        break;
      case CKA_SUBJECT:
        pValue = (char *)malloc(pPublicKeyTemplate[i].ulValueLen + 1);
        pValue[pPublicKeyTemplate[i].ulValueLen] = '\0';
        memcpy(pValue, pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
        sqlInsertKey << ", CKA_SUBJECT";
        sqlKeyValue << ", '" << pValue << "'";
        break;
      case CKA_ENCRYPT:
        sqlInsertKey << ", CKA_ENCRYPT";
        sqlKeyValue << ", " << ck_bbool_to_c(pPublicKeyTemplate[i].pValue);
        break;
      case CKA_VERIFY:
        sqlInsertKey << ", CKA_VERIFY";
        sqlKeyValue << ", " << ck_bbool_to_c(pPublicKeyTemplate[i].pValue);
        break;
      case CKA_VERIFY_RECOVER:
        sqlInsertKey << ", CKA_VERIFY_RECOVER";
        sqlKeyValue << ", " << ck_bbool_to_c(pPublicKeyTemplate[i].pValue);
        break;
      case CKA_WRAP:
        sqlInsertKey << ", CKA_WRAP";
        sqlKeyValue << ", " << ck_bbool_to_c(pPublicKeyTemplate[i].pValue);
        break;
      case CKA_TRUSTED:
        sqlInsertKey << ", CKA_TRUSTED";
        sqlKeyValue << ", " << ck_bbool_to_c(pPublicKeyTemplate[i].pValue);
        break;
      default:
        break;
    }
  }

  // Assign a default value if not defined by the user.
  if(foundLabel == 0) {
    sqlInsertObj << ", CKA_LABEL";
    sqlObjValue << ", '" << labelID << "'";
  }
  if(foundID == 0) {
    sqlInsertObj << ", CKA_ID";
    sqlObjValue << ", '" << labelID << "'";
  }

  // Insert the public key.
  sqlInsertKey << ") VALUES " << sqlKeyValue.str() << ");";
  sqlite3_exec(db, sqlInsertKey.str().c_str(), NULL, NULL, NULL);  
  int keyID = sqlite3_last_insert_rowid(db);

  // Add reference to the public key.
  sqlInsertObj << ", keyID";
  sqlObjValue << ", " << keyID;
  
  // Add the key object.
  sqlInsertObj << ") VALUES " << sqlObjValue.str() << ");";
  sqlite3_exec(db, sqlInsertObj.str().c_str(), NULL, NULL, NULL);  
  keyID = sqlite3_last_insert_rowid(db);

  return keyID;
}

int SoftDatabase::addRSAKeyPriv(SoftSession *session, char *pin, RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
    CK_ULONG ulPrivateKeyAttributeCount, char *labelID) {

  stringstream sqlInsertObj, sqlObjValue, sqlInsertKey, sqlKeyValue;

  sqlInsertObj << "INSERT INTO Objects (CKA_CLASS, CKA_KEY_TYPE, CKA_KEY_GEN_MECHANISM, CKA_LOCAL";
  // Values of CKO_PRIVATE_KEY, CKK_RSA, CKM_RSA_PKCS_KEY_PAIR_GEN, and CK_TRUE.
  sqlObjValue << "(3, 0, 0, 1";

  sqlInsertKey << "INSERT INTO PrivateKeys (encrypted_PKCS8_private_key";
  sqlKeyValue << "('" << PKCS8::PEM_encode(*rsaKey, *session->rng, pin) << "'";

  int foundID = 0, foundLabel = 0;
  char *pValue;

  // Extract the attributes
  for(unsigned int i = 0; i < ulPrivateKeyAttributeCount; i++) {
    switch(pPrivateKeyTemplate[i].type) {
      case CKA_TOKEN:
        sqlInsertObj << ", CKA_TOKEN";
        sqlObjValue << ", " << ck_bbool_to_c(pPrivateKeyTemplate[i].pValue);
        break;
      case CKA_PRIVATE:
        sqlInsertObj << ", CKA_PRIVATE";
        sqlObjValue << ", " << ck_bbool_to_c(pPrivateKeyTemplate[i].pValue);
        break;
      case CKA_MODIFIABLE:
        sqlInsertObj << ", CKA_MODIFIABLE";
        sqlObjValue << ", " << ck_bbool_to_c(pPrivateKeyTemplate[i].pValue);
        break;
      case CKA_LABEL:
        foundLabel = 1;
        pValue = (char *)malloc(pPrivateKeyTemplate[i].ulValueLen + 1);
        pValue[pPrivateKeyTemplate[i].ulValueLen] = '\0';
        memcpy(pValue, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
        sqlInsertObj << ", CKA_LABEL";
        sqlObjValue << ", '" << pValue << "'";
        break;
      case CKA_ID:
        foundID = 1;
        pValue = (char *)malloc(pPrivateKeyTemplate[i].ulValueLen + 1);
        pValue[pPrivateKeyTemplate[i].ulValueLen] = '\0';
        memcpy(pValue, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
        sqlInsertObj << ", CKA_ID";
        sqlObjValue << ", '" << pValue << "'";
        break;
      case CKA_DERIVE:
        sqlInsertObj << ", CKA_DERIVE";
        sqlObjValue << ", " << ck_bbool_to_c(pPrivateKeyTemplate[i].pValue);
        break;
      case CKA_SUBJECT:
        pValue = (char *)malloc(pPrivateKeyTemplate[i].ulValueLen + 1);
        pValue[pPrivateKeyTemplate[i].ulValueLen] = '\0';
        memcpy(pValue, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
        sqlInsertKey << ", CKA_SUBJECT";
        sqlKeyValue << ", '" << pValue << "'";
        break;
      case CKA_SENSITIVE:
        sqlInsertKey << ", CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE";
        if(ck_bbool_to_c(pPrivateKeyTemplate[i].pValue) == '0') {
          sqlKeyValue << ", 0, 0";
        } else {
          sqlKeyValue << ", 1, 1";
        }
        break;
      case CKA_DECRYPT:
        sqlInsertKey << ", CKA_DECRYPT";
        sqlKeyValue << ", " << ck_bbool_to_c(pPrivateKeyTemplate[i].pValue);
        break;
      case CKA_SIGN:
        sqlInsertKey << ", CKA_SIGN";
        sqlKeyValue << ", " << ck_bbool_to_c(pPrivateKeyTemplate[i].pValue);
        break;
      case CKA_SIGN_RECOVER:
        sqlInsertKey << ", CKA_SIGN_RECOVER";
        sqlKeyValue << ", " << ck_bbool_to_c(pPrivateKeyTemplate[i].pValue);
        break;
      case CKA_UNWRAP:
        sqlInsertKey << ", CKA_UNWRAP";
        sqlKeyValue << ", " << ck_bbool_to_c(pPrivateKeyTemplate[i].pValue);
      case CKA_EXTRACTABLE:
        sqlInsertKey << ", CKA_EXTRACTABLE, CKA_NEVER_EXTRACTABLE";
        if(ck_bbool_to_c(pPrivateKeyTemplate[i].pValue) == '0') {
          sqlKeyValue << ", 0, 1";
        } else {
          sqlKeyValue << ", 1, 0";
        }
      case CKA_WRAP_WITH_TRUSTED:
        sqlInsertKey << ", CKA_WRAP_WITH_TRUSTED";
        sqlKeyValue << ", " << ck_bbool_to_c(pPrivateKeyTemplate[i].pValue);
      case CKA_ALWAYS_AUTHENTICATE:
        sqlInsertKey << ", CKA_ALWAYS_AUTHENTICATE";
        sqlKeyValue << ", " << ck_bbool_to_c(pPrivateKeyTemplate[i].pValue);
        break;
      default:
        break;
    }
  }

  // Assign a default value if not defined by the user.
  if(foundLabel == 0) {
    sqlInsertObj << ", CKA_LABEL";
    sqlObjValue << ", '" << labelID << "'";
  }
  if(foundID == 0) {
    sqlInsertObj << ", CKA_ID";
    sqlObjValue << ", '" << labelID << "'";
  }

  // Insert the private key.
  sqlInsertKey << ") VALUES " << sqlKeyValue.str() << ");";
  sqlite3_exec(db, sqlInsertKey.str().c_str(), NULL, NULL, NULL);
  int keyID = sqlite3_last_insert_rowid(db);

  // Add reference to the private key.
  sqlInsertObj << ", keyID";
  sqlObjValue << ", " << keyID;

  // Add the key object.
  sqlInsertObj << ") VALUES " << sqlObjValue.str() << ");";
  sqlite3_exec(db, sqlInsertObj.str().c_str(), NULL, NULL, NULL);
  keyID = sqlite3_last_insert_rowid(db);

  return keyID;
}

void SoftDatabase::populateObj(SoftObject *&keyObject, int keyRef) {
  stringstream sqlQuery;
  sqlQuery << "SELECT * from Objects WHERE objectID = " << keyRef << ";";

  string sqlQueryStr = sqlQuery.str();
  sqlite3_stmt* select_sql;
  int result = sqlite3_prepare(db, sqlQueryStr.c_str(), sqlQueryStr.size(), &select_sql, NULL);

  if(result) {
    return;
  }

  if(sqlite3_step(select_sql) == SQLITE_ROW) {
    keyObject = new SoftObject();

    int intValue = sqlite3_column_int(select_sql, 1);
    keyObject->addAttributeFromData(CKA_CLASS, &intValue, sizeof(intValue));
    char boolValue = (char)sqlite3_column_int(select_sql, 2);
    keyObject->addAttributeFromData(CKA_TOKEN, &boolValue, sizeof(boolValue));
    boolValue = (char)sqlite3_column_int(select_sql, 3);
    keyObject->addAttributeFromData(CKA_PRIVATE, &boolValue, sizeof(boolValue));
    boolValue = (char)sqlite3_column_int(select_sql, 4);
    keyObject->addAttributeFromData(CKA_MODIFIABLE, &boolValue, sizeof(boolValue));
    char *textValue = (char *)sqlite3_column_text(select_sql, 5);
    keyObject->addAttributeFromData(CKA_LABEL, textValue, strlen(textValue));
    intValue = sqlite3_column_int(select_sql, 6);
    keyObject->addAttributeFromData(CKA_KEY_TYPE, &intValue, sizeof(intValue));
    textValue = (char *)sqlite3_column_text(select_sql, 7);
    keyObject->addAttributeFromData(CKA_ID, textValue, strlen(textValue));
    boolValue = (char)sqlite3_column_int(select_sql, 8);
    keyObject->addAttributeFromData(CKA_DERIVE, &boolValue, sizeof(boolValue));
    boolValue = (char)sqlite3_column_int(select_sql, 9);
    keyObject->addAttributeFromData(CKA_LOCAL, &boolValue, sizeof(boolValue));
    intValue = sqlite3_column_int(select_sql, 10);
    keyObject->addAttributeFromData(CKA_KEY_GEN_MECHANISM, &intValue, sizeof(intValue));

    // TBC....
  }
}
