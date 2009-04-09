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
#include "SoftDatabase.h"
#include "file.h"
#include "log.h"

// Standard includes
#include <string.h>
#include <sstream>
#include <stdlib.h>
using std::stringstream;
using std::string;

SoftDatabase::SoftDatabase() {
  db = NULL_PTR;
  token_info_sql = NULL;
  select_attri_id_sql = NULL;
  update_attribute_sql = NULL;
  insert_attribute_sql = NULL;
  update_object_key_sql = NULL;
}

SoftDatabase::~SoftDatabase() {
  if(token_info_sql != NULL) {
    sqlite3_finalize(token_info_sql);
  }

  if(select_attri_id_sql != NULL) {
    sqlite3_finalize(select_attri_id_sql);
  }

  if(update_attribute_sql != NULL) {
    sqlite3_finalize(update_attribute_sql);
  }

  if(insert_attribute_sql != NULL) {
    sqlite3_finalize(insert_attribute_sql);
  }

  if(update_object_key_sql != NULL) {
    sqlite3_finalize(update_object_key_sql);
  }

  sqlite3_close(db);
}

CK_RV SoftDatabase::init(char *dbPath) {
  // Open the database
  int result = sqlite3_open(dbPath, &db);
  if(result){
    if(db != NULL_PTR) {
      sqlite3_close(db);
    }

    return CKR_TOKEN_NOT_PRESENT;
  }

  // Check that the Token table exist
  result = sqlite3_exec(db, "SELECT COUNT(variableID) FROM Token;", NULL, NULL, NULL);
  if(result) {
    return CKR_TOKEN_NOT_PRESENT;
  }

  // Check that the Objects table exist
  result = sqlite3_exec(db, "SELECT COUNT(objectID) FROM Objects;", NULL, NULL, NULL);
  if(result) {
    return CKR_TOKEN_NOT_PRESENT;
  }

  // Check that the Attributes table exist
  result = sqlite3_exec(db, "SELECT COUNT(attributeID) FROM Attributes;", NULL, NULL, NULL);
  if(result) {
    return CKR_TOKEN_NOT_PRESENT;
  }

  // Create prepared statements

  const char token_info_str[] = "SELECT value FROM Token where variableID = ?;";
  result = sqlite3_prepare_v2(db, token_info_str, -1, &token_info_sql, NULL);
  if(result) {
    return CKR_TOKEN_NOT_PRESENT;
  }

  const char select_attri_id_str[] = "SELECT attributeID FROM Attributes WHERE objectID = ? AND type = ?;";
  result = sqlite3_prepare_v2(db, select_attri_id_str, -1, &select_attri_id_sql, NULL);
  if(result) {
    return CKR_TOKEN_NOT_PRESENT;
  }

  const char update_attribute_str[] = "UPDATE Attributes SET value = ?, length = ? WHERE attributeID = ?;";
  result = sqlite3_prepare_v2(db, update_attribute_str, -1, &update_attribute_sql, NULL);
  if(result) {
    return CKR_TOKEN_NOT_PRESENT;
  }

  const char insert_attribute_str[] = "INSERT INTO Attributes (objectID, type, value, length) VALUES (?, ?, ?, ?);";
  result = sqlite3_prepare_v2(db, insert_attribute_str, -1, &insert_attribute_sql, NULL);
  if(result) {
    return CKR_TOKEN_NOT_PRESENT;
  }

  const char update_object_key_str[] = "UPDATE Objects SET encodedKey = ? WHERE objectID = ?;";
  result = sqlite3_prepare_v2(db, update_object_key_str, -1, &update_object_key_sql, NULL);
  if(result) {
    return CKR_TOKEN_NOT_PRESENT;
  }

  return CKR_OK;
}

// Return the label of the token

char* SoftDatabase::getTokenLabel() {
  char *retLabel = NULL_PTR;

  sqlite3_reset(token_info_sql);
  sqlite3_bind_int(token_info_sql, 1, 0);

  if(sqlite3_step(token_info_sql) == SQLITE_ROW) {
    const char *tokenLabel = (const char*)sqlite3_column_text(token_info_sql, 0);
    int labelSize = sizeof(CK_TOKEN_INFO().label);

    retLabel = (char*)malloc(labelSize + 1);
    if(retLabel == NULL_PTR) {
      return NULL_PTR;
    }

    sprintf(retLabel, "%-*.*s", labelSize, labelSize, tokenLabel);
  }

  return retLabel;
}

// Return the hashed SO PIN

char* SoftDatabase::getSOPIN() {
  char *soPIN = NULL_PTR;

  sqlite3_reset(token_info_sql);
  sqlite3_bind_int(token_info_sql, 1, 1);

  if(sqlite3_step(token_info_sql) == SQLITE_ROW) {
    soPIN = strdup((const char*)sqlite3_column_text(token_info_sql, 0));
  }

  return soPIN;
}

// Return the hashed user PIN

char* SoftDatabase::getUserPIN() {
  char *userPIN = NULL_PTR;

  sqlite3_reset(token_info_sql);
  sqlite3_bind_int(token_info_sql, 1, 2);

  if(sqlite3_step(token_info_sql) == SQLITE_ROW) {
    userPIN = strdup((const char*)sqlite3_column_text(token_info_sql, 0));
  }

  return userPIN;
}

// Save the public RSA key in the database.

CK_OBJECT_HANDLE SoftDatabase::addRSAKeyPub(RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
    CK_ULONG ulPublicKeyAttributeCount) {

  stringstream sqlInsertObj;

  sqlInsertObj << "INSERT INTO Objects (encodedKey) VALUES ('" << X509::PEM_encode(*rsaKey) << "');";
  int result = sqlite3_exec(db, sqlInsertObj.str().c_str(), NULL, NULL, NULL);

  if(result) {
    return 0;
  }

  CK_OBJECT_HANDLE objectID = sqlite3_last_insert_rowid(db);

  CK_OBJECT_CLASS oClass = CKO_PUBLIC_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_MECHANISM_TYPE mechType = CKM_RSA_PKCS_KEY_PAIR_GEN;
  CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
  CK_DATE emptyDate;

  // General information
  this->saveAttribute(objectID, CKA_CLASS, &oClass, sizeof(oClass));
  this->saveAttribute(objectID, CKA_KEY_TYPE, &keyType, sizeof(keyType));
  this->saveAttribute(objectID, CKA_KEY_GEN_MECHANISM, &mechType, sizeof(mechType));
  this->saveAttribute(objectID, CKA_LOCAL, &ckTrue, sizeof(ckTrue));

  // Default values, may be changed by the template.
  this->saveAttribute(objectID, CKA_LABEL, NULL_PTR, 0);
  this->saveAttribute(objectID, CKA_ID, NULL_PTR, 0);
  this->saveAttribute(objectID, CKA_SUBJECT, NULL_PTR, 0);
  this->saveAttribute(objectID, CKA_PRIVATE, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_MODIFIABLE, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_TOKEN, &ckFalse, sizeof(ckFalse));
  this->saveAttribute(objectID, CKA_DERIVE, &ckFalse, sizeof(ckFalse));
  this->saveAttribute(objectID, CKA_ENCRYPT, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_VERIFY, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_VERIFY_RECOVER, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_WRAP, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_START_DATE, &emptyDate, 0);
  this->saveAttribute(objectID, CKA_END_DATE, &emptyDate, 0);

  // Extract the attributes from the template
  for(CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch(pPublicKeyTemplate[i].type) {
      // Byte array
      case CKA_LABEL:
      case CKA_ID:
      case CKA_SUBJECT:
        this->saveAttribute(objectID, pPublicKeyTemplate[i].type, pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
        break;
      // Bool
      case CKA_DERIVE:
      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_MODIFIABLE:
      case CKA_ENCRYPT:
      case CKA_VERIFY:
      case CKA_VERIFY_RECOVER:
      case CKA_WRAP:
      case CKA_TRUSTED:
        if(pPublicKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          this->saveAttribute(objectID, pPublicKeyTemplate[i].type, pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
        }
        break;
      // Date
      case CKA_START_DATE:
      case CKA_END_DATE:
        if(pPublicKeyTemplate[i].ulValueLen == sizeof(CK_DATE) ||
           pPublicKeyTemplate[i].ulValueLen == 0) {
          this->saveAttribute(objectID, pPublicKeyTemplate[i].type, pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
        }
        break;
      default:
        break;
    }
  }

  return objectID;
}

// Save the private RSA key in the database.

CK_OBJECT_HANDLE SoftDatabase::addRSAKeyPriv(char *pin, RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
    CK_ULONG ulPrivateKeyAttributeCount, RandomNumberGenerator *rng) {

  stringstream sqlInsertObj;

  sqlInsertObj << "INSERT INTO Objects (encodedKey) VALUES ('');";
  int result = sqlite3_exec(db, sqlInsertObj.str().c_str(), NULL, NULL, NULL);

  if(result) {
    return 0;
  }

  CK_OBJECT_HANDLE objectID = sqlite3_last_insert_rowid(db);

  CK_OBJECT_CLASS oClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_MECHANISM_TYPE mechType = CKM_RSA_PKCS_KEY_PAIR_GEN;
  CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
  CK_DATE emptyDate;

  // General information
  this->saveAttribute(objectID, CKA_CLASS, &oClass, sizeof(oClass));
  this->saveAttribute(objectID, CKA_KEY_TYPE, &keyType, sizeof(keyType));
  this->saveAttribute(objectID, CKA_KEY_GEN_MECHANISM, &mechType, sizeof(mechType));
  this->saveAttribute(objectID, CKA_LOCAL, &ckTrue, sizeof(ckTrue));

  // Default values, may be changed by the template.
  this->saveAttribute(objectID, CKA_LABEL, NULL_PTR, 0);
  this->saveAttribute(objectID, CKA_ID, NULL_PTR, 0);
  this->saveAttribute(objectID, CKA_SUBJECT, NULL_PTR, 0);
  this->saveAttribute(objectID, CKA_PRIVATE, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_MODIFIABLE, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_TOKEN, &ckFalse, sizeof(ckFalse));
  this->saveAttribute(objectID, CKA_DERIVE, &ckFalse, sizeof(ckFalse));
  this->saveAttribute(objectID, CKA_WRAP_WITH_TRUSTED, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_ALWAYS_AUTHENTICATE, &ckFalse, sizeof(ckFalse));
  this->saveAttribute(objectID, CKA_SENSITIVE, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_ALWAYS_SENSITIVE, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_DECRYPT, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_SIGN, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_SIGN_RECOVER, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_UNWRAP, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse));
  this->saveAttribute(objectID, CKA_NEVER_EXTRACTABLE, &ckTrue, sizeof(ckTrue));
  this->saveAttribute(objectID, CKA_START_DATE, &emptyDate, 0);
  this->saveAttribute(objectID, CKA_END_DATE, &emptyDate, 0);

  CK_BBOOL bolVal;
  CK_BBOOL isPrivate = CK_TRUE;
  CK_BBOOL isToken = CK_FALSE;

  // Extract the attributes
  for(CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
    switch(pPrivateKeyTemplate[i].type) {
      // Byte array
      case CKA_LABEL:
      case CKA_ID:
      case CKA_SUBJECT:
        this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
        break;
      // Bool
      case CKA_DERIVE:
      case CKA_MODIFIABLE:
      case CKA_DECRYPT:
      case CKA_SIGN:
      case CKA_SIGN_RECOVER:
      case CKA_UNWRAP:
      case CKA_WRAP_WITH_TRUSTED:
      case CKA_ALWAYS_AUTHENTICATE:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
        }
        break;
      case CKA_TOKEN:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
          isToken = *(CK_BBOOL*)pPrivateKeyTemplate[i].pValue;
        }
        break;
      case CKA_PRIVATE:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
          isPrivate = *(CK_BBOOL*)pPrivateKeyTemplate[i].pValue;
        }
        break;
      // Date
      case CKA_START_DATE:
      case CKA_END_DATE:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_DATE) ||
           pPrivateKeyTemplate[i].ulValueLen == 0) {
          this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
        }
        break;
      case CKA_SENSITIVE:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          this->saveAttribute(objectID, CKA_SENSITIVE, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
          this->saveAttribute(objectID, CKA_ALWAYS_SENSITIVE, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
        }
        break;
      case CKA_EXTRACTABLE:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          this->saveAttribute(objectID, CKA_EXTRACTABLE, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
          if(*(CK_BBOOL*)pPrivateKeyTemplate[i].pValue == CK_FALSE) {
            bolVal = CK_TRUE;
          } else {
            bolVal = CK_FALSE;
          } 
          this->saveAttribute(objectID, CKA_NEVER_EXTRACTABLE, &bolVal, sizeof(bolVal));
        }
        break;
      default:
        break;
    }
  }

  sqlite3_reset(update_object_key_sql);
  if(isPrivate == CK_TRUE && isToken == CK_TRUE) {
    string pemKey = PKCS8::PEM_encode(*rsaKey, *rng, pin);
    sqlite3_bind_text(update_object_key_sql, 1, pemKey.c_str(), -1, SQLITE_TRANSIENT);
  } else {
    string pemKey = PKCS8::PEM_encode(*rsaKey);
    sqlite3_bind_text(update_object_key_sql, 1, pemKey.c_str(), -1, SQLITE_TRANSIENT);
  }
  sqlite3_bind_int(update_object_key_sql, 2, objectID);
  sqlite3_step(update_object_key_sql);

  return objectID;
}

// Save the attribute in the database.
// Only update if the attribute exists.

void SoftDatabase::saveAttribute(CK_OBJECT_HANDLE objectID, CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG ulValueLen) {
  sqlite3_reset(token_info_sql);
  sqlite3_bind_int(token_info_sql, 1, objectID);
  sqlite3_bind_int(token_info_sql, 2, type);

  // The object have this attribute
  if(sqlite3_step(token_info_sql) == SQLITE_ROW) {
    int attributeID = sqlite3_column_int(token_info_sql, 0);

    sqlite3_reset(update_attribute_sql);
    sqlite3_bind_blob(update_attribute_sql, 1, pValue, ulValueLen, SQLITE_TRANSIENT);
    sqlite3_bind_int(update_attribute_sql, 2, ulValueLen);
    sqlite3_bind_int(update_attribute_sql, 3, attributeID);

    sqlite3_step(update_attribute_sql);
  // The object does not have this attribute
  } else {
    sqlite3_reset(insert_attribute_sql);
    sqlite3_bind_int(insert_attribute_sql, 1, objectID);
    sqlite3_bind_int(insert_attribute_sql, 2, type);
    sqlite3_bind_blob(insert_attribute_sql, 3, pValue, ulValueLen, SQLITE_TRANSIENT);
    sqlite3_bind_int(insert_attribute_sql, 4, ulValueLen);

    sqlite3_step(insert_attribute_sql);
  }
}

// Convert the big integer and save it in the database.

void SoftDatabase::saveAttributeBigInt(CK_OBJECT_HANDLE objectID, CK_ATTRIBUTE_TYPE type, BigInt *bigNumber) {
  CK_ULONG size = bigNumber->bytes();
  CK_VOID_PTR buf = (CK_VOID_PTR)malloc(size);
  
  bigNumber->binary_encode((byte *)buf);

  this->saveAttribute(objectID, type, buf, size);
  free(buf);
}

// Read in all the objects from the database

SoftObject* SoftDatabase::readAllObjects() {
  // Get all the objects
  string sqlSelect = "SELECT objectID FROM Objects;";
  sqlite3_stmt *select_sql;
  int result = sqlite3_prepare_v2(db, sqlSelect.c_str(), sqlSelect.size(), &select_sql, NULL);

  // Error?
  if(result != 0) {
    sqlite3_finalize(select_sql);

    return NULL_PTR;
  }

  SoftObject *objects = new SoftObject();

  // Get the results
  while(sqlite3_step(select_sql) == SQLITE_ROW) {
    SoftObject *newObject = populateObj(sqlite3_column_int(select_sql, 0));

    if(newObject != NULL_PTR) {
      // Add the object to the chain
      newObject->nextObject = objects;
      objects = newObject;
    }
  }

  sqlite3_finalize(select_sql);

  return objects;
}

// Creates an object an populate it with attributes from the database.

SoftObject* SoftDatabase::populateObj(CK_OBJECT_HANDLE keyRef) {
  stringstream sqlKey;
  sqlKey << "SELECT encodedKey from Objects WHERE objectID = " << keyRef << ";";

  string sqlKeyStr = sqlKey.str();
  sqlite3_stmt *key_sql;
  int result = sqlite3_prepare(db, sqlKeyStr.c_str(), sqlKeyStr.size(), &key_sql, NULL);

  if(result) {
    sqlite3_finalize(key_sql);

    return NULL_PTR;
  }

  SoftObject *keyObject = new SoftObject();
  keyObject->index = keyRef;

  if(sqlite3_step(key_sql) == SQLITE_ROW) {
    // Add the encoded key
    const char *encKey = (const char*)sqlite3_column_text(key_sql, 0);
    int length = strlen(encKey);
    keyObject->encodedKey = (char*)malloc(length + 1);
    keyObject->encodedKey[length] = '\0';
    memcpy(keyObject->encodedKey, encKey, length);
  } else {
    delete keyObject;
    sqlite3_finalize(key_sql);

    return NULL_PTR;
  }

  sqlite3_finalize(key_sql);
  stringstream sqlQuery;
  sqlQuery << "SELECT type,value,length from Attributes WHERE objectID = " << keyRef << ";";

  string sqlQueryStr = sqlQuery.str();
  sqlite3_stmt *select_sql;
  result = sqlite3_prepare(db, sqlQueryStr.c_str(), sqlQueryStr.size(), &select_sql, NULL);

  if(result) {
    delete keyObject;
    sqlite3_finalize(select_sql);

    return NULL_PTR;
  }

  CK_ULONG tmpValue;

  // Add all attributes
  while(sqlite3_step(select_sql) == SQLITE_ROW) {
    CK_ATTRIBUTE_TYPE type = sqlite3_column_int(select_sql, 0);
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_sql, 1);
    CK_ULONG length = sqlite3_column_int(select_sql, 2);

    keyObject->addAttributeFromData(type, pValue, length);

    switch(type) {
      case CKA_CLASS:
        keyObject->objectClass = *(CK_OBJECT_CLASS *)pValue;
        break;
      case CKA_PRIVATE:
        keyObject->isPrivate = *(CK_BBOOL *)pValue;
        break;
      case CKA_TOKEN:
        keyObject->isToken = *(CK_BBOOL *)pValue;
        break;
      case CKA_KEY_TYPE:
        keyObject->keyType = *(CK_KEY_TYPE *)pValue;
        break;
      case CKA_SENSITIVE:
        keyObject->sensible = *(CK_BBOOL *)pValue;
        break;
      case CKA_EXTRACTABLE:
        keyObject->extractable = *(CK_BBOOL *)pValue;
        break;
      case CKA_MODIFIABLE:
        keyObject->modifiable = *(CK_BBOOL *)pValue;
        break;
      default:
        break;
    }
  }

  sqlite3_finalize(select_sql);

  return keyObject;
}

// Delete an object and its attributes, if the PIN is correct.
// The trigger in the database removes the attributes.

void SoftDatabase::deleteObject(CK_OBJECT_HANDLE objRef) {
  stringstream sqlDeleteObj;

  sqlDeleteObj << "DELETE FROM Objects WHERE objectID = " << objRef << ";";
  sqlite3_exec(db, sqlDeleteObj.str().c_str(),  NULL, NULL, NULL);
}
