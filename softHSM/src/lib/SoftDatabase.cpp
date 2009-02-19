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
}

SoftDatabase::~SoftDatabase() {
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

  return CKR_OK;
}

// Return the label of the token

char* SoftDatabase::getTokenLabel() {
  // Get all the objects
  string sqlSelect = "SELECT value FROM Token where variableID = 0;";
  sqlite3_stmt *select_sql;
  int result = sqlite3_prepare_v2(db, sqlSelect.c_str(), sqlSelect.size(), &select_sql, NULL);

  char *retLabel = (char*)malloc(33);
  memset(retLabel, ' ', 32);
  retLabel[32] = '\0';

  // Error?
  if(result != 0) {
    sqlite3_finalize(select_sql);

    return retLabel;
  }

  if(sqlite3_step(select_sql) == SQLITE_ROW) {
    const char *tokenLabel = (const char*)sqlite3_column_text(select_sql, 0);
    strncpy(retLabel, tokenLabel, 32);
  }

  sqlite3_finalize(select_sql);

  return retLabel;
}

// Return the hashed SO PIN

char* SoftDatabase::getSOPIN() {
  // Get all the objects
  string sqlSelect = "SELECT value FROM Token where variableID = 1;";
  sqlite3_stmt *select_sql;
  int result = sqlite3_prepare_v2(db, sqlSelect.c_str(), sqlSelect.size(), &select_sql, NULL);

  char *soPIN = NULL_PTR;

  // Error?
  if(result != 0) {
    sqlite3_finalize(select_sql);

    return soPIN;
  }


  if(sqlite3_step(select_sql) == SQLITE_ROW) {
    const char *hashedSOPIN = (const char*)sqlite3_column_text(select_sql, 0);
    int length = strlen(hashedSOPIN);
    soPIN = (char *)malloc(length + 1);
    soPIN[length] = '\0';
    memcpy(soPIN, hashedSOPIN, length);
  }

  sqlite3_finalize(select_sql);

  return soPIN;
}

// Return the hashed user PIN

char* SoftDatabase::getUserPIN() {
  // Get all the objects
  string sqlSelect = "SELECT value FROM Token where variableID = 2;";
  sqlite3_stmt *select_sql;
  int result = sqlite3_prepare_v2(db, sqlSelect.c_str(), sqlSelect.size(), &select_sql, NULL);

  char *userPIN = NULL_PTR;

  // Error?
  if(result != 0) {
    sqlite3_finalize(select_sql);

    return userPIN;
  }


  if(sqlite3_step(select_sql) == SQLITE_ROW) {
    const char *hashedUserPIN = (const char*)sqlite3_column_text(select_sql, 0);
    int length = strlen(hashedUserPIN);
    userPIN = (char *)malloc(length + 1);
    userPIN[length] = '\0';
    memcpy(userPIN, hashedUserPIN, length);
  }

  sqlite3_finalize(select_sql);

  return userPIN;
}

// Save the public RSA key in the database.

CK_OBJECT_HANDLE SoftDatabase::addRSAKeyPub(RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
    CK_ULONG ulPublicKeyAttributeCount, char *labelID) {

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
  this->saveAttribute(objectID, CKA_LABEL, labelID, strlen(labelID));
  this->saveAttribute(objectID, CKA_ID, labelID, strlen(labelID));
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
    CK_ULONG ulPrivateKeyAttributeCount, char *labelID, RandomNumberGenerator *rng) {

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
  this->saveAttribute(objectID, CKA_LABEL, labelID, strlen(labelID));
  this->saveAttribute(objectID, CKA_ID, labelID, strlen(labelID));
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

  if(isPrivate == CK_TRUE && isToken == CK_TRUE) {
    stringstream sqlUpdateObj;

    sqlUpdateObj << "UPDATE Objects SET encodedKey = '" << PKCS8::PEM_encode(*rsaKey, *rng, pin) << "' WHERE objectID = " << objectID << ";";
    sqlite3_exec(db, sqlUpdateObj.str().c_str(), NULL, NULL, NULL);
  } else {
    stringstream sqlUpdateObj;

    sqlUpdateObj << "UPDATE Objects SET encodedKey = '" << PKCS8::PEM_encode(*rsaKey)  << "' WHERE objectID = " << objectID << ";";
    sqlite3_exec(db, sqlUpdateObj.str().c_str(), NULL, NULL, NULL);
  }

  return objectID;
}

// Save the attribute in the database.
// Only update if the attribute exists.

void SoftDatabase::saveAttribute(CK_OBJECT_HANDLE objectID, CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG ulValueLen) {
  string sqlFind = "SELECT attributeID FROM Attributes WHERE objectID = ? AND type = ?;";

  sqlite3_stmt *find_sql;
  int result = sqlite3_prepare_v2(db, sqlFind.c_str(), sqlFind.size(), &find_sql, NULL);

  if(result) {
    sqlite3_finalize(find_sql);

    return;
  }

  sqlite3_bind_int(find_sql, 1, objectID);
  sqlite3_bind_int(find_sql, 2, type);

  // The object have this attribute
  if(sqlite3_step(find_sql) == SQLITE_ROW) {
    int attributeID = sqlite3_column_int(find_sql, 0);

    string sqlUpdate = "UPDATE Attributes SET value = ?, length = ? WHERE attributeID = ?;";

    sqlite3_stmt *update_sql;
    result = sqlite3_prepare_v2(db, sqlUpdate.c_str(), sqlUpdate.size(), &update_sql, NULL);

    if(result) {
      sqlite3_finalize(find_sql);
      sqlite3_finalize(update_sql);

      return;
    }

    sqlite3_bind_blob(update_sql, 1, pValue, ulValueLen, SQLITE_TRANSIENT);
    sqlite3_bind_int(update_sql, 2, ulValueLen);
    sqlite3_bind_int(update_sql, 3, attributeID);

    sqlite3_step(update_sql);
    sqlite3_finalize(update_sql);
  // The object does not have this attribute
  } else {
    string sqlInsert = "INSERT INTO Attributes (objectID, type, value, length) VALUES (?, ?, ?, ?);";

    sqlite3_stmt *insert_sql;
    result = sqlite3_prepare_v2(db, sqlInsert.c_str(), sqlInsert.size(), &insert_sql, NULL);

    if(result) {
      sqlite3_finalize(find_sql);
      sqlite3_finalize(insert_sql);

      return;
    }

    sqlite3_bind_int(insert_sql, 1, objectID);
    sqlite3_bind_int(insert_sql, 2, type);
    sqlite3_bind_blob(insert_sql, 3, pValue, ulValueLen, SQLITE_TRANSIENT);
    sqlite3_bind_int(insert_sql, 4, ulValueLen);

    sqlite3_step(insert_sql);
    sqlite3_finalize(insert_sql);
  }

  sqlite3_finalize(find_sql);
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
  string sqlSelect = "SELECT * FROM Objects;";
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

      // Add the encoded key
      const char *encKey = (const char*)sqlite3_column_text(select_sql, 1);
      int length = strlen(encKey);
      objects->encodedKey = (char*)malloc(length + 1);
      objects->encodedKey[length] = '\0';
      memcpy(objects->encodedKey, encKey, length);
    }
  }

  sqlite3_finalize(select_sql);

  return objects;
}

// Creates an object an populate it with attributes from the database.

SoftObject* SoftDatabase::populateObj(CK_OBJECT_HANDLE keyRef) {
  stringstream sqlQuery;
  sqlQuery << "SELECT type,value,length from Attributes WHERE objectID = " << keyRef << ";";

  string sqlQueryStr = sqlQuery.str();
  sqlite3_stmt *select_sql;
  int result = sqlite3_prepare(db, sqlQueryStr.c_str(), sqlQueryStr.size(), &select_sql, NULL);

  if(result) {
    sqlite3_finalize(select_sql);

    return NULL_PTR;
  }

  SoftObject* keyObject = new SoftObject();
  keyObject->index = keyRef;

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
