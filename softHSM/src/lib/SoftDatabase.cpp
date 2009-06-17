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
#include <stdlib.h>

// Rollback the object if it can't be saved
#define CHECK_DB_RESPONSE(stmt) \
  if(stmt) { \
    while(sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_BUSY); \
    return 0; \
  }

// Prepare the SQL statement
#define PREP_STMT(str, sql) \
  if(sqlite3_prepare_v2(db, str, -1, sql, NULL)) { \
    return CKR_TOKEN_NOT_PRESENT; \
  }

// Finalize the prepared statement
#define FINALIZE_STMT(prep) \
  if(prep != NULL) { \
    sqlite3_finalize(prep); \
  }


SoftDatabase::SoftDatabase() {
  db = NULL_PTR;
  token_info_sql = NULL;
  insert_token_info_sql = NULL;
  select_attri_id_sql = NULL;
  update_attribute_sql = NULL;
  insert_attribute_sql = NULL;
  insert_object_sql = NULL;
  select_object_ids_sql = NULL;
  select_object_id_sql = NULL;
  select_attribute_sql = NULL;
  select_session_obj_sql = NULL;
  delete_object_sql = NULL;
  count_object_id_sql = NULL;
  select_an_attribute_sql = NULL;
}

SoftDatabase::~SoftDatabase() {
  // Would be nice to use this:
  //
  //   sqlite3_stmt *pStmt;
  //   while((pStmt = sqlite3_next_stmt(db, 0)) != 0 ) {
  //    sqlite3_finalize(pStmt);
  //   }
  //
  // But requires SQLite3 >= 3.6.0 beta

  FINALIZE_STMT(token_info_sql);
  FINALIZE_STMT(insert_token_info_sql);
  FINALIZE_STMT(select_attri_id_sql);
  FINALIZE_STMT(update_attribute_sql);
  FINALIZE_STMT(insert_attribute_sql);
  FINALIZE_STMT(insert_object_sql);
  FINALIZE_STMT(select_object_ids_sql);
  FINALIZE_STMT(select_object_id_sql);
  FINALIZE_STMT(select_attribute_sql);
  FINALIZE_STMT(select_session_obj_sql);
  FINALIZE_STMT(delete_object_sql);
  FINALIZE_STMT(count_object_id_sql);
  FINALIZE_STMT(select_an_attribute_sql);

  if(db != NULL_PTR) {
    sqlite3_close(db);
  }
}

CK_RV SoftDatabase::init(char *dbPath) {
  // Open the database
  int result = sqlite3_open(dbPath, &db);
  if(result){
    return CKR_TOKEN_NOT_PRESENT;
  }

  // Check the schema version
  sqlite3_stmt *pragStatem = NULL;
  PREP_STMT("PRAGMA user_version;", &pragStatem);
  if(sqlite3_step(pragStatem) == SQLITE_ROW) {
    int dbVersion = sqlite3_column_int(pragStatem, 0);
    FINALIZE_STMT(pragStatem);

    if(dbVersion != 100) {
      return CKR_TOKEN_NOT_RECOGNIZED;
    }
  } else {
    FINALIZE_STMT(pragStatem);
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  // Check that the Token table exist
  result = sqlite3_exec(db, "SELECT COUNT(variableID) FROM Token;", NULL, NULL, NULL);
  if(result) {
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  // Check that the Objects table exist
  result = sqlite3_exec(db, "SELECT COUNT(objectID) FROM Objects;", NULL, NULL, NULL);
  if(result) {
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  // Check that the Attributes table exist
  result = sqlite3_exec(db, "SELECT COUNT(attributeID) FROM Attributes;", NULL, NULL, NULL);
  if(result) {
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  // Create prepared statements
  const char token_info_str[] =			"SELECT value FROM Token where variableID = ?;";
  const char insert_token_info_str[] =		"INSERT OR REPLACE INTO Token (variableID, value) VALUES (?, ?);";
  const char select_attri_id_str[] =		"SELECT attributeID FROM Attributes WHERE objectID = ? AND type = ?;";
  const char update_attribute_str[] =		"UPDATE Attributes SET value = ?, length = ? WHERE attributeID = ?;";
  const char insert_attribute_str[] =		"INSERT INTO Attributes (objectID, type, value, length) VALUES (?, ?, ?, ?);";
  const char insert_object_str[] =		"INSERT INTO Objects DEFAULT VALUES;";
  const char select_object_ids_str[] =		"SELECT objectID FROM Objects;";
  const char select_object_id_str[] =		"SELECT objectID FROM Objects WHERE objectID = ?;";
  const char select_attribute_str[] =		"SELECT type,value,length from Attributes WHERE objectID = ?;";
  const char select_session_obj_str[] =		"SELECT objectID FROM Attributes WHERE type = ? AND value = ? AND objectID IN (SELECT objectID FROM Attributes WHERE type = ? AND value = ?);";
  const char delete_object_str[] =		"DELETE FROM Objects WHERE objectID = ?;";
  const char count_object_id_str[] =		"SELECT COUNT(objectID) FROM Objects;";
  const char select_an_attribute_str[] =	"SELECT value,length FROM Attributes WHERE objectID = ? AND type = ?;";

  PREP_STMT(token_info_str, &token_info_sql);
  PREP_STMT(insert_token_info_str, &insert_token_info_sql);
  PREP_STMT(select_attri_id_str, &select_attri_id_sql);
  PREP_STMT(update_attribute_str, &update_attribute_sql);
  PREP_STMT(insert_attribute_str, &insert_attribute_sql);
  PREP_STMT(insert_object_str, &insert_object_sql);
  PREP_STMT(select_object_ids_str, &select_object_ids_sql);
  PREP_STMT(select_object_id_str, &select_object_id_sql);
  PREP_STMT(select_attribute_str, &select_attribute_sql);
  PREP_STMT(select_session_obj_str, &select_session_obj_sql);
  PREP_STMT(delete_object_str, &delete_object_sql);
  PREP_STMT(count_object_id_str, &count_object_id_sql);
  PREP_STMT(select_an_attribute_str, &select_an_attribute_sql);

  return CKR_OK;
}

// Return the label of the token

char* SoftDatabase::getTokenLabel() {
  char *retLabel = NULL_PTR;

  sqlite3_bind_int(token_info_sql, 1, DB_TOKEN_LABEL);

  if(sqlite3_step(token_info_sql) == SQLITE_ROW) {
    const char *tokenLabel = (const char*)sqlite3_column_text(token_info_sql, 0);
    int labelSize = sizeof(CK_TOKEN_INFO().label);

    retLabel = (char*)malloc(labelSize + 1);
    if(retLabel != NULL_PTR) {
      sprintf(retLabel, "%-*.*s", labelSize, labelSize, tokenLabel);
    }
  }

  sqlite3_reset(token_info_sql);

  return retLabel;
}

// Return the hashed SO PIN

char* SoftDatabase::getSOPIN() {
  char *soPIN = NULL_PTR;

  sqlite3_bind_int(token_info_sql, 1, DB_TOKEN_SOPIN);

  if(sqlite3_step(token_info_sql) == SQLITE_ROW) {
    soPIN = strdup((const char*)sqlite3_column_text(token_info_sql, 0));
  }

  sqlite3_reset(token_info_sql);

  return soPIN;
}

// Return the hashed user PIN

char* SoftDatabase::getUserPIN() {
  char *userPIN = NULL_PTR;

  sqlite3_bind_int(token_info_sql, 1, DB_TOKEN_USERPIN);

  if(sqlite3_step(token_info_sql) == SQLITE_ROW) {
    userPIN = strdup((const char*)sqlite3_column_text(token_info_sql, 0));
  }

  sqlite3_reset(token_info_sql);

  return userPIN;
}

// Save/update the token info

CK_RV SoftDatabase::saveTokenInfo(int valueID, char *value, int length) {
  sqlite3_bind_int(insert_token_info_sql, 1, valueID);
  sqlite3_bind_text(insert_token_info_sql, 2, value, length, SQLITE_TRANSIENT);

  int result = sqlite3_step(insert_token_info_sql);
  sqlite3_reset(insert_token_info_sql);

  if(result != SQLITE_DONE) {
    return CKR_DEVICE_ERROR;
  }

  return CKR_OK;
}

// Save the public RSA key in the database.
// Makes sure that object is saved with all its attributes.
// If some error occur when saving the data, nothing is saved.

CK_OBJECT_HANDLE SoftDatabase::addRSAKeyPub(RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
    CK_ULONG ulPublicKeyAttributeCount) {

  // Begin the transaction
  int retVal = 0;
  while((retVal = sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL)) == SQLITE_BUSY) {}
  if(retVal != SQLITE_OK) {
    return 0;
  }

  CHECK_DB_RESPONSE(sqlite3_step(insert_object_sql) != SQLITE_DONE);
  CK_OBJECT_HANDLE objectID = sqlite3_last_insert_rowid(db);
  sqlite3_reset(insert_object_sql);

  CK_OBJECT_CLASS oClass = CKO_PUBLIC_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_MECHANISM_TYPE mechType = CKM_RSA_PKCS_KEY_PAIR_GEN;
  CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
  CK_DATE emptyDate;

  // Created by db handle. So we can remove the correct session objects in the future.
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_VENDOR_DEFINED, &db, sizeof(db)) != CKR_OK);

  // General information
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_CLASS, &oClass, sizeof(oClass)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_KEY_TYPE, &keyType, sizeof(keyType)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_KEY_GEN_MECHANISM, &mechType, sizeof(mechType)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_LOCAL, &ckTrue, sizeof(ckTrue)) != CKR_OK);

  // Default values, may be changed by the template.
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_LABEL, NULL_PTR, 0) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_ID, NULL_PTR, 0) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_SUBJECT, NULL_PTR, 0) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_PRIVATE, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_MODIFIABLE, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_TOKEN, &ckFalse, sizeof(ckFalse)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_DERIVE, &ckFalse, sizeof(ckFalse)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_ENCRYPT, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_VERIFY, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_VERIFY_RECOVER, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_WRAP, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_START_DATE, &emptyDate, 0) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_END_DATE, &emptyDate, 0) != CKR_OK);

  // The RSA modulus bits
  IF_Scheme_PublicKey *ifKey = dynamic_cast<IF_Scheme_PublicKey*>(rsaKey);
  BigInt bigModulus = ifKey->get_n();
  CK_ULONG bits = bigModulus.bits();
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_MODULUS_BITS, &bits, sizeof(bits)) != CKR_OK);

  // The RSA modulus
  CHECK_DB_RESPONSE(this->saveAttributeBigInt(objectID, CKA_MODULUS, &bigModulus) != CKR_OK);

  // The RSA public exponent
  BigInt bigExponent = ifKey->get_e();
  CHECK_DB_RESPONSE(this->saveAttributeBigInt(objectID, CKA_PUBLIC_EXPONENT, &bigExponent) != CKR_OK);

  // Extract the attributes from the template
  for(CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch(pPublicKeyTemplate[i].type) {
      // Byte array
      case CKA_LABEL:
      case CKA_ID:
      case CKA_SUBJECT:
        CHECK_DB_RESPONSE(this->saveAttribute(objectID, pPublicKeyTemplate[i].type, pPublicKeyTemplate[i].pValue, 
                          pPublicKeyTemplate[i].ulValueLen) != CKR_OK);
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
          CHECK_DB_RESPONSE(this->saveAttribute(objectID, pPublicKeyTemplate[i].type, pPublicKeyTemplate[i].pValue, 
                            pPublicKeyTemplate[i].ulValueLen) != CKR_OK);
        }
        break;
      // Date
      case CKA_START_DATE:
      case CKA_END_DATE:
        if(pPublicKeyTemplate[i].ulValueLen == sizeof(CK_DATE) ||
           pPublicKeyTemplate[i].ulValueLen == 0) {
          CHECK_DB_RESPONSE(this->saveAttribute(objectID, pPublicKeyTemplate[i].type, pPublicKeyTemplate[i].pValue, 
                            pPublicKeyTemplate[i].ulValueLen) != CKR_OK);
        }
        break;
      default:
        break;
    }
  }

  while(sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) == SQLITE_BUSY) {}

  return objectID;
}

// Save the private RSA key in the database.
// Makes sure that object is saved with all its attributes.
// If some error occur when saving the data, nothing is saved.

CK_OBJECT_HANDLE SoftDatabase::addRSAKeyPriv(RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
    CK_ULONG ulPrivateKeyAttributeCount) {

  // Begin the transaction
  int retVal = 0;
  while((retVal = sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL)) == SQLITE_BUSY) {}
  if(retVal != SQLITE_OK) {
    return 0;
  }

  CHECK_DB_RESPONSE(sqlite3_step(insert_object_sql) != SQLITE_DONE);
  CK_OBJECT_HANDLE objectID = sqlite3_last_insert_rowid(db);
  sqlite3_reset(insert_object_sql);

  CK_OBJECT_CLASS oClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_MECHANISM_TYPE mechType = CKM_RSA_PKCS_KEY_PAIR_GEN;
  CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
  CK_DATE emptyDate;

  // Created by db handle. So we can remove the correct session objects in the future.
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_VENDOR_DEFINED, &db, sizeof(db)) != CKR_OK);

  // General information
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_CLASS, &oClass, sizeof(oClass)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_KEY_TYPE, &keyType, sizeof(keyType)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_KEY_GEN_MECHANISM, &mechType, sizeof(mechType)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_LOCAL, &ckTrue, sizeof(ckTrue)) != CKR_OK);

  // Default values, may be changed by the template.
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_LABEL, NULL_PTR, 0) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_ID, NULL_PTR, 0) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_SUBJECT, NULL_PTR, 0) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_PRIVATE, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_MODIFIABLE, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_TOKEN, &ckFalse, sizeof(ckFalse)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_DERIVE, &ckFalse, sizeof(ckFalse)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_WRAP_WITH_TRUSTED, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_ALWAYS_AUTHENTICATE, &ckFalse, sizeof(ckFalse)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_ALWAYS_SENSITIVE, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_DECRYPT, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_SIGN, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_SIGN_RECOVER, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_UNWRAP, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_NEVER_EXTRACTABLE, &ckTrue, sizeof(ckTrue)) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_START_DATE, &emptyDate, 0) != CKR_OK);
  CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_END_DATE, &emptyDate, 0) != CKR_OK);

  // The RSA modulus
  IF_Scheme_PrivateKey *ifKeyPriv = dynamic_cast<IF_Scheme_PrivateKey*>(rsaKey);
  BigInt bigMod = ifKeyPriv->get_n();
  this->saveAttributeBigInt(objectID, CKA_MODULUS, &bigMod);

  // The RSA public exponent
  BigInt bigExp = ifKeyPriv->get_e();
  this->saveAttributeBigInt(objectID, CKA_PUBLIC_EXPONENT, &bigExp);

  // The RSA private exponent
  BigInt bigPrivExp = ifKeyPriv->get_d();
  this->saveAttributeBigInt(objectID, CKA_PRIVATE_EXPONENT, &bigPrivExp);

  // The RSA prime p
  BigInt bigPrime1 = ifKeyPriv->get_p();
  this->saveAttributeBigInt(objectID, CKA_PRIME_1, &bigPrime1);

  // The RSA prime q
  BigInt bigPrime2 = ifKeyPriv->get_q();
  this->saveAttributeBigInt(objectID, CKA_PRIME_2, &bigPrime2);

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
        CHECK_DB_RESPONSE(this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, 
                          pPrivateKeyTemplate[i].ulValueLen) != CKR_OK);
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
          CHECK_DB_RESPONSE(this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, 
                            pPrivateKeyTemplate[i].ulValueLen) != CKR_OK);
        }
        break;
      case CKA_TOKEN:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          CHECK_DB_RESPONSE(this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, 
                            pPrivateKeyTemplate[i].ulValueLen) != CKR_OK);
          isToken = *(CK_BBOOL*)pPrivateKeyTemplate[i].pValue;
        }
        break;
      case CKA_PRIVATE:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          CHECK_DB_RESPONSE(this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, 
                            pPrivateKeyTemplate[i].ulValueLen) != CKR_OK);
          isPrivate = *(CK_BBOOL*)pPrivateKeyTemplate[i].pValue;
        }
        break;
      // Date
      case CKA_START_DATE:
      case CKA_END_DATE:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_DATE) ||
           pPrivateKeyTemplate[i].ulValueLen == 0) {
          CHECK_DB_RESPONSE(this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, 
                            pPrivateKeyTemplate[i].ulValueLen) != CKR_OK);
        }
        break;
      case CKA_SENSITIVE:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_SENSITIVE, pPrivateKeyTemplate[i].pValue, 
                            pPrivateKeyTemplate[i].ulValueLen) != CKR_OK);
          CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_ALWAYS_SENSITIVE, pPrivateKeyTemplate[i].pValue,
                            pPrivateKeyTemplate[i].ulValueLen) != CKR_OK);
        }
        break;
      case CKA_EXTRACTABLE:
        if(pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_EXTRACTABLE, pPrivateKeyTemplate[i].pValue, 
                            pPrivateKeyTemplate[i].ulValueLen) != CKR_OK);
          if(*(CK_BBOOL*)pPrivateKeyTemplate[i].pValue == CK_FALSE) {
            bolVal = CK_TRUE;
          } else {
            bolVal = CK_FALSE;
          } 
          CHECK_DB_RESPONSE(this->saveAttribute(objectID, CKA_NEVER_EXTRACTABLE, &bolVal, sizeof(bolVal)) != CKR_OK);
        }
        break;
      default:
        break;
    }
  }

  while(sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) == SQLITE_BUSY) {}

  return objectID;
}

// Save the attribute in the database.
// Only update if the attribute exists.

CK_RV SoftDatabase::saveAttribute(CK_OBJECT_HANDLE objectID, CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG ulValueLen) {
  sqlite3_bind_int(select_attri_id_sql, 1, objectID);
  sqlite3_bind_int(select_attri_id_sql, 2, type);

  int result = sqlite3_step(select_attri_id_sql);
  int attributeID = sqlite3_column_int(select_attri_id_sql, 0);
  sqlite3_reset(select_attri_id_sql);

  // The object have this attribute
  if(result == SQLITE_ROW) {
    sqlite3_bind_blob(update_attribute_sql, 1, pValue, ulValueLen, SQLITE_TRANSIENT);
    sqlite3_bind_int(update_attribute_sql, 2, ulValueLen);
    sqlite3_bind_int(update_attribute_sql, 3, attributeID);

    result = sqlite3_step(update_attribute_sql);
    sqlite3_reset(update_attribute_sql);

    if(result != SQLITE_DONE) {
      return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
  // The object does not have this attribute
  } else if(result == SQLITE_DONE) {
    sqlite3_bind_int(insert_attribute_sql, 1, objectID);
    sqlite3_bind_int(insert_attribute_sql, 2, type);
    sqlite3_bind_blob(insert_attribute_sql, 3, pValue, ulValueLen, SQLITE_TRANSIENT);
    sqlite3_bind_int(insert_attribute_sql, 4, ulValueLen);

    result = sqlite3_step(insert_attribute_sql);
    sqlite3_reset(insert_attribute_sql);

    if(result != SQLITE_DONE) {
      return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
  } else {
    return CKR_GENERAL_ERROR;
  }
}

// Convert the big integer and save it in the database.

CK_RV SoftDatabase::saveAttributeBigInt(CK_OBJECT_HANDLE objectID, CK_ATTRIBUTE_TYPE type, BigInt *bigNumber) {
  CK_ULONG size = bigNumber->bytes();
  CK_VOID_PTR buf = (CK_VOID_PTR)malloc(size);

  if(buf == NULL_PTR)  {
    return CKR_GENERAL_ERROR;
  }

  bigNumber->binary_encode((byte *)buf);

  CK_RV rv = this->saveAttribute(objectID, type, buf, size);
  free(buf);

  return rv;
}

// Destroy all the session objects created by this database handle

void SoftDatabase::destroySessObj() {
  CK_BBOOL ckFalse = CK_FALSE;

  sqlite3_bind_int(select_session_obj_sql, 1, CKA_TOKEN);
  sqlite3_bind_blob(select_session_obj_sql, 2, &ckFalse, sizeof(ckFalse), SQLITE_TRANSIENT);
  sqlite3_bind_int(select_session_obj_sql, 3, CKA_VENDOR_DEFINED);
  sqlite3_bind_blob(select_session_obj_sql, 4, &db, sizeof(db), SQLITE_TRANSIENT);

  while(sqlite3_step(select_session_obj_sql) == SQLITE_ROW) {
    this->deleteObject(sqlite3_column_int(select_session_obj_sql, 0));
  }

  sqlite3_reset(select_session_obj_sql);
}

// Delete an object and its attributes.
// The trigger in the database removes the attributes.

void SoftDatabase::deleteObject(CK_OBJECT_HANDLE objRef) {
  sqlite3_bind_int(delete_object_sql, 1, objRef);
  while(sqlite3_step(delete_object_sql) == SQLITE_BUSY) {}
  sqlite3_reset(delete_object_sql);
}

// Return the all the object IDs

CK_OBJECT_HANDLE* SoftDatabase::getObjectRefs(CK_ULONG *objectCount) {
  *objectCount = 0;

  // Find out how many objects we have.
  if(sqlite3_step(count_object_id_sql) != SQLITE_ROW) {
    return NULL_PTR;
  }

  // Get the number of objects
  CK_ULONG objectsInDB = sqlite3_column_int(count_object_id_sql, 0);
  sqlite3_reset(count_object_id_sql);

  // Create the object-reference buffer
  CK_OBJECT_HANDLE *objectRefs = (CK_OBJECT_HANDLE *)malloc(objectsInDB * sizeof(CK_OBJECT_HANDLE));
  if(objectRefs == NULL_PTR) {
    return NULL_PTR;
  }

  // Get all the object ids
  CK_ULONG tmpCounter = 0;
  while(sqlite3_step(select_object_ids_sql) == SQLITE_ROW && tmpCounter < objectsInDB) {
    objectRefs[tmpCounter++] = sqlite3_column_int(select_object_ids_sql, 0);
  }

  *objectCount = tmpCounter;
  sqlite3_reset(select_object_ids_sql);
 
  return objectRefs;
}

// Return a boolean attribute of the object

CK_BBOOL SoftDatabase::getBooleanAttribute(CK_OBJECT_HANDLE objectRef, CK_ATTRIBUTE_TYPE type, CK_BBOOL defaultValue) {
  CK_BBOOL retVal = defaultValue;

  sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
  sqlite3_bind_int(select_an_attribute_sql, 2, type);

  // Get attribute
  if(sqlite3_step(select_an_attribute_sql) == SQLITE_ROW) {
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
    CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

    if(pValue != NULL_PTR && length == sizeof(CK_BBOOL)) {
      retVal = *(CK_BBOOL *)pValue;
    } 
  } 

  sqlite3_reset(select_an_attribute_sql);

  return retVal;
}

// Return the class of the object

CK_OBJECT_CLASS SoftDatabase::getObjectClass(CK_OBJECT_HANDLE objectRef) {
  CK_OBJECT_CLASS retVal = CKO_VENDOR_DEFINED;

  sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
  sqlite3_bind_int(select_an_attribute_sql, 2, CKA_CLASS);

  // Get attribute
  if(sqlite3_step(select_an_attribute_sql) == SQLITE_ROW) {
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
    CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

    if(pValue != NULL_PTR && length == sizeof(CK_OBJECT_CLASS)) {
      retVal = *(CK_OBJECT_CLASS *)pValue;
    }
  }

  sqlite3_reset(select_an_attribute_sql);

  return retVal;
}

// Return the key type of the object

CK_KEY_TYPE SoftDatabase::getKeyType(CK_OBJECT_HANDLE objectRef) {
  CK_KEY_TYPE retVal = CKK_VENDOR_DEFINED;

  sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
  sqlite3_bind_int(select_an_attribute_sql, 2, CKA_KEY_TYPE);

  // Get attribute
  if(sqlite3_step(select_an_attribute_sql) == SQLITE_ROW) {
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
    CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

    if(pValue != NULL_PTR && length == sizeof(CK_KEY_TYPE)) {
      retVal = *(CK_KEY_TYPE *)pValue;
    }
  }

  sqlite3_reset(select_an_attribute_sql);

  return retVal;
}

// Returns a big int of a given attribute.
// We reveal anything, because this is used to create a key within the SoftHSM.

BigInt SoftDatabase::getBigIntAttribute(CK_OBJECT_HANDLE objectRef, CK_ATTRIBUTE_TYPE type) {
  BigInt retVal = BigInt(0);

  sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
  sqlite3_bind_int(select_an_attribute_sql, 2, type);

  // Get attribute
  if(sqlite3_step(select_an_attribute_sql) == SQLITE_ROW) {
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
    CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

    if(pValue != NULL_PTR) {
      retVal = BigInt((byte *)pValue, (u32bit)length);
    }
  }

  sqlite3_reset(select_an_attribute_sql);

  return retVal;
}


// Check if the object has an matching attribute

CK_BBOOL SoftDatabase::matchAttribute(CK_OBJECT_HANDLE objectRef, CK_ATTRIBUTE *attTemplate) {
  CK_BBOOL retVal = CK_FALSE;

  sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
  sqlite3_bind_int(select_an_attribute_sql, 2, attTemplate->type);

  // Get attribute
  if(sqlite3_step(select_an_attribute_sql) == SQLITE_ROW) {
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
    CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

    // Match attribute
    if(length == attTemplate->ulValueLen && pValue != NULL_PTR && attTemplate->pValue != NULL_PTR &&
       memcmp(pValue, attTemplate->pValue, length) == 0) {

      retVal = CK_TRUE;
    }
  }

  sqlite3_reset(select_an_attribute_sql);

  return retVal;
}

// Check if the object handle exist in the database

CK_BBOOL SoftDatabase::hasObject(CK_OBJECT_HANDLE objectRef) {
  CK_BBOOL retVal = CK_FALSE;

  sqlite3_reset(select_object_id_sql);
  sqlite3_bind_int(select_object_id_sql, 1, objectRef);

  // Check object id
  if(sqlite3_step(select_object_id_sql) == SQLITE_ROW) {
    retVal = CK_TRUE;
  } 

  sqlite3_reset(select_object_id_sql);

  return retVal;
}

// Get the value of an attribute for this object.

CK_RV SoftDatabase::getAttribute(CK_OBJECT_HANDLE objectRef, CK_ATTRIBUTE *attTemplate) {
  // Can we reveal this attribute?
  switch(attTemplate->type) {
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
      if(this->getBooleanAttribute(objectRef, CKA_SENSITIVE, CK_TRUE) == CK_TRUE || 
         this->getBooleanAttribute(objectRef, CKA_EXTRACTABLE, CK_FALSE) == CK_FALSE) {
        attTemplate->ulValueLen = (CK_LONG)-1;
        return CKR_ATTRIBUTE_SENSITIVE;
      }
      break;
    default:
      break;
  }

  CK_RV retVal = CKR_OK;
  sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
  sqlite3_bind_int(select_an_attribute_sql, 2, attTemplate->type);

  // Get the attribute
  if(sqlite3_step(select_an_attribute_sql) == SQLITE_ROW) {
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
    CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

    // Do the user want the size of the attribute value?
    if(attTemplate->pValue == NULL_PTR) {
      attTemplate->ulValueLen = length;
    // Is the given buffer to small?
    } else if(attTemplate->ulValueLen < length) {
      attTemplate->ulValueLen = (CK_LONG)-1;
      retVal = CKR_BUFFER_TOO_SMALL;
    // Return the attribute
    } else {
      memcpy(attTemplate->pValue, pValue, length);
      attTemplate->ulValueLen = length;
    }
  } else {
    // We do not have this attribute
    attTemplate->ulValueLen = (CK_LONG)-1;
    retVal = CKR_ATTRIBUTE_TYPE_INVALID;
  }

  sqlite3_reset(select_an_attribute_sql);

  return retVal;
}

// Set the value of an attribute for this object.
// This function also performes a sanity check of the template

CK_RV SoftDatabase::setAttribute(CK_OBJECT_HANDLE objectRef, CK_ATTRIBUTE *attTemplate) {
  // Can we modify the object?
  if(this->getBooleanAttribute(objectRef, CKA_MODIFIABLE, CK_FALSE) == CK_FALSE) {
    return CKR_ATTRIBUTE_READ_ONLY;
  }

  // Evaluate the template
  switch(attTemplate->type) {
    case CKA_CLASS:
    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_MODIFIABLE:
    case CKA_KEY_TYPE:
    case CKA_LOCAL:
    case CKA_KEY_GEN_MECHANISM:
      // We can not change this attribute
      return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_LABEL:
    case CKA_ID:
    case CKA_SUBJECT:
      // We can change
      break;
    case CKA_DERIVE:
      // We can change, but check size
      if(attTemplate->ulValueLen != sizeof(CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;
    case CKA_START_DATE:
    case CKA_END_DATE:
      // We can change, but check size
      if(attTemplate->ulValueLen == sizeof(CK_DATE) ||
         attTemplate->ulValueLen == 0) {
        break;
      }
      return CKR_ATTRIBUTE_VALUE_INVALID;
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
    case CKA_WRAP:
      // We can change this for the public key
      // but invalid for other object classes
      if(this->getObjectClass(objectRef) != CKO_PUBLIC_KEY) {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      // Check size
      if(attTemplate->ulValueLen != sizeof(CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;
    case CKA_TRUSTED:
      // We can not set this for the public key
      if(this->getObjectClass(objectRef) == CKO_PUBLIC_KEY) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Invalid for other object classes
      return CKR_ATTRIBUTE_TYPE_INVALID;
    case CKA_DECRYPT:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_UNWRAP:
      // We can change this for the private key
      // but invalid for other object classes
      if(this->getObjectClass(objectRef) != CKO_PRIVATE_KEY) {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      // Check size
      if(attTemplate->ulValueLen != sizeof(CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;
    case CKA_ALWAYS_SENSITIVE:
    case CKA_NEVER_EXTRACTABLE:
    case CKA_WRAP_WITH_TRUSTED:
      // We can not set this for the private key
      if(this->getObjectClass(objectRef) == CKO_PRIVATE_KEY) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Invalid for other object classes
      return CKR_ATTRIBUTE_TYPE_INVALID;
    case CKA_ALWAYS_AUTHENTICATE:
      // We can change this for the private key
      // but invalid for other object classes
      if(this->getObjectClass(objectRef) != CKO_PRIVATE_KEY) {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      // This attribute can only be changed when the CKA_PRIVATE is set to true.
      if(this->getBooleanAttribute(objectRef, CKA_PRIVATE, CK_TRUE) != CK_FALSE) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      break;
    case CKA_SENSITIVE:
      // We can change this for the private key
      // but invalid for other object classes
      if(this->getObjectClass(objectRef) != CKO_PRIVATE_KEY) {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      // Attribute cannot be changed once set to CK_TRUE.
      if(this->getBooleanAttribute(objectRef, CKA_SENSITIVE, CK_TRUE) == CK_TRUE) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Check size
      if(attTemplate->ulValueLen != sizeof(CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;
    case CKA_EXTRACTABLE:
      // We can change this for the private key
      // but invalid for other object classes
      if(this->getObjectClass(objectRef) != CKO_PRIVATE_KEY) {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      // Attribute cannot be changed once set to CK_FALSE.
      if(this->getBooleanAttribute(objectRef, CKA_EXTRACTABLE, CK_FALSE) == CK_FALSE) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Check size
      if(attTemplate->ulValueLen != sizeof(CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;
    case CKA_MODULUS_BITS:
      // We can not set this for the public rsa key
      if(this->getObjectClass(objectRef) == CKO_PUBLIC_KEY && this->getKeyType(objectRef) == CKK_RSA) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Invalid for other object classes
      return CKR_ATTRIBUTE_TYPE_INVALID;
    case CKA_PUBLIC_EXPONENT:
    case CKA_MODULUS:
      // We can not set this for the RSA key
      if(this->getKeyType(objectRef) == CKK_RSA) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Invalid for other objects
      return CKR_ATTRIBUTE_TYPE_INVALID;
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
      // We can not set this for the private RSA key
      if(this->getObjectClass(objectRef) == CKO_PRIVATE_KEY && this->getKeyType(objectRef) == CKK_RSA) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
      // Invalid for other objects
      return CKR_ATTRIBUTE_TYPE_INVALID;
    default:
      // Invalid attribute
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  // Save/update in the database
  this->saveAttribute(objectRef, attTemplate->type, attTemplate->pValue, attTemplate->ulValueLen);

  return CKR_OK;
}
