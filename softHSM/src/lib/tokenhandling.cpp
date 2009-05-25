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
* Functions for token handling.
*
************************************************************/

#include "tokenhandling.h"
#include "userhandling.h"
#include "log.h"
#include "SoftDatabase.h"

#include <sqlite3.h>

#define EXEC_DB(db, sql) \
  if(sqlite3_exec(db, sql, NULL, NULL, NULL)) { \
    free(soPIN); \
    sqlite3_close(db); \
    DEBUG_MSG("C_InitToken", "Could not perform a query to the db"); \
    return CKR_DEVICE_ERROR; \
  }

// The database schema

static char sqlDBSchemaVersion[] =
  "PRAGMA user_version = 100";

static char sqlCreateTableToken[] =
  "CREATE TABLE Token ("
  "variableID INTEGER PRIMARY KEY,"
  "value TEXT DEFAULT NULL);";

static char sqlCreateTableObjects[] =
  "CREATE TABLE Objects ("
  "objectID INTEGER PRIMARY KEY);";

static char sqlCreateTableAttributes[] =
  "CREATE TABLE Attributes ("
  "attributeID INTEGER PRIMARY KEY,"
  "objectID INTEGER DEFAULT NULL,"
  "type INTEGER DEFAULT NULL,"
  "value BLOB DEFAULT NULL,"
  "length INTEGER DEFAULT 0);";

static char sqlDeleteTrigger[] =
  "CREATE TRIGGER deleteTrigger BEFORE DELETE ON Objects "
  "BEGIN "
    "DELETE FROM Attributes "
      "WHERE objectID = OLD.objectID; "
  "END;";


// Initialize a token

CK_RV softInitToken(SoftSlot *currentSlot, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
  // Digest the PIN
  char *soPIN = digestPIN(pPin, ulPinLen);
  CHECK_DEBUG_RETURN(soPIN == NULL_PTR, "C_InitToken", "Could not allocate memory",
                     CKR_HOST_MEMORY);

  // Check if the token is already initialized and if the SO PIN matches
  if((currentSlot->tokenFlags & CKF_TOKEN_INITIALIZED) == 1) {
    if(strcmp(soPIN, currentSlot->hashedSOPIN) != 0) {
      free(soPIN);
      DEBUG_MSG("C_InitToken", "The new SO PIN does not match the existing one");
      return CKR_PIN_INCORRECT;
    }
  }

  // Open the database
  sqlite3 *db = NULL;
  int result = sqlite3_open(currentSlot->dbPath, &db);
  if(result){
    if(db != NULL) {
      sqlite3_close(db);
    }
    DEBUG_MSG("C_InitToken", "Could not open the token database file");
    return CKR_DEVICE_ERROR;
  }

  // Clear the database.
  EXEC_DB(db, "DROP TABLE IF EXISTS Token");
  EXEC_DB(db, "DROP TABLE IF EXISTS Objects");
  EXEC_DB(db, "DROP TABLE IF EXISTS Attributes");
  EXEC_DB(db, "DROP TRIGGER IF EXISTS deleteTrigger");

  // Add the structure
  EXEC_DB(db, sqlDBSchemaVersion);
  EXEC_DB(db, sqlCreateTableToken);
  EXEC_DB(db, sqlCreateTableObjects);
  EXEC_DB(db, sqlCreateTableAttributes);
  EXEC_DB(db, sqlDeleteTrigger);
  sqlite3_close(db);

  // Open a connection to the new db
  SoftDatabase *softDB = new SoftDatabase();
  softDB->init(currentSlot->dbPath);
  CHECK_DEBUG_RETURN(softDB->init(currentSlot->dbPath) != CKR_OK, "C_InitToken", "Could not create a connection to the database",
                     CKR_DEVICE_ERROR);

  // Add token info
  softDB->saveTokenInfo(DB_TOKEN_LABEL, (char*)pLabel, 32);
  softDB->saveTokenInfo(DB_TOKEN_SOPIN, soPIN, strlen(soPIN));

  // Close
  free(soPIN);
  delete softDB;

  currentSlot->readDB();

  DEBUG_MSG("C_InitToken", "OK");
  return CKR_OK;
}
