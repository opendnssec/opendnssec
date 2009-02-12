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
* SoftHSM
*
* This program is for creating and initializing tokens for
* the libsofthsm. libsofthsm implements parts of the PKCS#11 
* interface defined by RSA Labratories, PKCS11 v2.20, 
* called Cryptoki.
*
************************************************************/

#define DB_TOKEN_LABEL 0
#define DB_TOKEN_SOPIN 1
#define DB_TOKEN_USERPIN 2

#include "softhsm.h"

// Includes for the crypto library
#include <botan/init.h>
#include <botan/pipe.h>
#include <botan/filters.h>
#include <botan/hex.h>
#include <botan/sha2_32.h>
using namespace Botan;

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
using std::string;

void usage() {
  printf("Usage: softhsm [OPTIONS]\n");
  printf("Creates and initialize the tokens for libsofthsm\n");
  printf("Options:\n");
  printf("--init-token <file>\tCreate a database at the given location. If the database exist, \n");
  printf("\t\t\tit will be erased. Use with --label, --so-pin, and --pin.\n");
  printf("--label <text>\t\tDefines the label of the token. Max 32 chars.\n");
  printf("--so-pin <PIN>\t\tThe PIN for the Security Officer (SO). 4-8000 chars.\n");
  printf("--pin <PIN>\t\tThe PIN for the normal user. 4-8000 chars.\n");
  printf("-h\t\t\tShows this help.\n");
}

enum {
  OPT_INIT_TOKEN = 0x100,
  OPT_LABEL,
  OPT_SO_PIN,
  OPT_PIN
};

static const struct option long_options[] = {
  { "init-token", 1, NULL, OPT_INIT_TOKEN },
  { "label",      1, NULL, OPT_LABEL },
  { "so-pin",     1, NULL, OPT_SO_PIN },
  { "pin",        1, NULL, OPT_PIN }
};

int main(int argc, char *argv[]) {
  int option_index = 0;
  int action  = 0;
  int opt;

  char *dbPath = NULL;
  char *soPIN = NULL;
  char *userPIN = NULL;
  char *label = NULL;

  while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
    switch (opt) {
      case OPT_INIT_TOKEN:
        action = OPT_INIT_TOKEN;
        dbPath = optarg;
        break;
      case OPT_LABEL:
        label = optarg;
        break;
      case OPT_SO_PIN:
        soPIN = optarg;
        break;
      case OPT_PIN:
        userPIN = optarg;
        break;
      case 'h':
      defualt:
        usage();
        exit(0);
        break;
    }
  }

  // No action given, display the usage.
  if(action == 0) {
    usage();
    exit(0);
  }

  // We should create the token.
  if(action == OPT_INIT_TOKEN) {
    createToken(dbPath, label, soPIN, userPIN);
  }

  return 0;
}

// Creates a SoftHSM token at the given location.

void createToken(char *dbPath, char *label, char *soPIN, char *userPIN) {
  if(dbPath == NULL) {
    printf("Error: A path to the database must be supplied.\n");
    exit(1);
  }

  if(label == NULL) {
    printf("Error: A label for the token must be supplied.\n");
    exit(1);
  }

  if(strlen(label) > 32) {
    printf("Error: The label must not have a length greater than 32 chars.\n");
    exit(1);;
  }

  sqlite3 *db = NULL;

  createDatabase(dbPath, &db);
  createTables(db);

  // Init the Botan crypto library
  LibraryInitializer::initialize();

  if(soPIN == NULL) {
    soPIN = getpass("Enter SO PIN (4-8000 chars): ");
  }

  int soLength = strlen(soPIN);
  while(soLength < 4 || soLength > 8000) {
    soPIN = getpass("Wrong size! Enter SO PIN (4-8000 chars): ");
    soLength = strlen(soPIN);
  }

  char *digestedSOPIN = digestPIN(soPIN);

  if(userPIN == NULL) {
    userPIN = getpass("Enter user PIN (4-8000 chars): ");
  }

  int userLength = strlen(userPIN);
  while(userLength < 4 || userLength > 8000) {
    userPIN = getpass("Wrong size! Enter user PIN (4-8000 chars): ");
    userLength = strlen(userPIN);
  }

  char *digestedUserPIN = digestPIN(userPIN);
  char *paddedLabel = padLabel(label);

  saveTokenInfo(db, DB_TOKEN_LABEL, paddedLabel);
  saveTokenInfo(db, DB_TOKEN_SOPIN, digestedSOPIN);
  saveTokenInfo(db, DB_TOKEN_USERPIN, digestedUserPIN);

  free(paddedLabel);
  free(digestedSOPIN);
  free(digestedUserPIN);

  sqlite3_close(db);

  // Deinitialize the Botan crypto lib
  LibraryInitializer::deinitialize();

  printf("New SoftHSM token created at: %s\n", dbPath);
}

// Create/open the database at the given location.

void createDatabase(char *dbPath, sqlite3 **db) {
  // Create the database file.
  int result = sqlite3_open(dbPath, db);
  if(result){
    if(db != NULL) {
      sqlite3_close(*db);
    }

    printf("Could not create the database!\n");
    exit(1);
  }
}

// Clears the database and adds new tables.

void createTables(sqlite3 *db) {
  static char sqlCreateTableToken[] = 
    "CREATE TABLE Token ("
    "variableID INTEGER PRIMARY KEY,"
    "value TEXT DEFAULT NULL);";

  static char sqlCreateTableObjects[] = 
    "CREATE TABLE Objects ("
    "objectID INTEGER PRIMARY KEY,"
    "encodedKey TEXT DEFAULT NULL);";

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

  char *sqlError;

  // Clear the database.
  sqlite3_exec(db, "DROP TABLE IF EXISTS Token", NULL, NULL, NULL);
  sqlite3_exec(db, "DROP TABLE IF EXISTS Objects", NULL, NULL, NULL);
  sqlite3_exec(db, "DROP TABLE IF EXISTS Attributes", NULL, NULL, NULL);
  sqlite3_exec(db, "DROP TRIGGER IF EXISTS deleteTrigger", NULL, NULL, NULL);

  // Create the Token table
  int result = sqlite3_exec(db, sqlCreateTableToken, NULL, NULL, &sqlError);
  if(result) {
    sqlite3_free(sqlError);
    sqlite3_close(db);

    printf("Could not create a table in the database");
    exit(1);
  }

  // Create the Objects table
  result = sqlite3_exec(db, sqlCreateTableObjects, NULL, NULL, &sqlError);
  if(result) {
    sqlite3_free(sqlError);
    sqlite3_close(db);

    printf("Could not create a table in the database");
    exit(1);
  }

  // Create the Attributes table
  result = sqlite3_exec(db, sqlCreateTableAttributes, NULL, NULL, &sqlError);
  if(result) {
    sqlite3_free(sqlError);
    sqlite3_close(db);

    printf("Could not create a table in the database");
    exit(1);
  }

  // Create the delete trigger.
  sqlite3_exec(db, sqlDeleteTrigger, NULL, NULL, NULL);
}

// Save information about the token.

void saveTokenInfo(sqlite3 *db, int valueID, char *value) {
  string sqlInsert = "INSERT INTO Token (variableID, value) VALUES (?, ?);";

  sqlite3_stmt *insert_sql;
  int result = sqlite3_prepare_v2(db, sqlInsert.c_str(), sqlInsert.size(), &insert_sql, NULL);

  if(result) {
    sqlite3_finalize(insert_sql);

    return;
  }

  sqlite3_bind_int(insert_sql, 1, valueID);
  sqlite3_bind_text(insert_sql, 2, value, strlen(value), SQLITE_TRANSIENT);

  sqlite3_step(insert_sql);
  sqlite3_finalize(insert_sql);
}

// Pads the label to 32 chars

char* padLabel(char *label) {
  char *newLabel = (char *)malloc(33);
  int size = strlen(label);

  if(size > 32) {
    size = 32;
  }

  memset(newLabel, ' ', 32);
  newLabel[32] = '\0';
  memcpy(newLabel, label, size);

  return newLabel;
}

// Digest the given PIN

char* digestPIN(char *oldPIN) {
  int length = strlen(oldPIN);

  // We do not use any salt
  Pipe *digestPIN = new Pipe(new Hash_Filter(new SHA_256), new Hex_Encoder);
  digestPIN->start_msg();
  digestPIN->write((byte*)oldPIN, (u32bit)length);
  digestPIN->write((byte*)oldPIN, (u32bit)length);
  digestPIN->write((byte*)oldPIN, (u32bit)length);
  digestPIN->end_msg();

  // Get the digested PIN
  SecureVector<byte> pinVector = digestPIN->read_all();
  int size = pinVector.size();
  char *tmpPIN = (char *)malloc(size + 1);
  tmpPIN[size] = '\0';
  memcpy(tmpPIN, pinVector.begin(), size);
  delete digestPIN;

  return tmpPIN;
}
