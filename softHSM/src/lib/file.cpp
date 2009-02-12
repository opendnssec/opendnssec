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
* Functions for file handling.
* Many of the function calls are POSIX specific.
*
************************************************************/

#include "file.h"

// Standard includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// C POSIX library header
#include <sys/stat.h>

// Returns the directory where the database is stored.
// It is stored under the .softHSM directory in the user's
// home directory.

char* checkHSMDir() {
  char *homeDir = getenv("HOME");
  char *directory = (char*)malloc(strlen(homeDir) + 10);

  if(directory == NULL) {
    return NULL;
  }

  snprintf(directory, strlen(homeDir) + 10, "%s/.softHSM", homeDir);

  struct stat st;

  // Create the directory if it is not present.
  if(stat(directory, &st) != 0) {
    mkdir(directory, S_IRUSR | S_IWUSR | S_IXUSR);
  }

  return directory;
}

// Return the path of the database

char* getDatabasePath() {
  char *directory = checkHSMDir();
  char *dbPath = (char *)malloc(strlen(directory) + 17);

  if(dbPath == NULL) {
    free(directory);
    return NULL;
  }

  snprintf(dbPath, strlen(directory) + 17, "%s/SoftHSM.sqlite3", directory);

  free(directory);
  return dbPath;
}
