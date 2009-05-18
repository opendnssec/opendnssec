/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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
 *
 */

#ifndef KSM_DATABASE_H
#define KSM_DATABASE_H

#ifdef __cplusplus
extern "C" {
#endif

/*+
 * database.h - Database Functions
 *
 * Description:
 *      Holds definitions and prototypes for the database module.
-*/

#include <stdlib.h>

#define MYSQL_DB 1
#define SQLITE_DB 2

#ifdef USE_MYSQL

#include "mysql.h"

typedef MYSQL*	DB_HANDLE;				/* Connection handle */
typedef unsigned long DB_ID;			/* Database row identification */

struct db_result {						/* Result structure */
	unsigned int	magic;				/* Identification */
	int				count;				/* Field count */
	DB_HANDLE		handle;				/* Parent database handle */
	MYSQL_RES*		data;				/* Pointer to the result set */
};
#define DB_RESULT_MAGIC	(0x10203044)

typedef struct db_result*	DB_RESULT;	/* Handle to a result set */

struct db_row {							/* Row structure */
	unsigned int	magic;				/* Idenfification */
	DB_RESULT		result;				/* Parent result structure */
	MYSQL_ROW		data;				/* Actual row of data */
};
#define DB_ROW_MAGIC	(0xbedea133)
typedef	struct db_row*	DB_ROW;			/* Handle to the row structure */

#else

#include <sqlite3.h>

typedef sqlite3* DB_HANDLE;             /* Connection handle*/
typedef unsigned long DB_ID;			/* Database row identification */

struct db_result {						/* Result structure */
	unsigned int	magic;				/* Identification */
	int				count;				/* Field count */
	DB_HANDLE		handle;				/* Parent database handle */
    sqlite3_stmt*   data;               /* current result set (or as close to 
                                           this as sqlite gets) */
	short			first_row;			/* Set to 1 when no rows have been fetched */
};
#define DB_RESULT_MAGIC	(0x10203044)

typedef struct db_result*	DB_RESULT;	/* Handle to a result set */

/* need to typedef DB_ROW to avoid changing MySQL calls */
struct db_row {							/* Row structure */
	unsigned int	magic;				/* Idenfification */
	DB_RESULT		result;				/* Parent result structure */
};
#define DB_ROW_MAGIC	(0xbedea133)
typedef	struct db_row*	DB_ROW;

#endif

/* Initialization and rundown */

void DbInit(void);
void DbRundown(void);

/* Basic connection to the database */

int DbConnect(DB_HANDLE* dbhandle, const char* database, ...);
int DbDisconnect(DB_HANDLE dbhandle);
int DbConnected(DB_HANDLE dbhandle);
int DbCheckConnected(DB_HANDLE dbhandle);

DB_HANDLE DbHandle(void);

/* Various basic information access functions */

int DbExecuteSql(DB_HANDLE handle, const char* stmt_str, DB_RESULT* result);
/*int DbRowCount(DB_RESULT result);*/
void DbFreeResult(DB_RESULT result);
int DbFetchRow(DB_RESULT result, DB_ROW* row);
void DbFreeRow(DB_ROW row);
int DbString(DB_ROW row, int field_index, char** result);
void DbStringFree(char* string);

/* Derived information access functions */

int DbExecuteSqlNoResult(DB_HANDLE dbhandle, const char* stmt_str);
int DbUnsignedLong(DB_ROW row, int field_index, unsigned long* value);
int DbInt(DB_ROW row, int field_index, int *value);
int DbIntQuery(DB_HANDLE handle, int* value, const char* query);
int DbStringBuffer(DB_ROW row, int field_index, char* buffer, size_t buflen);
int DbRowId(DB_ROW, DB_ID* id);

/* Others */

const char* DbErrmsg(DB_HANDLE handle);
int DbErrno(DB_HANDLE handle);
int DbLastRowId(DB_HANDLE handle, DB_ID* id);

/* Transaction stuff */

int DbBeginTransaction(void);
int DbCommit(void);
int DbRollback(void);

/* What sort of DB are we running */

int DbFlavour(void);


#ifdef __cplusplus
};
#endif

#endif /* KSM_DATABASE_H */
