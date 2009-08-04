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

/*+
 * di_string.c - Database INSERT String
 *
 * Description:
 *      Holds miscellaneous utility functions used when constructing SQL INSERT
 *      statements.
-*/

#include <stdio.h>

#include "ksm/ksm.h"
#include "ksm/database_statement.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"



/*+
 * DisInit - Create Basic Query
 *
 * Description:
 *      Creates the basic sql string comprising:
 *
 *          INSERT INTO <table> VALUES (NULL, 
 *
 *      The initial insert is due to the fact that the table is assumed to
 *      have as its first column an autonumber field (which is automatically
 *      set when the data is inserted).
 *
 * Arguments:
 *      const char* table
 *          Name of the table from where the data is inserted.
 *
 * Returns:
 *      char*
 *          Query string.  This must be freed via a call to DisEnd
-*/

char* DisInit(const char* table)
{
    char*   sql;

    sql = StrStrdup("INSERT INTO ");
    StrAppend(&sql, table);
    StrAppend(&sql, " VALUES (NULL");

    return sql;
}

/*+
 * DisSpecifyInit - Create Basic Query
 *
 * Description:
 *      Creates the basic sql string comprising:
 *
 *          INSERT INTO <table> VALUES (NULL, 
 *
 *      The initial insert is due to the fact that the table is assumed to
 *      have as its first column an autonumber field (which is automatically
 *      set when the data is inserted).
 *
 * Arguments:
 *      const char* table
 *          Name of the table from where the data is inserted.
 *      const char* cols
 *          List of columns that we are inserting into
 *
 * Returns:
 *      char*
 *          Query string.  This must be freed via a call to DisEnd
-*/

char* DisSpecifyInit(const char* table, const char* cols)
{
    char*   sql;

    sql = StrStrdup("INSERT INTO ");
    StrAppend(&sql, table);
    StrAppend(&sql, " (id, ");
    StrAppend(&sql, cols);
    StrAppend(&sql, ")");
    StrAppend(&sql, " VALUES (NULL");

    return sql;
}


/*+
 * DisAppendInt - Append Integer Field
 * DisAppendString - Append String Field
 *
 * Description:
 *      Appends an integer or string field to the sql.
 *
 * Arguments:
 *      char** sql
 *          Query to modify.
 *
 *      int/const char* what
 *          Data to append.  If a string, it is assumed NOT to contain the
 *          apostrophe character. Also, if a string and specified as NULL,
 *          then the keyword NULL is inserted.
-*/

void DisAppendInt(char** sql, int what)
{
    char    buffer[KSM_INT_STR_SIZE];     /* Enough to hold any integer */

    StrAppend(sql, ", ");
    snprintf(buffer, KSM_INT_STR_SIZE, "%d", what);
    StrAppend(sql, buffer);

    return;
}

void DisAppendString(char** sql, const char* what)
{
    if (what) {
        StrAppend(sql, ", '");
        StrAppend(sql, what);   /* TODO make sure 'what' is safe to insert (quote quotes?) */
        StrAppend(sql, "'");
    }
    else {
        StrAppend(sql, ", NULL");
    }

    return;
}



/*+
 * DisEnd - End Up SQL Statement
 *
 * Description:
 *      Appends the trailing bracket to the SQL sql string.
 *
 * Arguments:
 *      char** sql
 *          Query string.  If not NULL, is freed.  On return, the pointer
 *          is invalid.
-*/

void DisEnd(char** sql)
{
    StrAppend(sql, ")");

    return;
}



/*+
 * DisFree - Free Query Resources
 *
 * Description:
 *      Frees up resources allocated for the sql string.
 *
 * Arguments:
 *      char* sql
 *          Query string.  If not NULL, is freed.  On return, the pointer
 *          is invalid.
-*/

void DisFree(char* sql)
{
    if (sql) {
        StrFree(sql);
    }

    return;
}
