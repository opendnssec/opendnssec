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
 * du_string.c - Database UPDATE String
 *
 * Description:
 *      Holds miscellaneous utility functions used when constructing SQL UPDATE
 *      statments of the KSM database.
-*/

#include <stdio.h>

#include "ksm/ksm.h"
#include "ksm/database_statement.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"


/*+
 * DusInit - Create Basic Update
 *
 * Description:
 *      Creates the basic sql string comprising:
 *
 *          UPDATE <table> SET
 *
 * Arguments:
 *      const char* table
 *          Name of the table from where the data is inserted.
 *
 * Returns:
 *      char*
 *          Query string.  This must be freed via a call to DusEnd
-*/

char* DusInit(const char* table)
{
    char*   sql;

    sql = StrStrdup("UPDATE ");
    StrAppend(&sql, table);
    StrAppend(&sql, " SET ");

    return sql;
}


/*+
 * DusSetInt - Integer Set
 * DusSetString - String Set
 *
 * Description:
 *      Appends an integer or string field to the sql of the form:
 *
 *          keyword = value
 *
 * Arguments:
 *      char** sql
 *          Query to modify.
 *
 *      const char* field
 *          Field to modify.
 *
 *      int/const char* data
 *          Data to append.  If a string, it is assumed NOT to contain the
 *          apostrophe character. Also, if a string and specified as NULL,
 *          then the keyword NULL is inserted.
 *
 *      int clause
 *          If 0, no comma is prepended to the string.
-*/

void DusSetInt(char** sql, const char* field, int data, int clause)
{
    char    buffer[KSM_INT_STR_SIZE];        /* Enough to hold any integer */

    if (clause) {
        StrAppend(sql, ", ");
    }
    StrAppend(sql, field);
    StrAppend(sql, " = ");

    snprintf(buffer, KSM_INT_STR_SIZE, "%d", data);
    StrAppend(sql, buffer);

    return;
}

void DusSetString(char** sql, const char* field, const char* data, int clause)
{
    if (clause) {
        StrAppend(sql, ", ");
    }

    StrAppend(sql, field);
    StrAppend(sql, " = ");

    if (data) {
        StrAppend(sql, "\"");
        StrAppend(sql, data);
        StrAppend(sql, "\"");
    }
    else {
        StrAppend(sql, "NULL");
    }

    return;
}


/*+
 * DusConditionInt - Append Integer Condition to Query
 * DusConditionString - Append String Condition to Query
 * DusConditionKeyword - Append Keyword Condition to Query
 *
 * Description:
 *      Appends a condition to the basic query.
 *
 *      -Int        Appends a comparison with an integer
 *      -String     Appends a comparison with a string, quoting the string
 *      -Keyword    Appends more complicated condition
 *
 *      Note: These simply call the corresponding Dqs functions.
 *
 * Arguments:
 *      char** query
 *          Query to modify.
 *
 *      const char* field
 *          Name of field to be comparison value
 *
 *      DQS_COMPARISON compare
 *          Code for the compaison.
 *
 *      int value/char* value
 *          Value to compare against.
 *
 *      int clause
 *          Condition clause.  If 0, a WHERE is appended in front of the
 *          condition as it is the first one.  Otherwise an AND in appended.
 *
 *          N.B. This is a different variable to the clause in the DusSetXxx
 *          functions.
-*/

void DusConditionInt(char** query, const char* field, DQS_COMPARISON compare,
    int value, int clause)
{
    DqsConditionInt(query, field, compare, value, clause);
}

void DusConditionString(char** query, const char* field, DQS_COMPARISON compare,
    const char* value, int clause)
{
    DqsConditionString(query, field, compare, value, clause);
}

void DusConditionKeyword(char** query, const char* field,
    DQS_COMPARISON compare, const char* value, int clause)
{
    DqsConditionKeyword(query, field, compare, value, clause);
}



/*+
 * DusEnd - End Up SQL Statement
 *
 * Description:
 *      Appends the trailing bracket to the SQL sql string.
 *
 * Arguments:
 *      char** sql
 *          Query string.  If not NULL, is freed.  On return, the pointer
 *          is invalid. ???
-*/

void DusEnd(char** sql)
{
    /* Unused parameter */
    (void)sql;
    return;
}



/*+
 * DusFree - Free Query Resources
 *
 * Description:
 *      Frees up resources allocated for the sql string.
 *
 * Arguments:
 *      char* sql
 *          Query string.  If not NULL, is freed.  On return, the pointer
 *          is invalid.
-*/

void DusFree(char* sql)
{
    if (sql) {
        StrFree(sql);
    }

    return;
}
