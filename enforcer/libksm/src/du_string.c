/*+
 * du_string.c - Database UPDATE String
 *
 * Description:
 *      Holds miscellaneous utility functions used when constructing SQL UPDATE
 *      statments of the KSM database.
 *
 * Copyright:
 *      Copyright 2008 Nominet
 *      
 * Licence:
 *      Licensed under the Apache Licence, Version 2.0 (the "Licence");
 *      you may not use this file except in compliance with the Licence.
 *      You may obtain a copy of the Licence at
 *      
 *          http://www.apache.org/licenses/LICENSE-2.0
 *      
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the Licence is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the Licence for the specific language governing permissions and
 *      limitations under the Licence.
-*/

#include <stdio.h>

#include "database_statement.h"
#include "string_util.h"
#include "string_util2.h"


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
    char    buffer[128];        /* Enough to hold any integer */

    if (clause) {
        StrAppend(sql, ", ");
    }
    StrAppend(sql, field);
    StrAppend(sql, " = ");

    sprintf(buffer, "%d", data);
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
