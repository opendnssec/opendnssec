/*+
 * di_string.c - Database INSERT String
 *
 * Description:
 *      Holds miscellaneous utility functions used when constructing SQL INSERT
 *      statements.
 *
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
    char    buffer[32];     /* Enough to hold any integer */

    StrAppend(sql, ", ");
    sprintf(buffer, "%d", what);
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
