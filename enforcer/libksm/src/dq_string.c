/*+
 * dq_string.c - Database QUERY String
 *
 * Description:
 *      Holds miscellaneous utility functions used when constructing queries
 *      (SELECT) of the KSM database.
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

#include "ksm.h"
#include "database_statement.h"
#include "string_util.h"
#include "string_util2.h"



/*+
 * DqsInit - Create Basic Query - DEPRECATED
 *
 * Description:
 *      Creates the basic query string comprising:
 *
 *          SELECT * FROM <table>
 *
 * Arguments:
 *      const char* table
 *          Name of the table from where the data is retrieved.
 *
 * Returns:
 *      char*
 *          Query string.  This must be freed via a call to DqsFree
-*/

char* DqsInit(const char* table)
{
    char*   query;

    query = StrStrdup("SELECT * FROM ");
    StrAppend(&query, table);

    return query;
}



/*+
 * DqsCountInit - Create Basic Count Query
 *
 * Description:
 *      Creates the basic query string comprising:
 *
 *          SELECT COUNT(*) FROM <table>
 *
 * Arguments:
 *      const char* table
 *          Name of the table from where the data is retrieved.
 *
 * Returns:
 *      const char*
 *          Query string.  This must be freed via a call to DqsFree
-*/

char* DqsCountInit(const char* table)
{
    char*   query;

    query = StrStrdup("SELECT COUNT(*) FROM ");
    StrAppend(&query, table);

    return query;
}

/*+
 * DqsSpecifyInit - Create Query
 *
 * Description:
 *      Creates the basic query string comprising:
 *
 *          SELECT x, y, z FROM <table>
 *
 * Arguments:
 *      const char* table
 *          Name of the table from where the data is retrieved.
 *
 * Returns:
 *      char*
 *          Query string.  This must be freed via a call to DqsEnd
-*/

char* DqsSpecifyInit(const char* table, const char* fields)
{
    char*   query;
    char* query1;

    query = StrStrdup("SELECT ");
    StrAppend(&query, fields);
    query1 = StrStrdup(" FROM ");
    StrAppend(&query, query1);
    StrAppend(&query, table);
    StrFree(query1);
    return query;
}

/*+
 * DqsAppendComparison - Append Comparison Operator
 *
 * Description:
 *      Depending on the value of the comparsion code, append the appropriate
 *      operator to the string.
 *
 * Arguments:
 *      char** query
 *          Query to modify.
 *
 *      DQS_COMPARISON compare
 *          One of the KSM comparison codes.  If invalid, the string " ??"
 *          is appended, which will cause the query to fail.
-*/

static void DqsAppendComparison(char** query, DQS_COMPARISON compare)
{
    switch (compare) {
    case DQS_COMPARE_LT:
        StrAppend(query, " < ");
        break;

    case DQS_COMPARE_LE:
        StrAppend(query, " <= ");
        break;

    case DQS_COMPARE_EQ:
        StrAppend(query, " = ");
        break;

    case DQS_COMPARE_NE:
        StrAppend(query, " != ");
        break;

    case DQS_COMPARE_GE:
        StrAppend(query, " >= ");
        break;

    case DQS_COMPARE_GT:
        StrAppend(query, " > ");
        break;

    case DQS_COMPARE_IN:
        StrAppend(query, " IN ");
        break;

    default:
        StrAppend(query, " ?? ");
    }

    return;
}


/*+
 * DqsConditionInt - Append Integer Condition to Query
 * DqsConditionString - Append String Condition to Query
 * DqsConditionKeyword - Append Keyword Condition to Query
 *
 * Description:
 *      Appends a condition to the basic query.
 *
 *      -Int        Appends a comparison with an integer
 *      -String     Appends a comparison with a string, quoting the string
 *      -Keyword    Appends more complicated condition
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
 *      int index
 *          Condition index.  If 0, a WHERE is appended in front of the
 *          condition as it is the first one.  Otherwise an AND in appended.
-*/

void DqsConditionInt(char** query, const char* field, DQS_COMPARISON compare,
    int value, int index)
{
    char    stringval[KSM_INT_STR_SIZE];  /* For Integer to String conversion */

    StrAppend(query, (index == 0) ? " WHERE " : " AND ");
    StrAppend(query, field);
    DqsAppendComparison(query, compare);
    snprintf(stringval, KSM_INT_STR_SIZE, "%d", value);
    StrAppend(query, stringval);

    return;
}

void DqsConditionString(char** query, const char* field, DQS_COMPARISON compare,
    const char* value, int index)
{
    StrAppend(query, (index == 0) ? " WHERE " : " AND ");
    StrAppend(query, field);
    DqsAppendComparison(query, compare);
    StrAppend(query, "\"");
    StrAppend(query, value);
    StrAppend(query, "\"");

    return;
}

void DqsConditionKeyword(char** query, const char* field,
    DQS_COMPARISON compare, const char* value, int index)
{
    StrAppend(query, (index == 0) ? " WHERE " : " AND ");
    StrAppend(query, field);
    DqsAppendComparison(query, compare);
    StrAppend(query, value);

    return;
}


/*+
 * DqsOrderBy - Add Order By Clause
 *
 * Description:
 *      Adds an ORDER BY clause to the query.
 *
 * Arguments:
 *      char** query
 *          Query to modify.
 *
 *      const char* field
 *          Field on which to order.
-*/

void DqsOrderBy(char** query, const char* field)
{
    StrAppend(query, " ORDER BY ");
    StrAppend(query, field);

    return;
}


/*+
 * DqsEnd - End Query String Creation

 *
 * Description:
 *      Closes down the creation of the query string.  At present, this is a
 *      no-op.
 *
 * Arguments:
 *      char** query
 *          Query string.
-*/

void DqsEnd(char** query)
{
    return;
}



/*+
 * DqsFree - Free Query Resources
 *
 * Description:
 *      Frees up resources allocated for the query string.
 *
 * Arguments:
 *      char* query
 *          Query string.  If not NULL, is freed.  On return, the pointer
 *          is invalid.
-*/

void DqsFree(char* query)
{
    if (query) {
        StrFree(query);
    }

    return;
}
