/*+
 * dd_string.c - Database DELETE String
 *
 * Description:
 *      Holds miscellaneous utility functions used when constructing SQL DELETE
 *      commands in the KSM database.
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
 * DdsInit - Create Basic Query
 *
 * Description:
 *      Creates the basic query string comprising:
 *
 *          DELETE FROM <table>
 *
 * Arguments:
 *      const char* table
 *          Name of the table from where the data is retrieved.
 *
 * Returns:
 *      char*
 *          Query string.  This must be freed via a call to DdsEnd
-*/

char* DdsInit(const char* table)
{
    char*   query;

    query = StrStrdup("DELETE FROM ");
    StrAppend(&query, table);

    return query;
}


/*+
 * DdsConditionInt - Append Integer Condition to Query
 * DdsConditionString - Append String Condition to Query
 * DdsConditionKeyword - Append Keyword Condition to Query
 * DdsEnd - End Query String Creation
 * DdsFree - Free Query Resources
 *
 * Description:
 *      Add conditions to the deletion statement and free up resources.
 *
 *      Because the operations are the same as the corresponding "query"
 *      functions, this are no more than wrappers for those functions.
 *
 * Arguments:
 *      See corresponding query functions.
-*/

void DdsConditionInt(char** query, const char* field, DQS_COMPARISON compare,
    int value, int index)
{
    DqsConditionInt(query, field, compare, value, index);
    return;
}

void DdsConditionString(char** query, const char* field, DQS_COMPARISON compare,
    const char* value, int index)
{
    DqsConditionString(query, field, compare, value, index);
    return;
}

void DdsConditionKeyword(char** query, const char* field,
    DQS_COMPARISON compare, const char* value, int index)
{
    DqsConditionKeyword(query, field, compare, value, index);
    return;
}

void DdsEnd(char** query)
{
    DqsEnd(query);
    return;
}

void DdsFree(char* query)
{
    DqsFree(query);
    return;
}
