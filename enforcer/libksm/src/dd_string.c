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
 * dd_string.c - Database DELETE String
 *
 * Description:
 *      Holds miscellaneous utility functions used when constructing SQL DELETE
 *      commands in the KSM database.
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
