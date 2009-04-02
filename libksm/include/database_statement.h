#ifndef DATABASE_STATEMENT_H
#define DATABASE_STATEMENT_H

#ifdef __cplusplus
extern "C" {
#endif

/*+
 * database_statement.h - Database SQL Statement Construction
 *
 * Description:
 *      Prototypes for all the functions concerned with creating database
 *      query strings.
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

/* Database comparison operators */

typedef enum {
    DQS_END_OF_LIST,    /* Used to make the end of a list */
    DQS_COMPARE_LT,
    DQS_COMPARE_LE,
    DQS_COMPARE_EQ,
    DQS_COMPARE_NE,
    DQS_COMPARE_GT,
    DQS_COMPARE_GE,
    DQS_COMPARE_IN
} DQS_COMPARISON;

/* General comparsion structure */

typedef struct {                /* Structure for a query */
    int             code;       /* Code to query for */
    DQS_COMPARISON  compare;    /* What comparison to use */
    union {                     /* Data value to compare for */
        int         number;
        const char* string;
        void*       binary;
        struct tm*  datetime;
    } data;
} DQS_QUERY_CONDITION;

/* SELECT function prototypes */

char* DqsInit(const char* table);
char* DqsCountInit(const char* table);
char* DqsSpecifyInit(const char* table, const char* fields);
void DqsConditionInt(char** query, const char* field, DQS_COMPARISON compare,
    int value, int clause);
void DqsConditionString(char** query, const char* field, DQS_COMPARISON compare,
    const char* value, int clause);
void DqsConditionKeyword(char** query, const char* field,
    DQS_COMPARISON compare, const char* value, int clause);
void DqsOrderBy(char** query, const char* field);
void DqsEnd(char** query);
void DqsFree(char* query);

/* INSERT helper functions */

char* DisInit(const char* table);
char* DisSpecifyInit(const char* table, const char* cols);
void DisAppendInt(char** sql, int what);
void DisAppendString(char** sql, const char* what);
void DisEnd(char** sql);
void DisFree(char* sql);

/* UPDATE helper functions */

char* DusInit(const char* table);
void DusSetInt(char** sql, const char* field, int data, int clause);
void DusSetString(char** sql, const char* field, const char* data, int clause);
void DusConditionInt(char** query, const char* field, DQS_COMPARISON compare,
    int value, int clause);
void DusConditionString(char** query, const char* field, DQS_COMPARISON compare,
    const char* value, int clause);
void DusConditionKeyword(char** query, const char* field,
    DQS_COMPARISON compare, const char* value, int clause);
void DusEnd(char** sql);
void DusFree(char* sql);

/* DELETE function prototypes */

char* DdsInit(const char* table);
void DdsConditionInt(char** query, const char* field, DQS_COMPARISON compare,
    int value, int clause);
void DdsConditionString(char** query, const char* field, DQS_COMPARISON compare,
    const char* value, int clause);
void DdsConditionKeyword(char** query, const char* field,
    DQS_COMPARISON compare, const char* value, int clause);
void DdsEnd(char** query);
void DdsFree(char* query);

#ifdef __cplusplus
};
#endif

#endif
