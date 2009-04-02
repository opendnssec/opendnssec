#ifndef PARSER_H
#define PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

/*+
 * parser.h - Parser Include File
 *
 * Description:
 *      Defines the functions and structures used by the parser.
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

#include "commands.h"

/* Command Option Descriptor */

typedef struct {
    char    option;     /* The single letter option found */
    char*   string;     /* Value of the option, or NULL if no value found */
                        /* It is up to the caller to free this string */
    long    value;      /* Value of the string as long value */
    int     valid;      /* 1 if the "string"->"value" conversion succeeded */
} par_option;

typedef par_option **PAR_OPTLIST;   /* PAR_OPTLIST is the basic type now */

/* Function definitions */

void ParAdd(par_option*** optlist, char option, const char* string);
void ParFree(par_option*** optlist);

int ParPresent(par_option** optlist, char option);
int ParValid(par_option** optlist, char option);
const char* ParString(par_option** optlist, char option);
long ParValue(par_option** optlist, char option);

int ParCommand(int argc, char** argv, CMD_DESCRIPTOR* cmdlist);

#ifdef __cplusplus
};
#endif

#endif
