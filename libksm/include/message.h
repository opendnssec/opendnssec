#ifndef MESSAGE_H
#define MESSAGE_H

/*+
 * Filename: message.h
 *
 * Description:
 *      Definitions of the message utility functions and data structures.
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

#include <stdarg.h>

#include "system_includes.h"
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*MSG_OUTPUT_FUNCTION)(const char* text);

typedef struct {
    int     min;            	/* Base value of the error code range */
    int     max;            	/* Maximum error code value */
    const char** message;   	/* Message text value */
    MSG_OUTPUT_FUNCTION output;	/* Output function for this message block */
} MSG_CODEBLOCK;


void MsgInit(void);
void MsgDefaultOutput(const char* text);
void MsgNoOutput(const char* text);
void MsgRegister(int min, int max, const char** message,
    MSG_OUTPUT_FUNCTION output);
int MsgFindCodeBlock(int status);
const char* MsgText(int status);
MSG_OUTPUT_FUNCTION MsgGetOutput(int status);
void MsgSetOutput(int code, MSG_OUTPUT_FUNCTION output);
int MsgLog(int status, ...);
int MsgLogAp(int status, va_list ap);
void MsgRundown(void);


#ifdef __cplusplus
}
#endif

#endif
