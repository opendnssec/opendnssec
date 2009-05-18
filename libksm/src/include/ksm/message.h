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

#ifndef KSM_MESSAGE_H
#define KSM_MESSAGE_H

/*+
 * Filename: message.h
 *
 * Description:
 *      Definitions of the message utility functions and data structures.
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

#endif /* KSM_MESSAGE_H */
