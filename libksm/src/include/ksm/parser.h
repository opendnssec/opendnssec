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
