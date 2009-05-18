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

#ifndef KSM_DEBUG_H
#define KSM_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

/*+
 * debug.h
 *
 * Description:
 *      Holds definitions and prototypes for the debug functions.
-*/

/* Debug mask flags */

#define DBG_M_SQL		0x1     /* Print SQL before it is executed */
#define DBG_M_UPDATE	0x2     /* List information for time updates */
#define DBG_M_REQUEST	0x4		/* List messages during REQUEST processing */

/* Debug functions */

unsigned int DbgGet(void);
unsigned int DbgSet(unsigned int mask);

int DbgIsSet(unsigned int flags);

void DbgLog(unsigned int mask, int status, ...);
void DbgOutput(unsigned int mask, const char* format, ...);
void DbgPrint(const char* format, ...);

#ifdef __cplusplus
};
#endif

#endif /* KSM_DEBUG_H */

