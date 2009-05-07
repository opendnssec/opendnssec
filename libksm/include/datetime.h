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

#ifndef DATETIME_H
#define DATETIME_H

#ifdef __cplusplus
extern "C" {
#endif

/*+
 * datetime.h - Date/Time Utilities
 *
 * Description:
 *      Miscellaneous date/time utilities (mainly conversion functions).
-*/

#include <stdlib.h>
#include <time.h>

int DtNow(struct tm* datetime);
int DtNumeric(const char* string, struct tm* datetime);
int DtAppendTime(char* fulldt, const char* timepart);
int DtGeneral(const char* string, struct tm* datetime);
char* DtGeneralString(const char* string);
int DtParseDateTime(const char* string, struct tm* datetime);
char* DtParseDateTimeString(const char* string);
int DtIntervalSeconds(const char* number, int* interval);
void DtSecondsInterval(int interval, char* text, size_t textlen);
int DtDateDiff(const char* date1, const char* date2, int* diff);
int DtXMLIntervalSeconds(const char* number, int* interval);

#ifdef __cplusplus
};
#endif

#endif

