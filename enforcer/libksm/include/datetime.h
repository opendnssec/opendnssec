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

#ifdef __cplusplus
};
#endif

#endif

