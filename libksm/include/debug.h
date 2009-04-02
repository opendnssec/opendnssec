#ifndef DEBUG_H
#define DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

/*+
 * debug.h
 *
 * Description:
 *      Holds definitions and prototypes for the debug functions.
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

#endif

