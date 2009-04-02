#ifndef KSM_INTERNAL_H
#define KSM_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

/*+
 * ksm_internal.h - Internal KSM Functions
 *
 * Description:
 *      Holds definitions and prototypes for KSM that depend on the
 *      implementation, i.e. that depends on external packages (such as MySql).
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

#ifdef USE_MYSQL

#include "mysql.h"

MYSQL* KsmHandle(void);

#else

#include <sqlite3.h>

sqlite3* KsmHandle(void);

#endif

#ifdef __cplusplus
};
#endif

#endif
