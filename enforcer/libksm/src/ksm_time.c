/*+
 * ksm_time - Perform Time-Related Functions
 *
 * Description:
 *      Utility routines needed by the ksm_xxx modules.
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

#include <time.h>

/*+
 * ksm_time - Get KSM Time
 *
 * Description:
 *      Converts a time_t to a string suitable for use in a MySql statement.
 *
 * Arguments:
 *      time_t time
 *          Time to convert.  It is assumed that this is local time.
 *          If zero, the current time is used.
 *
 * Returns:
 *      const char*
 *          Pointer to a static buffer holding the UTC time.
-*/
