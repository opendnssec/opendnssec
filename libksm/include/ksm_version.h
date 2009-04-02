#ifndef KSM_VERSION_H
#define KSM_VERSION_H

/*+
 * Filename: ksm_version.h
 *
 * Description:
 *      Definition for the function returning the current library version.
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

#ifdef __cplusplus
extern "C" {
#endif

const char* KsmVersion(void);

#ifdef __cplusplus
}
#endif

#endif
