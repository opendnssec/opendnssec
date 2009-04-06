/*+
 * KsmInit_rundown.c - KSM Initialization and Rundown
 *
 * Description:
 *      Holds the miscellaneous administration functions.
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

#include "ksm.h"
#include "kmedef.inc"
#include "message.h"


/*+
 * KsmInit - Initialization Function
 *
 * Description:
 *      Initialize KSM library.  The tasks are:
 *
 *      a) Register the KSM error messages.
 *      b) Initialize the database
 *
 * Arguments:
 *      None.
 *
 * Returns:
 *      int
 *          0 for success or a KSM error code
-*/

int KsmInit(void)
{
	MsgInit();
    MsgRegister(KME_MIN_VALUE, KME_MAX_VALUE, m_messages, NULL);
	DbInit();

    return 0;
}



/*+
 * KsmRundown - Rundown Function
 *
 * Description:
 *      Runs down the KSM library and frees any resources.
 *
 * Arguments:
 *      None.
 *
 * Returns:
 *      int
 *          0 for success or a KSM error code
-*/

int KsmRundown(void)
{
	DbRundown();
	MsgRundown();

    return 0;
}
