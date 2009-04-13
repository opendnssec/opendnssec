/*+
 * database_init_rundown.c - Database Access Initialization
 *
 * Description:
 *      Contains the functions needed to initialize and run down the
 *      database access module.
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

#include "database.h"
#include "dbsdef.inc"
#include "message.h"

/* Flag as to whether the database modules have been initialized */

static int m_initialized = 0;       /* Default is not */



/*+
 * DbInit - Initialize Database Access
 *
 * Description:
 *      Initializes the Database Modules if not already initialized.
 *
 * Arguments:
 *      None.
-*/

void DbInit(void)
{
    if (! m_initialized) {
        MsgRegister(DBS_MIN_VALUE, DBS_MAX_VALUE, m_messages, NULL);
        m_initialized = 1;
    }

    return;
}



/*+
 * DbRundown - Rundown Database Access
 *
 * Description:
 * 		Performs any rundown needed of the database module.
 *
 * Arguments:
 * 		None.
-*/

void DbRundown(void)
{
	return;
}
