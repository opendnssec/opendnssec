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

/*+
 * KsmInit_rundown.c - KSM Initialization and Rundown
 *
 * Description:
 *      Holds the miscellaneous administration functions.
-*/

#include "ksm/ksm.h"
#include "ksm/kmedef.h"
#include "ksm/kmemsg.h"
#include "ksm/message.h"


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
