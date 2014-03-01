/*
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
 * All rights reserved.
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

#ifndef _ENFORCER_RESALT_H_
#define _ENFORCER_RESALT_H_

#include "policy/kasp.pb.h"

/*+
 * PolicyUpdateSalt
 *
 * Description:
 *      Given a policy see if the salt needs updating (based on denial->resalt).
 *      If it is out of date then generate a new salt and write it to the object.
 *
 * Arguments:
 *      ::ods::kasp::Policy &policy
 *      	object that holds the current policy information should have been populated
 *
 * Returns:
 *      int
 *          Status return:
 *              1           success, policy was changed
 *              0           success, policy was unchanged
 *              <0          some error occurred and a message has been output.
 *              -1          no policy found
 *              -2          an error working out time difference between stamp and now
 *              -3          salt length in policy is out of range (either 0 or larger than 255)
 *
 -*/

int PolicyUpdateSalt(::ods::kasp::Policy &policy);

#endif
