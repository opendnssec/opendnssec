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
 * KsmPolicyValue - Return Values of Parameters
 *
 * Abstract:
 *      This set of functions encapsulates the parameter collection object.
 *      It provides functions for extracting parameters - and derived
 *      parameters - from that object.
-*/

#include "ksm/ksm.h"
#include "ksm/ksmdef.h"

#define max(x,y) ((x) > (y) ? (x) : (y))
#define min(x,y) ((x) < (y) ? (x) : (y))


/*+
 * KsmParameterXxxxx - Return Parameter Xxxx
 *
 * Description:
 *      Returns the value of the named parameter from the object.  In some
 *      cases, these values are derived from other parameters.
 *
 * Arguments:
 *      KSM_PARCOLL* collection
 *          Parameter collection object.
 *
 * Returns:
 *      int
 *          Value of the parameter.
-*/

int KsmPolicyClockskew(KSM_SIGNATURE_POLICY *policy)
{
    /* check the argument */
    if (policy == NULL) {
        MsgLog(KSM_INVARG, "NULL policy");
        return -1;
    }
    return policy->clockskew;
}

int KsmPolicyKeyLifetime(KSM_KEY_POLICY *policy)
{
    /* check the argument */
    if (policy == NULL) {
        MsgLog(KSM_INVARG, "NULL policy");
        return -1;
    }
    return policy->lifetime;
}

int KsmPolicyEmergencyKeys(KSM_KEY_POLICY *policy)
{
    /* check the argument */
    if (policy == NULL) {
        MsgLog(KSM_INVARG, "NULL policy");
        return -1;
    }
    return policy->overlap;
}

int KsmPolicyPropagationDelay(KSM_SIGNER_POLICY *policy)
{
    /* check the argument */
    if (policy == NULL) {
        MsgLog(KSM_INVARG, "NULL policy");
        return -1;
    }
    return policy->propdelay;
}

/*int KsmParameterSigningInterval(KSM_PARCOLL* collection)
//{
//    return collection->signint;
}*/

int KsmPolicySoaMin(KSM_SIGNER_POLICY *policy)
{
    /* check the argument */
    if (policy == NULL) {
        MsgLog(KSM_INVARG, "NULL policy");
        return -1;
    }
    return policy->soamin;
}

int KsmPolicySoaTtl(KSM_SIGNER_POLICY *policy)
{
    /* check the argument */
    if (policy == NULL) {
        MsgLog(KSM_INVARG, "NULL policy");
        return -1;
    }
    return policy->soattl;
}

int KsmPolicyKeyTtl(KSM_KEY_POLICY *policy)
{
    /* check the argument */
    if (policy == NULL) {
        MsgLog(KSM_INVARG, "NULL policy");
        return -1;
    }
    return policy->ttl;
}

/*
 * Initial publication interval
 */
int KsmPolicyInitialPublicationInterval(KSM_POLICY *policy)
{
    int     ncache;         /* Negative cache time */
    int     pubint;         /* Publication interval */

    /* check the argument */
    if (policy == NULL) {
        MsgLog(KSM_INVARG, "NULL policy");
        return -1;
    }
    ncache = min(policy->signer->soattl, policy->signer->soamin);
    pubint = max(policy->zsk->ttl, ncache) + policy->signer->propdelay;

    return pubint;
}
