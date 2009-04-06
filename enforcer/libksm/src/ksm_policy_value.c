/*+
 * KsmPolicyValue - Return Values of Parameters
 *
 * Abstract:
 *      This set of functions encapsulates the parameter collection object.
 *      It provides functions for extracting parameters - and derived
 *      parameters - from that object.
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
    return policy->clockskew;
}

int KsmPolicyKeyLifetime(KSM_KEY_POLICY *policy)
{
    return policy->lifetime;
}

int KsmPolicyEmergencyKeys(KSM_KEY_POLICY *policy)
{
    return policy->overlap;
}

int KsmPolicyPropagationDelay(KSM_SIGNER_POLICY *policy)
{
    return policy->propdelay;
}

/*int KsmParameterSigningInterval(KSM_PARCOLL* collection)
//{
//    return collection->signint;
}*/

int KsmPolicySoaMin(KSM_SIGNER_POLICY *policy)
{
    return policy->soamin;
}

int KsmPolicySoaTtl(KSM_SIGNER_POLICY *policy)
{
    return policy->soattl;
}

int KsmPolicyKeyTtl(KSM_KEY_POLICY *policy)
{
    return policy->ttl;
}

/*
 * Initial publication interval
 */
int KsmPolicyInitialPublicationInterval(KSM_POLICY *policy)
{
    int     ncache;         /* Negative cache time */
    int     pubint;         /* Publication interval */

    ncache = min(KsmParameterSoaTtl(policy->signer),
        KsmParameterSoaMin(policy->signer));
    pubint = max(KsmParameterZskTtl(policy->zsk), ncache) +
        KsmParameterPropagationDelay(policy->signer);

    return pubint;
}
