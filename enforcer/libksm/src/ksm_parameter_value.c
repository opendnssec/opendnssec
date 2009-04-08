/*+
 * KsmParameterValue - Return Values of Parameters
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

int KsmParameterClockskew(KSM_PARCOLL* collection)
{
    return collection->clockskew;
}

int KsmParameterKskLifetime(KSM_PARCOLL* collection)
{
    return collection->ksklife;
}

int KsmParameterEmergencyKSKeys(KSM_PARCOLL* collection)
{
    return collection->nemkskeys;
}

int KsmParameterEmergencyZSKeys(KSM_PARCOLL* collection)
{
    return collection->nemzskeys;
}

int KsmParameterPropagationDelay(KSM_PARCOLL* collection)
{
    return collection->propdelay;
}

int KsmParameterSigningInterval(KSM_PARCOLL* collection)
{
    return collection->signint;
}

int KsmParameterSoaMin(KSM_PARCOLL* collection)
{
    return collection->soamin;
}

int KsmParameterSoaTtl(KSM_PARCOLL* collection)
{
    return collection->soattl;
}

int KsmParameterZskLifetime(KSM_PARCOLL* collection)
{
    return collection->zsklife;
}

int KsmParameterZskTtl(KSM_PARCOLL* collection)
{
    return collection->zskttl;
}

int KsmParameterPubSafety(KSM_PARCOLL* collection)
{
    return collection->pub_safety;
}

int KsmParameterRetSafety(KSM_PARCOLL* collection)
{
    return collection->ret_safety;
}

/*
 * Initial publication interval
 */
int KsmParameterInitialPublicationInterval(KSM_PARCOLL* collection)
{
    int     ncache;         /* Negative cache time */
    int     pubint;         /* Publication interval */

    ncache = min(KsmParameterSoaTtl(collection),
        KsmParameterSoaMin(collection));
    pubint = max(KsmParameterZskTtl(collection), ncache) +
        KsmParameterPropagationDelay(collection);
    /* TODO add "publish safety margin" into pubint calc. or is that what PropagationDelay is? (see p13 of Morris et al.) */

    return pubint;
}
