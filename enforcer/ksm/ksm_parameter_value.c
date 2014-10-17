/*
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
 * KsmParameterValue - Return Values of Parameters
 *
 * Abstract:
 *      This set of functions encapsulates the parameter collection object.
 *      It provides functions for extracting parameters - and derived
 *      parameters - from that object.
-*/

#include "ksm/ksm.h"
#include "ksm/ksmdef.h"
#include "ksm/message.h"

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
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->clockskew;
}

int KsmParameterKskLifetime(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->ksklife;
}

int KsmParameterStandbyKSKeys(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->standbyksks;
}

int KsmParameterStandbyZSKeys(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->standbyzsks;
}

int KsmParameterPropagationDelay(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->propdelay;
}

int KsmParameterSigningInterval(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->signint;
}

int KsmParameterSoaMin(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->soamin;
}

int KsmParameterSoaTtl(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->soattl;
}

int KsmParameterZskLifetime(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->zsklife;
}

int KsmParameterZskTtl(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->zskttl;
}

int KsmParameterKskTtl(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->kskttl;
}

int KsmParameterKskPropagationDelay(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->kskpropdelay;
}

int KsmParameterRegistrationDelay(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->regdelay;
}

int KsmParameterPubSafety(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->pub_safety;
}

int KsmParameterRetSafety(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->ret_safety;
}

int KsmParameterRfc5011(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->rfc5011;
}

int KsmParameterRevoke(KSM_PARCOLL* collection)
{
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }
    return collection->revoke;
}

/*
 * Initial publication interval
 *
 * Make sure that you add "publish safety margin" for "real world" use
 */
int KsmParameterInitialPublicationInterval(KSM_PARCOLL* collection)
{
    int     ncache;         /* Negative cache time */
    int     pubint;         /* Publication interval */
    /* check the argument */
    if (collection == NULL) {
        MsgLog(KSM_INVARG, "NULL collection");
        return -1;
    }

    ncache = min(KsmParameterSoaTtl(collection),
        KsmParameterSoaMin(collection));
    pubint = max(KsmParameterZskTtl(collection), ncache) +
        KsmParameterPropagationDelay(collection);

    return pubint;
}
