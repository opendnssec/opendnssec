/*
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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

/* 
 * @section DESCRIPTION
 * 
 * This module controls the order and time for keys to be introduced,
 * generated and discarded. It can be called for one zone at a time. It
 * will then manipulate its keys and bring them closer to their goal, 
 * within bounds of the zone's policy. New keys may be fetched from the
 * HSM and old keys discarded. When done, the update function returns 
 * a time at which it need to be called again for this zone. Unless 
 * there is an unscheduled change for this zone (some user input) it 
 * should not be called sooner. Calling sooner is not harmful in any
 * way but also not effective. Calling later does not do any harm as 
 * well, however rollovers may be delayed.
 */

#include "config.h"

#include <time.h>

#include "libhsm.h"
#include "hsmkey/hsm_key_factory.h"

#include <libhsmdns.h>
#include <ldns/ldns.h>

#include "duration.h"
#include "log.h"
#include "daemon/engine.h"
#include "db/dbw.h"

#include "enforcer/enforcer.h"

#undef DEBUG_ENFORCER_LOGIC

#define HIDDEN      DBW_HIDDEN
#define RUMOURED    DBW_RUMOURED
#define OMNIPRESENT DBW_OMNIPRESENT
#define UNRETENTIVE DBW_UNRETENTIVE
#define NA          DBW_NA

static const char *module_str = "enforcer";

/** When no key available wait this many seconds before asking again. */
#define NOKEY_TIMEOUT 60

static int64_t max(int64_t a, int64_t b) { return a>b?a:b; }
static int64_t min(int64_t a, int64_t b) { return a<b?a:b; }

/**
 * Stores the minimum of parm1 and parm2 in parm2.
 * 
 * Stores smallest of two times in min. Avoiding negative values,
 * which mean no update necessary. Any other time in the past: ASAP.
 *
 * \param t[in], some time to test
 * \param min[in,out], smallest of t and min.
 */
static inline void
minTime(const time_t t, time_t* min)
{
	ods_log_assert(min);
	if ( (t < *min || *min < 0) && t >= 0 ) *min = t;
}

/**
 * Adds seconds to a time. 
 *
 * Adds seconds to a time. Adding seconds directly is not portable.
 *
 * \param[in] t, base time
 * \param[in] seconds, seconds to add to base
 * \return sum
 */
static time_t
addtime(const time_t t, const int seconds)
{
    struct tm timebuf;
    struct tm *tp = localtime_r(&t, &timebuf);
    if (!tp) return -1; /* bad, but mktime also returns -1 on error */
    tp->tm_sec += seconds;
    return mktime(tp);
}

/**
 * Return state of a record.
 */
static inline enum dbw_keystate_state
getState(struct dbw_key* key, enum dbw_keystate_type type)
{
    return dbw_get_keystate(key, type)->state;
}

/**
 * Given goal and state, what will be the next state?
 *
 * This is an implementation of our state diagram. State indicates
 * our current node and goal helps decide which edge to choose.
 * Input state and return state me be the same: the record is said
 * to be stable.
 *
 * \return a key_state_state_t for the next state
 */
static enum dbw_keystate_state
getDesiredState(int introducing, enum dbw_keystate_state state, struct dbw_keystate *ks)
{
    if (!introducing) {
        switch (state) {
            case RUMOURED:
                if (ks->type == DBW_DS && ks->key->ds_at_parent < DBW_DS_AT_PARENT_SUBMITTED) {
                    ks->key->ds_at_parent = DBW_DS_AT_PARENT_UNSUBMITTED;
                }
                return UNRETENTIVE;
            case OMNIPRESENT: return UNRETENTIVE;
            case UNRETENTIVE: return HIDDEN;
            default:          return state;
        }
    } else {
        switch (state) {
            case HIDDEN:
            case UNRETENTIVE: return RUMOURED;
            case RUMOURED:    return OMNIPRESENT;
            default:          return state;
        }
    }
}

/**
 * Test if a key matches specific states.
 *
 * \return 1 on match, 0 otherwise
 */
static int
match(struct dbw_key *key, int algorithm, int same_algorithm,
    const enum dbw_keystate_state mask[4])
{
    if (same_algorithm && key->algorithm != algorithm) return 0;
    /* Check the states against the mask, for each mask that is not NA we
     * need a match on that key state. */
    for (int i = 0; i < 4; i++) {
        if (mask[i] != NA && getState(key, i) != mask[i])
            return 0;
    }
    return 1;
}

/**
 * Test if a key exist with certain states.
 *
 * \return A positive value if a key exists, zero if a key does not exists.
 */
static int
exists(struct dbw_zone *zone, int algorithm, int same_algorithm,
    const enum dbw_keystate_state mask[4])
{
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (match(key, algorithm, same_algorithm, mask)) return 1;
    }
    return 0;
}

static int
exists_with_ds_state(struct dbw_zone *zone, int algorithm, int same_algorithm,
    const enum dbw_keystate_state mask[4], int ds_state)
{
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (match(key, algorithm, same_algorithm, mask)) {
            if ((key->ds_at_parent == ds_state)
             || ( key->ds_at_parent > ds_state && key->ds_at_parent <= DBW_DS_AT_PARENT_SEEN))
                return 1;
        }
    }
    return 0;
}

/**
 * Test if a key is a potential successor.
 *
 * \return 1 if a key is a potential successor, 0 otherwise.
 */
static int
isPotentialSuccessor(struct dbw_key *succkey, struct dbw_key *predkey,
    enum dbw_keystate_type type)
{
    /* You can't be a successor of yourself */
    if (succkey->id == predkey->id) return 0;
    /* Only rumoured keys can be successor. */
    if (getState(succkey, type) != RUMOURED) return 0;
    /* key of different algorithms may not be in successor relation */
    if (succkey->algorithm != predkey->algorithm) return 0;

    /* Now test whether the appropriate parts of the successor key are in the */
    /* correct state, or are about to be in the correct state. */
    switch (type) {
        case DBW_DS: /* Intentional fall-through */
        case DBW_RRSIG:
            return getState(succkey, DBW_DNSKEY) == OMNIPRESENT;
        case DBW_DNSKEY:
            /* Either both DS's should be omnipresent or both signatures, for the
             * keys to be in a potential relationship for the DNSKEY.  */
            return (  getState(predkey, DBW_DS) == OMNIPRESENT
                   && getState(succkey, DBW_DS) == OMNIPRESENT )
                || (  getState(predkey, DBW_RRSIG) == OMNIPRESENT
                   && getState(succkey, DBW_RRSIG) == OMNIPRESENT );
        default: /* no dependencies defined for DNSKEYRRSIG*/
            return 0;
    }
}

/*
 * count number of key dependencies in given list that are applicable
 * to type.
 */
static int
dependencies_for_type(struct dbw_keydependency **deplist, int count,
    enum dbw_keystate_type type)
{
    int c = 0;
    for (size_t d = 0; d < count; d++) {
        struct dbw_keydependency *dep = deplist[d];
        if (dep->type == type) c++;
    }
    return c;
}

/*
 * Given a predecessor key P that matches pmask test whether there is a
 * key S (and an arbitrary amount of P' keys in between) that matches smask
 */
static int
find_succ(struct dbw_key *P, const enum dbw_keystate_state pmask[4],
    const enum dbw_keystate_state smask[4], int algorithm,
    enum dbw_keystate_type type)
{
    /* recursive definition */
    for (size_t d = 0; d < P->from_keydependency_count; d++) {
        struct dbw_keydependency *dep = P->from_keydependency[d];
        if (dep->type != type) continue;
        struct dbw_key *PP = dep->tokey;
        /* if key PP matches smask we found key S, success! */
        if (match(PP, algorithm, 1, smask)) return 1;
        /* This was not S. Is it a P'? */
        if (!match(PP, algorithm, 1, pmask)) continue;
        if (find_succ(PP, pmask, smask, algorithm, type)) return 1;
    }
    /* From the last P' to S there might not yet been a dependency defined.
     * Test if this is the case. */
    /* But if there already is a dependency from P defined we can't do this. */
    if (dependencies_for_type(P->from_keydependency, P->from_keydependency_count, type) != 0)
        return 0;
    /* Scan for potential S */
    for (size_t kk = 0; kk < P->zone->key_count; kk++) {
        struct dbw_key *S = P->zone->key[kk];
        if (!match(S, algorithm, 1, smask)) continue;
        /* We found a potential S, now test whether it is unencumbered. */
        if (dependencies_for_type(S->to_keydependency, S->to_keydependency_count, type) != 0)
            continue;
        if (dependencies_for_type(S->from_keydependency, S->from_keydependency_count, type) != 0)
            continue;
        return 1; /* it is! */
    }
    return 0;
}

static int
first_of_dependency_chain(struct dbw_key *P, enum dbw_keystate_type type)
{
    if (!dependencies_for_type(P->to_keydependency, P->to_keydependency_count, type))
        return 1;
    /* if not first, is predecessor hidden? */

    for (size_t d = 0; d < P->to_keydependency_count; d++) {
        struct dbw_keydependency *dep = P->to_keydependency[d];
        if (dep->type != type) continue;
        struct dbw_key *fromkey = dep->fromkey;
        if (getState(fromkey, type) == HIDDEN && fromkey->to_keydependency_count == 0)
            return 1;
        /* if we can find a predeccessor with state[type]=hidden
         * and no predeccessors itself. we can consider this key
         * a valid first of the chain. */
    }
    return 0;
}

/**
 * Test the existence of a pair of keys P, S in zone with states pmask and
 * smask. There might be a successor relation defined between these keys.
 *
 * \return A positive value if a key exists, zero if a key does not exists
 */
static int
exists_with_successor(struct dbw_zone *zone, int algorithm, int same_algorithm,
    const enum dbw_keystate_state pmask[4],
    const enum dbw_keystate_state smask[4], enum dbw_keystate_type type)
{
    /* try all keys */
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *P = zone->key[k];
        /* must be the first in the chain */
        if (!first_of_dependency_chain(P, type)) continue;
        /* must match pmask */
        if (!match(P, algorithm, 1, pmask)) continue;
        /* find S*/
        if (find_succ(P, pmask, smask, algorithm, type)) return 1;

    }
    return 0;
}

/**
 * Test if keys are in a good unsigned state. For example when we have a key
 * with a rumoured DS and omnipresent DNSKEY, every other key may not have
 * its DS other than rumoured or hidden.
 *
 * \return A positive value if keys are in a good unsigned state, zero if keys
 * are not.
 */
static int
unsignedOk(struct dbw_zone *zone, int algorithm, const enum dbw_keystate_state mask[4],
    enum dbw_keystate_type type)
{
    /* collect the amount of keys in each state */
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (key->algorithm != algorithm) continue;

    enum dbw_keystate_state cmp_mask[4];
    memcpy(cmp_mask, mask, 4 * sizeof(enum dbw_keystate_state));
    cmp_mask[type] = getState(key, type);

    if (cmp_mask[type] == HIDDEN || cmp_mask[type] == NA) continue;

    cmp_mask[DBW_DS] = NA;
    if  (!exists_with_ds_state(zone, algorithm, 1, cmp_mask, key->ds_at_parent)) return 0;
    }

   return 1;
}

/* Check if ALL DS records for this algorithm are hidden
 *
 * \return 0 if !HIDDEN DS is found, 1 if no such DS where found */
static int
all_DS_hidden(struct dbw_zone *zone, int algorithm)
{
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (key->algorithm != algorithm) continue;
        enum dbw_keystate_state state = getState(key, DBW_DS);
        if (state != HIDDEN && state != NA) return 0; /*Test failed. Found DS.*/
    }
    return 1; /*No such DS where found.*/
}

/**
 * Checks for existence of DS.
 *
 * \return A positive value if the rule applies, zero if the rule does not
 * apply
 */
static int
rule1(struct dbw_zone *zone, int algorithm)
{
    static const enum dbw_keystate_state mask[2][4] = {
        { OMNIPRESENT, NA, NA, NA },/* a good key state.  */
        { RUMOURED,    NA, NA, NA } /* the DS is introducing.  */
    };
    /* Return positive value if any of the masks are found.  */
#ifdef DEBUG_ENFORCER_LOGIC
    ods_log_error("DEBUG rule1");
    ods_log_error("%d %d", exists(zone, algorithm, 0, mask[0]), exists(zone, algorithm, 0, mask[1]));
#endif
    return (exists(zone, algorithm, 0, mask[0]) || exists(zone, algorithm, 0, mask[1]));
}

/**
 * Checks for a valid DNSKEY situation.
 *
 * \return A positive value if the rule applies, zero if the rule does not
 * apply
 */
static int
rule2(struct dbw_zone *zone, int algorithm)
{
    static const enum dbw_keystate_state  mask[8][4] = {
        { OMNIPRESENT, NA, OMNIPRESENT, OMNIPRESENT },/*good key state.*/
        { RUMOURED,    NA, OMNIPRESENT, OMNIPRESENT },/*introducing DS state.*/
        { UNRETENTIVE, NA, OMNIPRESENT, OMNIPRESENT },/*outroducing DS state.*/
        { OMNIPRESENT, NA, RUMOURED,    RUMOURED    },/*introducing DNSKEY state.*/
        { OMNIPRESENT, NA, OMNIPRESENT, RUMOURED    },
        { OMNIPRESENT, NA, UNRETENTIVE, UNRETENTIVE },/*outroducing DNSKEY state.*/
        { OMNIPRESENT, NA, UNRETENTIVE, OMNIPRESENT },
        { HIDDEN,      NA, OMNIPRESENT, OMNIPRESENT } /*unsigned state.*/
    };
    /* Return positive value if any of the masks are found.  */
#ifdef DEBUG_ENFORCER_LOGIC
        ods_log_error("DEBUG rule2");
        ods_log_error("%d %d %d %d %d %d %d", exists(zone, algorithm, 1, mask[0])
            , exists_with_successor(zone, algorithm, 1, mask[2], mask[1], DBW_DS)
            , exists_with_successor(zone, algorithm, 1, mask[5], mask[3], DBW_DNSKEY)
            , exists_with_successor(zone, algorithm, 1, mask[5], mask[4], DBW_DNSKEY)
            , exists_with_successor(zone, algorithm, 1, mask[6], mask[3], DBW_DNSKEY)
            , exists_with_successor(zone, algorithm, 1, mask[6], mask[4], DBW_DNSKEY)
            , unsignedOk(zone, algorithm, mask[7], DBW_DS));
#endif
    return (exists(zone, algorithm, 1, mask[0])
        || exists_with_successor(zone, algorithm, 1, mask[2], mask[1], DBW_DS)
        || exists_with_successor(zone, algorithm, 1, mask[5], mask[3], DBW_DNSKEY)
        || exists_with_successor(zone, algorithm, 1, mask[5], mask[4], DBW_DNSKEY)
        || exists_with_successor(zone, algorithm, 1, mask[6], mask[3], DBW_DNSKEY)
        || exists_with_successor(zone, algorithm, 1, mask[6], mask[4], DBW_DNSKEY)
        || unsignedOk(zone, algorithm, mask[7], DBW_DS));
}

/**
 * Checks for a valid signature situation.
 *
 * \return A positive value if the rule applies, zero if the rule does not
 * apply
 */
static int
rule3(struct dbw_zone *zone, int algorithm)
{
    static const enum dbw_keystate_state  mask[6][4] = {
        { NA, OMNIPRESENT, OMNIPRESENT, NA },/* good key state. */
        { NA, OMNIPRESENT, RUMOURED,    NA },/* introducing DNSKEY state. */
        { NA, OMNIPRESENT, UNRETENTIVE, NA },/* outroducing DNSKEY state. */
        { NA, RUMOURED   , OMNIPRESENT, NA },/* introducing RRSIG state. */
        { NA, UNRETENTIVE, OMNIPRESENT, NA },/* outroducing RRSIG state. */
        { NA, OMNIPRESENT, HIDDEN,      NA } /* unsigned state. */
    };
#ifdef DEBUG_ENFORCER_LOGIC
        ods_log_error("DEBUG rule3");
        ods_log_error("%d %d %d %d %d", exists(zone, algorithm, 1, mask[0])
        , exists_with_successor(zone, algorithm, 1, mask[2], mask[1], DBW_DNSKEY)
        , exists_with_successor(zone, algorithm, 1, mask[4], mask[3], DBW_RRSIG)
        , unsignedOk(zone, algorithm, mask[5], DBW_DNSKEY)
        , all_DS_hidden(zone, algorithm));
#endif
    /* Return positive value if any of the masks are found. */
    return (exists(zone, algorithm, 1, mask[0])
        || exists_with_successor(zone, algorithm, 1, mask[2], mask[1], DBW_DNSKEY)
        || exists_with_successor(zone, algorithm, 1, mask[4], mask[3], DBW_RRSIG)
        || unsignedOk(zone, algorithm, mask[5], DBW_DNSKEY)
        || all_DS_hidden(zone, algorithm));
}

/**
 * Checks if transition to next_state maintains validity of zone.
 *
 * \return A positive value if the transition is allowed, zero if it is not.
 */
static int
dnssecApproval(struct dbw_zone *zone, struct dbw_key *key, enum dbw_keystate_type type,
    enum dbw_keystate_state next_state, int allow_unsigned)
{
    /* Check if DNSSEC state will be invalid by the transition by checking that
     * all 3 DNSSEC rules apply. Rule 1 only applies if we are not allowing an
     * unsigned state.
     *
     * A rule is first checked against the current state of the key_state and if
     * the current state is not valid an transition is allowed for that rule in
     * order to try and move out of an invalid DNSSEC state.
     *
     * Next the rule is checked against the desired state and if that state is a
     * valid DNSSEC state then the transition is allowed.
     *
     * rule1 - Handles DS states
     * rule2 - Handles DNSKEY states.
     * rule3 - Handles signatures.
     */
    int before_change = 0;
    int after_change = 0;

    /* set flag for each rule */
    before_change |= ( rule1(zone, key->algorithm) << 0 );
    before_change |= ( rule2(zone, key->algorithm) << 1 );
    before_change |= ( rule3(zone, key->algorithm) << 2 );

    /* safe current state, apply change and test again.*/
    struct dbw_keystate *keystate = dbw_get_keystate(key, type);
    int current_state = keystate->state;
    keystate->state = next_state;
        /* if we make the rules more sophisticated by using the timing information
         * as well, we also need to set last_change to now here.  */
        after_change |= ( rule1(zone, key->algorithm) << 0 );
        after_change |= ( rule2(zone, key->algorithm) << 1 );
        after_change |= ( rule3(zone, key->algorithm) << 2 );
    keystate->state = current_state; /* restore */

    /* before => after (implication)
     * If one of the rules isn't satisfied in the before situation we allow
     * it to be unsatisfied in the after situation. This provides us a way to
     * recover from an invalid state. */
    int valid = ((~before_change)|after_change)&0x7;
    valid |= allow_unsigned; //disable rule1
#ifdef DEBUG_ENFORCER_LOGIC
        ods_log_error("DEBUG dnssec %d %d %d", before_change, after_change, valid);
#endif
    return valid == 0x7;
}

/**
 * At what time may this transition take place?
 *
 * Given a record, its next state, and its last change time when may
 * apply the transition? This is largely policy related.
 *
 * return a time_t with the absolute time
 */
static time_t
minTransitionTime(const struct dbw_policy *policy, enum dbw_keystate_type type,
    enum dbw_keystate_state next_state, const time_t lastchange, const int ttl)
{
    /* We may freely move a record to a uncertain state.  */
    if (next_state == RUMOURED || next_state == UNRETENTIVE) return lastchange;

    switch (type) {
        case DBW_DS:
            return addtime(lastchange, ttl
                + policy->parent_registration_delay
                + policy->parent_propagation_delay);

        /* TODO: 5011 will create special case here */
        case DBW_DNSKEY: /* intentional fall-through */
        case DBW_RRSIGDNSKEY:
            return addtime(lastchange, ttl
                + policy->zone_propagation_delay
                + ( next_state == OMNIPRESENT
                    ? policy->keys_publish_safety
                    : policy->keys_retire_safety ));

        case DBW_RRSIG:
            return addtime(lastchange, ttl
                + policy->zone_propagation_delay);

        default:
            ods_log_assert(0);
            return 0; /* squelch compiler */
    }
}

/**
 * Make sure records are introduced in correct order.
 *
 * Make sure records are introduced in correct order. Only look at the
 * policy, timing and validity is done in another function.
 *
 * \return A positive value if the transition is allowed, zero if it is not and
 * a negative value if an error occurred.
 */
static int
policyApproval(struct dbw_zone *zone, struct dbw_key *key, enum dbw_keystate_type type,
    enum dbw_keystate_state next_state)
{
    static const enum dbw_keystate_state mask[14][4] = {
        /*ZSK*/
        { NA, OMNIPRESENT, OMNIPRESENT, NA },   /* good key state.*/
        { NA, OMNIPRESENT, RUMOURED,    NA },   /* introducing DNSKEY */
        { NA, OMNIPRESENT, UNRETENTIVE, NA },   /* outroducing DNSKEY */
        { NA, RUMOURED,    OMNIPRESENT, NA },   /* introducing RRSIG */
        { NA, UNRETENTIVE, OMNIPRESENT, NA },   /* outroducing RRSIG */
        { NA, OMNIPRESENT, HIDDEN,      NA },   /* unsigned state.*/

        /*KSK*/
        { OMNIPRESENT, NA, OMNIPRESENT, OMNIPRESENT },  /* good key state */
        { RUMOURED   , NA, OMNIPRESENT, OMNIPRESENT },  /* introducing DS */
        { UNRETENTIVE, NA, OMNIPRESENT, OMNIPRESENT },  /* outroducing DS */
        { OMNIPRESENT, NA, RUMOURED,    RUMOURED    },  /* introducing DNSKEY */
        { OMNIPRESENT, NA, OMNIPRESENT, RUMOURED    },
        { OMNIPRESENT, NA, UNRETENTIVE, UNRETENTIVE },  /* outroducing DNSKEY */
        { OMNIPRESENT, NA, UNRETENTIVE, OMNIPRESENT },
        { HIDDEN     , NA, OMNIPRESENT, OMNIPRESENT }   /* unsigned state.*/
    };

    /* Once the record is introduced the policy has no influence. */
    if (next_state != RUMOURED) return 1;

    struct dbw_keystate *ks_ds = dbw_get_keystate(key, DBW_DS);
    struct dbw_keystate *ks_dnskey = dbw_get_keystate(key, DBW_DNSKEY);
    struct dbw_keystate *ks_sigkey = dbw_get_keystate(key, DBW_RRSIGDNSKEY);
    struct dbw_keystate *ks_rrsig = dbw_get_keystate(key, DBW_RRSIG);
    /* Check if policy prevents transition if the next state is rumoured.  */
    switch (type) {

    case DBW_DS:
        /* If we want to minimize the DS transitions make sure the DNSKEY is
         * fully propagated.  */
        return !(ks_ds->minimize && ks_dnskey->state != OMNIPRESENT);

    case DBW_DNSKEY:
        /* There are no restrictions for the DNSKEY transition so we can
         * just continue. */
        if (!ks_dnskey->minimize) return 1;
        /* Check that signatures has been propagated for CSK/ZSK. */
        if (key->role & DBW_ZSK) {
            if (ks_rrsig->state == OMNIPRESENT || ks_rrsig->state == NA) {
                return 1; /* RRSIG fully propagated so we will do the transitions. */
            }
        }
        /* Check if the DS is introduced and continue if it is. */
        if (key->role & DBW_KSK) {
            if (ks_ds->state == OMNIPRESENT || ks_ds->state == NA) {
                return 1;
            }
        }
        /* We might be doing an algorithm rollover so we check if there are
         * no other good KSK available and ignore the minimize flag if so. */
        return !exists(zone, key->algorithm, 1, mask[6])
            && !exists_with_successor(zone, key->algorithm, 1, mask[8], mask[7], DBW_DS)
            && !exists_with_successor(zone, key->algorithm, 1, mask[11], mask[9], DBW_DNSKEY);

    case DBW_RRSIGDNSKEY:
        /* The only time not to introduce RRSIG DNSKEY is when the DNSKEY is
         * still hidden. */
        return ks_dnskey->state != HIDDEN;

    case DBW_RRSIG:
        /* There are no restrictions for the RRSIG transition if there is no
         * need to minimize, we can just continue.  */
        if (!ks_rrsig->minimize) return 1;
        /* Check if the DNSKEY is fully introduced and continue if it is. */
        if (ks_dnskey->state == OMNIPRESENT) return 1;
        /* We might be doing an algorithm rollover so we check if there are
         * no other good ZSK available and ignore the minimize flag if so. */
        return !exists(zone, key->algorithm, 1, mask[0])
            && !exists_with_successor(zone, key->algorithm, 1, mask[2], mask[1], DBW_DNSKEY)
            && !exists_with_successor(zone, key->algorithm, 1, mask[4], mask[3], DBW_RRSIG);

    default:
        ods_log_assert(0);
    }
    ods_log_assert(0);
    return 0; /* squelch compiler */
}

/**
 * Given the zone, what TTL should be used for record?
 *
 * Normally we use the TTL from the policy. However a larger TTL might
 * have been published in the near past causing this record to take
 * extra time to propagate
 *
 * \return The TTL that should be used for the record or -1 on error.
 */
static unsigned int
getZoneTTL(struct dbw_zone *zone, int type, const time_t now)
{
    time_t end_date = 0;
    int ttl = 0;
    struct dbw_policy *policy = zone->policy;

    switch (type) {
        case DBW_DS:
            end_date = zone->ttl_end_ds;
            ttl = policy->parent_ds_ttl;
            break;
        case DBW_DNSKEY: /* Intentional fall-through */
        case DBW_RRSIGDNSKEY:
            end_date = zone->ttl_end_dk;
            ttl = policy->keys_ttl;
            break;
        case DBW_RRSIG:
            end_date = zone->ttl_end_rs;
            ttl = max(min(policy->zone_soa_ttl, policy->zone_soa_minimum),
                ( policy->denial_type == POLICY_DENIAL_TYPE_NSEC3
                    ? ( policy->denial_ttl > policy->signatures_max_zone_ttl
                        ? policy->denial_ttl
                        : policy->signatures_max_zone_ttl )
                    : policy->signatures_max_zone_ttl ));
            break;
        default:
            ods_log_assert(0);
    }

    return max((int)difftime(end_date, now), ttl);
}

static struct dbw_keystate *
getstate(struct dbw_key *key, enum dbw_keystate_type type)
{
    for (size_t s = 0; s < key->keystate_count; s++) {
        if (key->keystate[s]->type == type) return key->keystate[s];
    }
    return NULL;
}

/**
 * Find out if this key can be in a successor relationship
 *
 * return 1 if it is successable by a new key, 0 otherwise
 */
static int
isSuccessable(struct dbw_key *key, enum dbw_keystate_type type,
    enum dbw_keystate_state next_state)
{
    if (next_state != UNRETENTIVE) return 0;

    switch (type) {
        case DBW_DS:
        case DBW_RRSIG:
            return getstate(key, DBW_DNSKEY)->state == OMNIPRESENT;
        case DBW_RRSIGDNSKEY:
            return 0;
        case DBW_DNSKEY:
            return getstate(key, DBW_DS)->state == OMNIPRESENT
                || getstate(key, DBW_RRSIG)->state == OMNIPRESENT;
        default:
            ods_log_assert(0);
            return 0; /* squelch compiler */
    }
}

/**
 * Establish relationships between keys in keylist and the future_key.
 * Also remove relationships not longer relevant for future_key.
 */
void
markSuccessors(struct dbw_db *db, struct dbw_zone *zone, struct dbw_key *key,
    enum dbw_keystate_type type, enum dbw_keystate_state next_state)
{
    static const char *scmd = "markSuccessors";
    struct dbw_key *fromkey = key;

    /* If key,type in deplist and new state is omnipresent it is no
     * longer relevant for the dependencies */
    if (next_state == OMNIPRESENT) {
        for (size_t d = 0; d < fromkey->to_keydependency_count; d++) {
            struct dbw_keydependency *dep = fromkey->to_keydependency[d];
            if (type != dep->type) continue;
            dep->dirty = DBW_DELETE; /*unconditionally delete*/
            //TODO WE NEED a keydep delete func 
        }
    }

    if (!isSuccessable(key, type, next_state)) return;

    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *tokey = zone->key[k];
        if (!isPotentialSuccessor(tokey, fromkey, type))
            continue;

        /* First check we didn't already added such a dependency. */
        int exists = 0;
        for (size_t kd = 0; kd < fromkey->from_keydependency_count; kd++) {
            struct dbw_keydependency *keydep = fromkey->from_keydependency[kd];
            if (keydep->tokey_id == tokey->id && type == keydep->type) {
                exists = 1;
                break;
            }
        }
        /* From now on key will depend on futurekey.*/
        if (!exists)
            (void) dbw_new_keydependency(db, fromkey, tokey, type, zone);
    }
}

static int
has_omnipresent_dnskey(struct dbw_zone *zone)
{
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_keystate *keystate = getstate(zone->key[k], DBW_DNSKEY);
        if (!keystate) continue;
        if (keystate->state == DBW_OMNIPRESENT) return 1;
    }
    return 0;
}

static void
track_ttls(struct dbw_zone *zone, const time_t now)
{
    struct dbw_policy *policy = zone->policy;
    /*
     * This code keeps track of TTL changes. If in the past a large TTL is used,
     * our keys *may* need to transition extra careful to make sure each
     * resolver picks up the RRset. When this date passes we may start using the
     * policies TTL.
     */
    if (zone->ttl_end_ds <= now) { /*DS*/
        zone->ttl_end_ds = addtime(now, policy->parent_ds_ttl);
        dbw_mark_dirty((struct dbrow *)zone);
    }
    if (zone->ttl_end_dk <= now) { /*DNSKEY*/
        unsigned int ttl;
        if (has_omnipresent_dnskey(zone)) {
            ttl = policy->keys_ttl;
        } else {
            /* No dnskeys published yet. So consider negative caching as well. */
            ttl = max(policy->keys_ttl, min(policy->zone_soa_ttl,
                policy->zone_soa_minimum));
        }
        zone->ttl_end_dk = addtime(now, ttl);
        dbw_mark_dirty((struct dbrow *)zone);
    }
    if (zone->ttl_end_rs <= now) { /*RRSIG*/
        unsigned int ttl;
        if (policy->denial_type == POLICY_DENIAL_TYPE_NSEC3) {
            ttl = max(policy->signatures_max_zone_ttl, policy->denial_ttl);
        } else {
            ttl = policy->signatures_max_zone_ttl;
        }
        zone->ttl_end_rs = addtime(now, max(ttl,
            min(policy->zone_soa_ttl, policy->zone_soa_minimum)));
        dbw_mark_dirty((struct dbrow *)zone);
    }
}

static unsigned int
minimize(struct dbw_key *key, int type)
{
    unsigned int m = key->minimize;
    switch (type) {
        case DBW_DS:     return (m>>2)&1;
        case DBW_DNSKEY: return (m>>1)&1;
        case DBW_RRSIG:  return (m>>0)&1;
        default:         return 0;
    }
}

static unsigned int
initial_state(unsigned int type, unsigned int role)
{
    switch (type) {
        case DBW_DS:
        case DBW_RRSIGDNSKEY:
            return (DBW_KSK & role)? DBW_HIDDEN : DBW_NA;
        case DBW_DNSKEY:
            return DBW_HIDDEN;
        case DBW_RRSIG:
            return (DBW_ZSK & role)? DBW_HIDDEN : DBW_NA;
    }
    ods_log_assert(0);
    return 0; /* squelch compiler */
}

static void
generate_missing_keystates(struct dbw_db *db, struct dbw_zone *zone, time_t now)
    //TODO call from policy update instead of zoneupdate
{
    static const char *scmd = "generate_missing_keystates";
    for (size_t k = 0; k < zone->key_count; k++) {
        for (int i = DBW_DS; i <= DBW_RRSIGDNSKEY; i++) {
            struct dbw_keystate *keystate = getstate(zone->key[k], i);
            if (keystate) continue;
            keystate = calloc(1, sizeof (struct dbw_keystate));
            if (!keystate) {
                ods_log_error("[%s] %s memory allocation error", module_str, scmd);
                continue;
            }
            keystate->key_id = zone->key[k]->id;
            keystate->type = i;
            keystate->minimize = minimize(zone->key[k], i);
            /* We might consider not generating non relevant key states. */
            keystate->state = initial_state(i, zone->key[k]->role);
            keystate->last_change = now;
            keystate->ttl = getZoneTTL(zone, i, now);
            if (dbw_add_keystate(db, zone->key[k], keystate)) {
                ods_log_error("[%s] %s memory allocation error", module_str, scmd);
                continue;
            }
        }
    }
}


static int
is_ds_waiting_for_user(struct dbw_keystate *keystate, enum dbw_keystate_state next_state)
{
    if (keystate->type != DBW_DS)
        return 0;
    if (next_state == DBW_OMNIPRESENT)
        return keystate->key->ds_at_parent != DBW_DS_AT_PARENT_SEEN;
    if (next_state == DBW_HIDDEN)
        return (keystate->key->ds_at_parent != DBW_DS_AT_PARENT_UNSUBMITTED && keystate->key->ds_at_parent != DBW_DS_AT_PARENT_GONE);
    return 0;
}

/**
 * \return 1 if changes to key have been made. 0 otherwise.
 */
static int
handle_ds_at_parent(struct dbw_key *key, enum dbw_keystate_state next_state)
{
    /* If we are handling a DS we depend on the user or
     * some other external process. We must communicate
     * through the DSSeen and -submit flags. */
    if (next_state == RUMOURED) {
        /* Ask the user to submit the DS to the parent. */
        switch (key->ds_at_parent) {
            case DBW_DS_AT_PARENT_SEEN:
            case DBW_DS_AT_PARENT_SUBMIT:
            case DBW_DS_AT_PARENT_SUBMITTED:
                return 0;

            case DBW_DS_AT_PARENT_RETRACT:
                /* Hypothetical case where we reintroduce keys. */
                key->ds_at_parent = KEY_DATA_DS_AT_PARENT_SUBMITTED;
                return 1;

            default:
                key->ds_at_parent = KEY_DATA_DS_AT_PARENT_SUBMIT;
                return 1;
            }
    } else if (next_state == UNRETENTIVE) {
        /* Ask the user to remove the DS from the parent. */
        switch (key->ds_at_parent) {
            case DBW_DS_AT_PARENT_SUBMIT:
                /* Never submitted.
                 * NOTE: not safe if we support reintroducing of keys. */
                key->ds_at_parent = DBW_DS_AT_PARENT_UNSUBMITTED;
                return 1;

            case KEY_DATA_DS_AT_PARENT_UNSUBMITTED:
            case KEY_DATA_DS_AT_PARENT_GONE:
            case KEY_DATA_DS_AT_PARENT_RETRACTED:
            case KEY_DATA_DS_AT_PARENT_RETRACT:
                return 0;

            default:
                key->ds_at_parent = DBW_DS_AT_PARENT_RETRACT;
                return 1;
        }
    }
    return 0;
}

/**
 * Try to push each key for this zone to a next state. If one changes
 * visit the rest again. Loop stops when no changes can be made without
 * advance of time. Return time of first possible event.
 *
 * @param zone, zone we are processing
 * @param now, current time
 * @return first absolute time some record *could* be advanced.
 * */
static time_t
updateZone(struct dbw_db *db, struct dbw_zone *zone, const time_t now,
    int allow_unsigned, int *zone_updated)
{
    static const char *scmd = "updateZone";
    time_t returntime_zone = -1;

    struct dbw_policy *policy = zone->policy;

     ods_log_verbose("[%s] %s: processing %s with policyName %s",
         module_str, scmd, zone->name, policy->name);
    track_ttls(zone, now);
    generate_missing_keystates(db, zone, now);

    int stable = 0;
    while (!stable) {
        stable = 1;
        for (size_t k = 0; k < zone->key_count; k++) {
            struct dbw_key *key = zone->key[k];
            ods_log_verbose("[%s] %s: processing key %s %u", module_str, scmd,
                key->hsmkey->locator, key->minimize);
            for (size_t s = 0; s < key->keystate_count; s++) {
                time_t returntime_keystate;
                struct dbw_keystate *keystate = key->keystate[s];
                enum dbw_keystate_state next_state = getDesiredState(key->introducing, keystate->state, keystate);
                if (next_state == keystate->state) continue;
                if (is_ds_waiting_for_user(keystate, next_state)) continue;

                ods_log_verbose("[%s] %s: May %s %s %s in state %s transition to %s?",
                    module_str, scmd,
                    dbw_key_role_txt[key->role],
                    key->hsmkey->locator,
                    dbw_keystate_type_txt[keystate->type],
                    dbw_keystate_state_txt[keystate->state],
                    dbw_keystate_state_txt[next_state]);

                /* Check if policy prevents transition. */
                if (!policyApproval(zone, key, keystate->type, next_state)) continue;
                ods_log_verbose("[%s] %s Policy says we can (1/3)", module_str, scmd);

                /* Check if DNSSEC state prevents transition.  */
                if (!dnssecApproval(zone, key, keystate->type, next_state, allow_unsigned)) continue;
                ods_log_verbose("[%s] %s DNSSEC says we can (2/3)", module_str, scmd);

                returntime_keystate = minTransitionTime(policy, keystate->type, next_state,
                    keystate->last_change, getZoneTTL(zone, keystate->type, now));

                /* If this is an RRSIG and the DNSKEY is omnipresent and next
                 * state is a certain state, wait an additional signature
                 * lifetime to allow for 'smooth rollover'.  */
                static const enum dbw_keystate_state mask[2][4] = {
                    {NA, UNRETENTIVE, OMNIPRESENT, NA},
                    {NA, RUMOURED,    OMNIPRESENT, NA}
                };
                int zsk_out = exists(zone, key->algorithm, 1, mask[0]);
                int zsk_in  = exists(zone, key->algorithm, 1, mask[1]);

                if (keystate->type == DBW_RRSIG
                    && getstate(key, DBW_DNSKEY)->state == OMNIPRESENT
                    && ((next_state == OMNIPRESENT && zsk_out)
                        || (next_state == HIDDEN && zsk_in)))
                {
                    returntime_keystate = addtime(returntime_keystate,
                        policy->signatures_jitter
                        + max(policy->signatures_validity_default,
                            policy->signatures_validity_denial)
                        + policy->signatures_resign
                        - policy->signatures_refresh);
                }

                /* It is to soon to make this change. Schedule it. */
                if (returntime_keystate > now) {
                    minTime(returntime_keystate, &returntime_zone);
                    continue;
                }
                ods_log_verbose("[%s] %s Timing says we can (3/3) now: %lu key: %lu",
                    module_str, scmd, (unsigned long)now, (unsigned long)returntime_keystate);

                /* A record can only reach Omnipresent if properly backed up. */
                if (next_state == OMNIPRESENT
                    && (key->hsmkey->backup == HSM_KEY_BACKUP_BACKUP_REQUIRED
                    ||  key->hsmkey->backup == HSM_KEY_BACKUP_BACKUP_REQUESTED))
                {
                    ods_log_crit("[%s] %s Ready for transition but key"
                        " material not backed up yet (%s)",
                        module_str, scmd, key->hsmkey->locator);
                    /* Try again in 60 seconds */
                    returntime_keystate = addtime(now, 60);
                    minTime(returntime_keystate, &returntime_zone);
                    continue;
                }

                if (keystate->type == DBW_DS && handle_ds_at_parent(key, next_state))
                    dbw_mark_dirty((struct dbrow *)key);

                /* We've passed all tests! Make the transition. */
                ods_log_verbose("[%s] %s: Transitioning %s %s %s from %s to %s", module_str, scmd,
                    dbw_key_role_txt[key->role],
                    key->hsmkey->locator,
                    dbw_keystate_type_txt[keystate->type],
                    dbw_keystate_state_txt[keystate->state],
                    dbw_keystate_state_txt[next_state]);

                keystate->state = next_state;
                keystate->last_change = now;
                keystate->ttl = getZoneTTL(zone, keystate->type, now);
                /* we don't want DELETED or INSERTED to be marked UPDATE */
                dbw_mark_dirty((struct dbrow *)keystate);
                stable = 0; /* There have been changes. Keep processing */
                /* Let the caller know there have been changes to the zone */
                *zone_updated = 1;

                if (!zone->signconf_needs_writing) {
                    zone->signconf_needs_writing = 1;
                    dbw_mark_dirty((struct dbrow *)zone);
                }
                markSuccessors(db, zone, key, keystate->type, next_state);
            }
        }
    }
    return returntime_zone;
}

int
hsmkey_in_use_by_zone(const struct dbw_hsmkey *hsmkey, const struct dbw_zone *zone)
{
    /* a hsmkey is indirectly linked to a zone via a key */
    for (size_t k = 0; k < hsmkey->key_count; k++) {
        struct dbw_key *key = hsmkey->key[k];
        if (key->zone_id == zone->id) return 1;
    }
    return 0;
}

/**
 * Get a reusable HSMkey for this policy key. NULL of no such key exists
 */
static struct dbw_hsmkey *
getLastReusableKey(const struct dbw_zone *zone, const struct dbw_policykey *pkey)
{
    struct dbw_hsmkey *newest = NULL;
    /* We need to find the newest shareable key that matches pkey
     * and is NOT already in use by THIS zone. */
    for (size_t h = 0; h < pkey->policy->hsmkey_count; h++) {
        struct dbw_hsmkey *hkey = zone->policy->hsmkey[h];
        if (hkey->state == DBW_HSMKEY_UNUSED) continue;
        /* bitwise pkey->role implies hkey->role. We are looking for hsmkeys
         * !p|h. skip otherwise. */
        if (~hkey->role & pkey->role) continue;
        if (hsmkey_in_use_by_zone(hkey, zone)) continue;
        /** This key matches, is it newer? */
        if (!newest || newest->inception < hkey->inception) newest = hkey;
    }
    return newest;
}


static int
key_matches_pkey(const struct dbw_key *key, const struct dbw_policykey *pkey)
{
    return (pkey->role == key->role
        && !strcmp(key->hsmkey->repository, pkey->repository)
        && key->hsmkey->algorithm == pkey->algorithm
        && key->hsmkey->bits == pkey->bits);
}

/**
 * Test for the existence of key-configuration in the policy for
 * which key could have been generated.
 * 
 * \param[in] policy
 * \param[in] key key to be tested.
 * \return 1 if a matching policy exists, 0 otherwise.
 */
static int
existsPolicyForKey(const struct dbw_policy *policy, const struct dbw_key *key)
{
    static const char *scmd = "existsPolicyForKey";

    for (size_t pk = 0; pk < policy->policykey_count; pk++) {
        struct dbw_policykey *pkey = policy->policykey[pk];
        if (key_matches_pkey(key, pkey)) return 1;
    }
    return 0;
}

/**
 * Find the inception time of the most recent key for this policy.
 */
static time_t
last_inception_policy(const struct dbw_zone *zone, const struct dbw_policykey *pkey)
{
    time_t max_inception = -1;
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (!key_matches_pkey(key, pkey)) continue;
        max_inception = max(max_inception, key->inception);
    }
    return max_inception;
}

/**
 * Test for existence of a similar key.
 * 
 * \param[in] zone
 * \param[in] Role
 * \param[in] Algorithm
 * \return existence of such a key. 1 if it does
 */
static int
key_for_conf(const struct dbw_zone *zone, const struct dbw_policykey *pkey)
{
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (pkey->algorithm == key->algorithm && pkey->role == key->role)
            return 1;
    }
    return 0;
}

/**
 * Set the next roll time in the zone for the specified policy key.
 *
 * \return Zero on success, a positive value on database error and a negative
 * value on generic errors.
 */
static void
setnextroll(struct dbw_zone *zone, enum dbw_key_role role, time_t t)
{
    switch (role) {
        case DBW_KSK:
            zone->next_ksk_roll = t;
            break;
        case DBW_ZSK:
            zone->next_zsk_roll = t;
            break;
        case DBW_CSK:
            zone->next_csk_roll = t;
            break;
        default:
            ods_log_assert(0);
    }
    dbw_mark_dirty((struct dbrow *)zone);
}

static int
enforce_roll(const struct dbw_zone *zone, const struct dbw_policykey *pkey)
{
    switch(pkey->role) {
        case DBW_KSK: return zone->roll_ksk_now;
        case DBW_ZSK: return zone->roll_zsk_now;
        case DBW_CSK: return zone->roll_csk_now;
        default:
            ods_log_assert(0);
            return 0; /* squelch compiler */
    }
}

static void
set_roll(struct dbw_zone *zone, enum dbw_key_role role, int roll_flag)
{
    switch (role) {
        case DBW_KSK:
            zone->roll_ksk_now = roll_flag;
            break;
        case DBW_ZSK:
            zone->roll_zsk_now = roll_flag;
            break;
        case DBW_CSK:
            zone->roll_csk_now = roll_flag;
            break;
        default:
            ods_log_assert(0);
    }
    dbw_mark_dirty((struct dbrow *)zone);
}

static int
lifetime_too_short(struct dbw_policy *policy, struct dbw_policykey *pkey)
{
    static const char *scmd = "lifetime_too_short";
    if ((pkey->role & DBW_KSK) &&
        policy->parent_ds_ttl + policy->keys_ttl >= pkey->lifetime)
    {
        ods_log_error("[%s] %s: For policy %s %s key lifetime of %d "
            "is unreasonably short with respect to sum of parent "
            "TTL (%d) and key TTL (%d). Will not insert key!",
            module_str, scmd, policy->name, dbw_key_role_txt[pkey->role],
            pkey->lifetime, policy->parent_ds_ttl, policy->keys_ttl);
        return 1;
    }
    if ((pkey->role & DBW_ZSK) &&
        policy->signatures_max_zone_ttl + policy->keys_ttl >= pkey->lifetime)
    {
        ods_log_error("[%s] %s: For policy %s %s key lifetime of %d "
            "is unreasonably short with respect to sum of parent "
            "TTL (%d) and key TTL (%d). Will not insert key!",
            module_str, scmd, policy->name, dbw_key_role_txt[pkey->role],
            pkey->lifetime, policy->signatures_max_zone_ttl , policy->keys_ttl);
        return 1;
    }
    return 0;
}

/**
 * See what needs to be done for the policy 
 * 
 * @param policy
 * @param zone
 * @param now
 * @param[out] allow_unsigned, true when no keys are configured.
 * @return time_t
 * */
static time_t
updatePolicy(engine_type *engine, struct dbw_db *db, struct dbw_zone *zone, const time_t now, int *allow_unsigned, int *zone_updated, int mockup)
{
    static const char *scmd = "updatePolicy";
    struct dbw_policy *policy = zone->policy;
    time_t return_at = -1;

    ods_log_verbose("[%s] %s: policyName: %s", module_str, scmd, policy->name);

    /* Decommission all key data objects without any matching policy key config. */
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (!key->introducing) continue; /* already know as old */
        if (!existsPolicyForKey(policy, key)) {
            key->introducing = 0;
            dbw_mark_dirty((struct dbrow *)key);
        }
    }

    if (policy->policykey_count == 0) {
        /* If no keys are configured an unsigned zone is okay. */
        *allow_unsigned = 1;
        /* If there are no keys configured set 'signconf_needs_writing'
         * every time this function is called. Normally this is triggered by
         * updateZone. But without keys it wouldn't. */
        if (!zone->signconf_needs_writing) {
            zone->signconf_needs_writing = 1;
            *zone_updated = 1;
            dbw_mark_dirty((struct dbrow *)zone);
        }
    } else {
        *allow_unsigned = 0;
    }

    for (size_t pk = 0; pk < policy->policykey_count; pk++) {
        struct dbw_policykey *pkey = policy->policykey[pk];
        /* We force a roll when indicated by the user or when we do not have
         * any keys yet. */
        int force_roll = enforce_roll(zone, pkey) || !key_for_conf(zone, pkey);
        if (pkey->manual_rollover && !force_roll) continue;
    
        if (!force_roll) {
            /* We do not need to roll but we should check if the youngest key
             * needs to be replaced. If not we reschedule for later based on the
             * youngest key. */
            time_t inception = last_inception_policy(zone, pkey);
            time_t t_ret = addtime(inception, pkey->lifetime);
            if (inception != -1 && t_ret > now) {
                minTime(t_ret, &return_at);
                setnextroll(zone, pkey->role, t_ret);
                *zone_updated = 1;
                continue;
            }
        }
        /* Time for a new key */
        ods_log_verbose("[%s] %s: New key needed for role %s",
                module_str, scmd, dbw_key_role_txt[pkey->role]);

        /* Sanity check for unreasonable short key lifetime.
         * This would produce silly output and give the signer lots of useless
         * work to do otherwise. */
        if (lifetime_too_short(policy, pkey)) {
            setnextroll(zone, pkey->role, now);
            *zone_updated = 1;
            continue;
        }

        /* Get a new key, either a existing/shared key if the policy is set to
         * share keys or create a new key. */
        struct dbw_hsmkey *hkey = NULL;
        if (policy->keys_shared)
            hkey = getLastReusableKey(zone, pkey);
        if (!hkey) {
            if (!mockup) {
                hkey = hsm_key_factory_get_key(engine, db, pkey, zone);
            } else {
                hkey = dbw_new_hsmkey(db, policy);
                hkey->locator = strdup("[Not generated yet]");
                hkey->repository = strdup(pkey->repository);
                hkey->state = DBW_HSMKEY_PRIVATE;
                hkey->bits = pkey->bits;
                hkey->algorithm = pkey->algorithm;
                hkey->role = pkey->role;
                hkey->inception = now;
                hkey->is_revoked = 0;
                hkey->key_type = HSM_KEY_KEY_TYPE_RSA;
                hkey->backup = HSM_KEY_BACKUP_NO_BACKUP;
            }
        }
        if (!hkey) {
            /* Unable to get/create a HSM key at this time, retry later. */
            ods_log_warning("[%s] %s: No keys available in HSM for "
                "policy %s, retry in %d seconds",
                module_str, scmd, policy->name, NOKEY_TIMEOUT);
            minTime(now + NOKEY_TIMEOUT, &return_at);
            setnextroll(zone, pkey->role, now);
            *zone_updated = 1;
            continue;
        }
        ods_log_verbose("[%s] %s: got new key from HSM", module_str, scmd);

        uint16_t tag;
        /* Generate keytag for the new key and set it. */
        if (!mockup) {
            int err = hsm_keytag(hkey->locator, hkey->algorithm, hkey->role & DBW_KSK, &tag);
            if (err) {
                /* TODO: better log error */
                ods_log_error("[%s] %s: error keytag", module_str, scmd);
                hsm_key_factory_release_key(hkey, NULL);
                return now + 60;
            }
        } else {
            tag = 0xFFFF;
        }

        struct dbw_key *key = dbw_new_key(db, zone, hkey);
        if (!key) {
            ods_log_error("[%s] %s: error new key", module_str, scmd);
            if (!mockup)
                hsm_key_factory_release_key(hkey, NULL);
            return now + 60;
        }
        key->algorithm = pkey->algorithm;
        key->inception = now;
        key->role = pkey->role;
        key->minimize = pkey->minimize;
        key->introducing = 1;
        key->ds_at_parent = DBW_DS_AT_PARENT_UNSUBMITTED;
        key->keytag = tag;

        time_t t_ret = addtime(now, pkey->lifetime);
        minTime(t_ret, &return_at);
        setnextroll(zone, pkey->role, t_ret);
        *zone_updated = 1;

        /* Tell similar keys to out-troduce.
         * Similar keys are those that match role, algorithm, bits and repository
         * and are introduced.
         *
         * NOTE:
         * Will not work if a policy has 2 or more keys of the same role, algorithm,
         * bits and repository. Unclear how to fix this since keys are not directly
         * related to a policy key.
         * We currently do not allow two policy keys with the same attributes.
         */
        for (size_t k = 0; k < zone->key_count; k++) {
            struct dbw_key *oldkey = zone->key[k];
            if (!oldkey->introducing) continue; /* already know as old */
            if (!key_matches_pkey(oldkey, pkey)) continue;
            if (oldkey == key) continue;

            oldkey->introducing = 0;
            dbw_mark_dirty((struct dbrow *)oldkey);
            *zone_updated = 1;
            ods_log_verbose("[%s] %s: decommissioning old key: %s",
                module_str, scmd, oldkey->hsmkey->locator);
        }

        /* Clear roll now (if set) in the zone for this policy key. */
        if (enforce_roll(zone, pkey)) {
            set_roll(zone, pkey->role, 0);
            *zone_updated = 1;
            dbw_mark_dirty((struct dbrow *)zone);
        }
    }
    return return_at;
}

static time_t
removeDeadKeys(struct dbw_zone *zone, const time_t now, int mockup)
{
    static const char *scmd = "removeDeadKeys";
    time_t first_purge = -1;
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (key->introducing) continue;
        if (key->dirty == DBW_DELETE) continue;
        time_t key_time = -1;
        int purgable = 1;
        for (size_t s = 0; s < key->keystate_count; s++) {
            struct dbw_keystate *keystate = key->keystate[s];
            if (keystate->state == NA) continue;
            purgable &= (keystate->state == HIDDEN);
            key_time = max(key_time, keystate->last_change);
        }
        /* Add purge delay to keytime */
        if (key_time != -1)
            key_time = addtime(key_time, zone->policy->keys_purge_after);
        if (!purgable) continue; /* Eval next key */

        /* key is purgable, is it time yet? */
        if (now < key_time) {
            minTime(key_time, &first_purge);
            continue;
        }
        ods_log_info("[%s] %s deleting key: %s", module_str, scmd, key->hsmkey->locator);
        for (size_t s = 0; s < key->keystate_count; s++) {
            key->keystate[s]->dirty = DBW_DELETE;
        }
        key->dirty = DBW_DELETE;
        hsm_key_factory_release_key_mockup(key->hsmkey, key, mockup);
        /* we can clean up dependency because key is purgable */
        for (size_t d = 0; d < key->from_keydependency_count; d++) {
            key->from_keydependency[d]->dirty = DBW_DELETE;
        }
        for (size_t t = 0; t < key->to_keydependency_count; t++) {
            key->to_keydependency[t]->dirty = DBW_DELETE;
        }

        if (!zone->signconf_needs_writing) {
            zone->signconf_needs_writing = 1;
            dbw_mark_dirty((struct dbrow *)zone);
        }
    }
    return first_purge;
}

static int
set_key_flags(struct dbw_zone *zone)
{
    /* Always set these flags. Normally this needs to be done _only_ when the
     * Signer config needs writing. However a previous Signer config might not
     * be available, we have no way of telling. :(
     */
    int mod_zone = 0;
    enum dbw_keystate_state state;
    for (size_t i = 0; i < zone->key_count; i++) {
        struct dbw_key *key = zone->key[i];
        int mod_key = 0;
        int in_use;

        state = dbw_get_keystate(key, DBW_DNSKEY)->state;
        in_use = state == OMNIPRESENT || state == RUMOURED;
        if (key->publish != in_use) {
            key->publish = in_use;
            mod_key = 1;
        }
        state = dbw_get_keystate(key, DBW_RRSIGDNSKEY)->state;
        in_use = state == OMNIPRESENT || state == RUMOURED;
        if (key->active_ksk != in_use) {
            key->active_ksk = in_use;
            mod_key = 1;
        }
        state = dbw_get_keystate(key, DBW_RRSIG)->state;
        in_use = state == OMNIPRESENT || state == RUMOURED;
        if (key->active_zsk != in_use) {
            key->active_zsk = in_use;
            mod_key = 1;
        }
        if (mod_key) {
            mod_zone = 1;
            dbw_mark_dirty((struct dbrow *)key);
        }
    }
    return mod_zone;
}

static time_t
_update(engine_type *engine, struct dbw_db *db, struct dbw_zone *zone, time_t now,
    int *zone_updated, int mockup)
{
    ods_log_info("[%s] update zone: %s", module_str, zone->name);

	if (engine->config->rollover_notification && zone_db_next_ksk_roll(zone) > 0) {
		if ((time_t)zone_db_next_ksk_roll(zone) - engine->config->rollover_notification <= now
		    && (time_t)zone_db_next_ksk_roll(zone) != now) {
			time_t t = (time_t) zone_db_next_ksk_roll(zone);
			ods_log_info("[%s] KSK Rollover for zone %s is impending, "
				     "rollover will happen at %s",
				     module_str, zone_db_name(zone), ctime(&t));
		}
	}
	else if (engine->config->rollover_notification && zone_db_next_csk_roll(zone) > 0) {
		if ((time_t)zone_db_next_csk_roll(zone) - engine->config->rollover_notification <= now
		    && (time_t)zone_db_next_csk_roll(zone) != now) {
			time_t t = (time_t) zone_db_next_csk_roll(zone);
			ods_log_info("[%s] CSK Rollover for zone %s is impending, "
				     "rollover will happen at %s",
				     module_str, zone_db_name(zone), ctime(&t));
		}
	}


    /* Update policy.*/
    int allow_unsigned = 0;
    time_t policy_return_time = updatePolicy(engine, db, zone, now,
        &allow_unsigned, zone_updated, mockup);
    if (allow_unsigned) {
        ods_log_info("[%s] No keys configured for %s, zone will become"
           " unsigned eventually", module_str, zone->name);
    }

    /* Update zone.*/
    time_t zone_return_time = updateZone(db, zone, now, allow_unsigned, zone_updated);

    /*Only purge old keys if the policy says so.*/
    time_t purge_return_time = -1;
    if (zone->policy->keys_purge_after) {
        purge_return_time = removeDeadKeys(zone, now, mockup);
    }

    if (set_key_flags(zone)) { /* active and publish flags in signconf */
        *zone_updated = 1;
    }

    /* Of all the relevant times find the earliest*/
    time_t return_time = zone_return_time;
    minTime(policy_return_time, &return_time);
    /*
     * Take the rollover notification time into account when scheduling
     * this zone. We will need to print a message at that time.
     */
    if (zone->next_ksk_roll > 0
            && (zone->next_ksk_roll - engine->config->rollover_notification > now))
    {
        minTime(zone->next_ksk_roll - engine->config->rollover_notification, &return_time);
    } else if (zone->next_csk_roll > 0
             && (zone->next_csk_roll - engine->config->rollover_notification > now))
    {
        minTime(zone->next_csk_roll - engine->config->rollover_notification, &return_time);
    }

    minTime(purge_return_time, &return_time);
    return return_time;
}

time_t
update(engine_type *engine, struct dbw_db *db, struct dbw_zone *zone, time_t now,
    int *zone_updated)
{
    return _update(engine, db, zone, now, zone_updated, 0);
}

time_t
update_mockup(engine_type *engine, struct dbw_db *db, struct dbw_zone *zone, time_t now,
    int *zone_updated)
{
    return _update(engine, db, zone, now, zone_updated, 1);
}
