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

#include "db/zone_db.h"
#include "db/policy.h"
#include "db/policy_key.h"
#include "db/hsm_key.h"
#include "db/key_data.h"
#include "db/key_dependency.h"
#include "db/db_error.h"

#include "enforcer/enforcer.h"

#define HIDDEN      KEY_STATE_STATE_HIDDEN
#define RUMOURED    KEY_STATE_STATE_RUMOURED
#define OMNIPRESENT KEY_STATE_STATE_OMNIPRESENT
#define UNRETENTIVE KEY_STATE_STATE_UNRETENTIVE
#define NA          KEY_STATE_STATE_NA

static const char *module_str = "enforcer";

/** When no key available wait this many seconds before asking again. */
#define NOKEY_TIMEOUT 60

struct future_key {
    key_data_t* key;
    key_state_type_t type;
    key_state_state_t next_state;
    int pretend_update;
};

static int max(int a, int b) { return a>b?a:b; }
static int min(int a, int b) { return a<b?a:b; }

/**
 * Stores the minimum of parm1 and parm2 in parm2.
 * 
 * Stores smallest of two times in min. Avoiding negative values,
 * which mean no update necessary. Any other time in the past: ASAP.
 * 
 * \param t[in], some time to test
 * \param min[in,out], smallest of t and min.
 * */
static inline void
minTime(const time_t t, time_t* min)
{
	assert(min); /* TODO: proper error */
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
 * */
static time_t
addtime(const time_t t, const int seconds)
{
	struct tm *tp = localtime(&t);
	if (!tp) return -1; /* bad, but mktime also returns -1 on error */
	tp->tm_sec += seconds;
	return mktime(tp);
}

/**
 * Retrieve the key_state object from one of the records of a key.
 *
 * \return a key_state_t pointer or NULL on error or if the type specified is
 * invalid.
 */
static inline const key_state_t*
getRecord(key_data_t* key, key_state_type_t type)
{
    if (!key) {
        return NULL;
    }

    switch (type) {
    case KEY_STATE_TYPE_DS:
        return key_data_cached_ds(key);

    case KEY_STATE_TYPE_DNSKEY:
        return key_data_cached_dnskey(key);

    case KEY_STATE_TYPE_RRSIG:
        return key_data_cached_rrsig(key);

    case KEY_STATE_TYPE_RRSIGDNSKEY:
        return key_data_cached_rrsigdnskey(key);

    default:
        break;
    }

    return NULL;
}

/**
 * Return state of a record.
 *
 * \return a key_state_state_t which will be KEY_STATE_STATE_INVALID on error.
 */
static inline key_state_state_t
getState(key_data_t* key, key_state_type_t type, struct future_key *future_key)
{
    int cmp;

    if (!key) {
        return KEY_STATE_STATE_INVALID;
    }

    if (future_key
        && future_key->pretend_update
        && future_key->type == type
        && future_key->key)
    {
        if (db_value_cmp(key_data_id(key), key_data_id(future_key->key), &cmp)) {
            return KEY_STATE_STATE_INVALID;
        }
        if (!cmp) {
            return future_key->next_state;
        }
    }

    return key_state_state(getRecord(key, type));
}

/**
 * Given goal and state, what will be the next state?
 *
 * This is an implementation of our state diagram. State indicates
 * our current node and goal helps decide which edge to choose.
 * Input state and return state me be the same: the record is said
 * to be stable.
 *
 * \return a key_state_state_t for the next state which will be
 * KEY_STATE_STATE_INVALID on error.
 */
static key_state_state_t
getDesiredState(int introducing, key_state_state_t state)
{
    /*
     * Given goal and state, what will be the next state?
     */
    if (!introducing) {
        /*
         * We are outroducing this key so we would like to move rumoured and
         * omnipresent keys to unretentive and unretentive keys to hidden.
         */
        switch (state) {
        case HIDDEN:
            break;

        case RUMOURED:
            state = UNRETENTIVE;
            break;

        case OMNIPRESENT:
            state = UNRETENTIVE;
            break;

        case UNRETENTIVE:
            state = HIDDEN;
            break;

        case NA:
            break;

        default:
            state = KEY_STATE_STATE_INVALID;
            break;
        }
    }
    else {
        /*
         * We are introducing this key so we would like to move hidden and
         * unretentive keys to rumoured and rumoured keys to omnipresent.
         */
        switch (state) {
        case HIDDEN:
            state = RUMOURED;
            break;

        case RUMOURED:
            state = OMNIPRESENT;
            break;

        case OMNIPRESENT:
            break;

        case UNRETENTIVE:
            state = RUMOURED;
            break;

        case NA:
            break;

        default:
            state = KEY_STATE_STATE_INVALID;
            break;
        }
    }

    return state;
}

/**
 * Test if a key matches specific states.
 *
 * \return A positive value if the key match, zero if a key does not match and
 * a negative value if an error occurred.
 */
static int
match(key_data_t* key, struct future_key *future_key, int same_algorithm,
    const key_state_state_t mask[4])
{
    if (!key) {
        return -1;
    }
    if (!future_key) {
        return -1;
    }
    if (!future_key->key) {
        return -1;
    }

    if (same_algorithm
        && key_data_algorithm(key) != key_data_algorithm(future_key->key))
    {
        return 0;
    }

    /*
     * Check the states against the mask, for each mask that is not NA we
     * need a match on that key state.
     */
    if ((mask[0] != NA
            && getState(key, KEY_STATE_TYPE_DS, future_key) != mask[0])
        || (mask[1] != NA
            && getState(key, KEY_STATE_TYPE_DNSKEY, future_key) != mask[1])
        || (mask[2] != NA
            && getState(key, KEY_STATE_TYPE_RRSIGDNSKEY, future_key) != mask[2])
        || (mask[3] != NA
            && getState(key, KEY_STATE_TYPE_RRSIG, future_key) != mask[3]))
    {
        return 0;
    }
    return 1;
}

/**
 * Test if a key exist with certain states.
 *
 * \return A positive value if a key exists, zero if a key does not exists and
 * a negative value if an error occurred.
 */
static int
exists(key_data_t** keylist, size_t keylist_size, struct future_key *future_key,
	int same_algorithm, const key_state_state_t mask[4])
{
    size_t i;
    if (!keylist || !future_key || !future_key->key)
        return -1;
    /* Check the states against the mask. If we have a match we return a
    * positive value. */
    for (i = 0; i < keylist_size; i++) {
        if (match(keylist[i], future_key, same_algorithm, mask) > 0)
            return 1;
    }
    return 0; /* We've got no match. */
}

/**
 * Test if a key is a potential successor.
 *
 * \return A positive value if a key is a potential successor, zero if a key
 * is not and a negative value if an error occurred.
 */
static int
isPotentialSuccessor(key_data_t* successor_key, key_data_t* predecessor_key,
    struct future_key *future_key, key_state_type_t type)
{
    if (!successor_key || !predecessor_key || !future_key)
        return -1;

    /* You can't be a successor of yourself */
    if (!key_data_cmp(successor_key, predecessor_key)) return 0;

    /*
     * TODO
     */
    if (getState(successor_key, type, future_key) != RUMOURED
        || key_data_algorithm(successor_key) != key_data_algorithm(predecessor_key))
    {
        return 0;
    }

    /*
     * TODO
     */
    switch (type) {
    case KEY_STATE_TYPE_DS: /* Intentional fall-through */
    case KEY_STATE_TYPE_RRSIG:
        /*
         * TODO
         */
        if (getState(successor_key, KEY_STATE_TYPE_DNSKEY, future_key) == OMNIPRESENT) {
            return 1;
        }
        break;

    case KEY_STATE_TYPE_DNSKEY:
        /*
         * Either both DS's should be omnipresent or both signatures, for the
         * keys to be in a potential relationship for the DNSKEY.
         */
        if ((getState(predecessor_key, KEY_STATE_TYPE_DS, future_key) == OMNIPRESENT
                && getState(successor_key, KEY_STATE_TYPE_DS, future_key) == OMNIPRESENT)
            || (getState(predecessor_key, KEY_STATE_TYPE_RRSIG, future_key) == OMNIPRESENT
                && getState(successor_key, KEY_STATE_TYPE_RRSIG, future_key) == OMNIPRESENT))
        {
            return 1;
        }
        break;

    case KEY_STATE_TYPE_RRSIGDNSKEY:
        /*
         * TODO
         */
        break;

    default:
        return -1;
    }

    return 0;
}

/**
 * Test if a key record is a successor.
 *
 * \return A positive value if a key record is a successor, zero if a key is not
 * and a negative value if an error occurred.
 */
static int
successor_rec(key_data_t** keylist, size_t keylist_size,
    key_data_t* successor_key, key_data_t* predecessor_key,
    struct future_key *future_key,
    key_state_type_t type, key_dependency_list_t* deplist_ext)
{
    size_t i;
    int cmp;
    const key_dependency_t* dep;
    key_data_t *from_key;
    key_dependency_list_t* deplist;

    if (!keylist) {
        return -1;
    }
    if (!successor_key) {
        return -1;
    }
    if (!predecessor_key) {
        return -1;
    }
    if (!future_key) {
        return -1;
    }
    if (!future_key->key) {
        return -1;
    }
    if (!deplist_ext) {
        return -1;
    }

    /*
     * Make a copy of the deplist in order to preserve where we are in the list
     * if we are calling ourselves later on.
     *
     * TODO: This can be optimized with the implementation of *_list_ref_t or
     * allocating an array as with keylist.
     */
    if (!(deplist = key_dependency_list_new_copy(deplist_ext))) {
        return -1;
    }

    /*
     * Check the trivial case where the predecessor key is already a predecessor
     * for the successor key.
     */
    for (dep = key_dependency_list_begin(deplist); dep; dep = key_dependency_list_next(deplist)) {
        switch (key_dependency_type(dep)) {
        case KEY_DEPENDENCY_TYPE_DS:
            if (type != KEY_STATE_TYPE_DS) {
                continue;
            }
            break;

        case KEY_DEPENDENCY_TYPE_RRSIG:
            if (type != KEY_STATE_TYPE_RRSIG) {
                continue;
            }
            break;

        case KEY_DEPENDENCY_TYPE_DNSKEY:
            if (type != KEY_STATE_TYPE_DNSKEY) {
                continue;
            }
            break;

        case KEY_DEPENDENCY_TYPE_RRSIGDNSKEY:
            if (type != KEY_STATE_TYPE_RRSIGDNSKEY) {
                continue;
            }
            break;

        default:
            continue;
        }

        if (db_value_cmp(key_data_id(predecessor_key), key_dependency_from_key_data_id(dep), &cmp)) {
            key_dependency_list_free(deplist);
            return -1;
        }
        if (cmp) {
            continue;
        }

        if (db_value_cmp(key_data_id(successor_key), key_dependency_to_key_data_id(dep), &cmp)) {
            key_dependency_list_free(deplist);
            return -1;
        }
        if (cmp) {
            continue;
        }

        key_dependency_list_free(deplist);
        return 1;
    }

    /*
     * Check the trivial case where there is a direct relationship in the future
     */
    if (future_key->pretend_update) {
        if (db_value_cmp(key_data_id(future_key->key), key_data_id(predecessor_key), &cmp)) {
            key_dependency_list_free(deplist);
            return -1;
        }
        if (!cmp && isPotentialSuccessor(successor_key, predecessor_key, future_key, type) > 0) {
            key_dependency_list_free(deplist);
            return 1;
        }
    }

    /*
     * Check for indirect relationship where X depends on S and X is in the same
     * state as P and X is a successor of P.
     */
    for (dep = key_dependency_list_begin(deplist); dep; dep = key_dependency_list_next(deplist)) {
        switch (key_dependency_type(dep)) {
        case KEY_DEPENDENCY_TYPE_DS:
            if (type != KEY_STATE_TYPE_DS) {
                continue;
            }
            break;

        case KEY_DEPENDENCY_TYPE_RRSIG:
            if (type != KEY_STATE_TYPE_RRSIG) {
                continue;
            }
            break;

        case KEY_DEPENDENCY_TYPE_DNSKEY:
            if (type != KEY_STATE_TYPE_DNSKEY) {
                continue;
            }
            break;

        case KEY_DEPENDENCY_TYPE_RRSIGDNSKEY:
            if (type != KEY_STATE_TYPE_RRSIGDNSKEY) {
                continue;
            }
            break;

        default:
            continue;
        }

        if (db_value_cmp(key_data_id(successor_key), key_dependency_to_key_data_id(dep), &cmp)) {
            key_dependency_list_free(deplist);
            return -1;
        }
        if (cmp) {
            continue;
        }

        /*
         * TODO: This may be optimized by searching for the key in the keylist
         * first, only retrieving it from the database if needed or giving an
         * error if it does not exist in the keylist.
         */
        if (!(from_key = key_dependency_get_from_key_data(dep))) {
            key_dependency_list_free(deplist);
            return -1;
        }

        /*
         * The RRSIGDNSKEY is not compared because TODO .
         */
        if (getState(predecessor_key, KEY_STATE_TYPE_DS, future_key) != getState(from_key, KEY_STATE_TYPE_DS, future_key)
            || getState(predecessor_key, KEY_STATE_TYPE_DNSKEY, future_key) != getState(from_key, KEY_STATE_TYPE_DNSKEY, future_key)
            || getState(predecessor_key, KEY_STATE_TYPE_RRSIG, future_key) != getState(from_key, KEY_STATE_TYPE_RRSIG, future_key))
        {
            key_data_free(from_key);
            continue;
        }
        if (successor_rec(keylist, keylist_size, from_key, predecessor_key, future_key, type, deplist_ext) > 0) {
            key_data_free(from_key);
            key_dependency_list_free(deplist);
            return 1;
        }
        key_data_free(from_key);
    }
    key_dependency_list_free(deplist);

    /*
     * TODO
     */
    if (future_key->pretend_update) {
        for (i = 0; i < keylist_size; i++) {
            if (db_value_cmp(key_data_id(predecessor_key), key_data_id(keylist[i]), &cmp)) {
                return -1;
            }
            if (!cmp) {
                continue;
            }

            if (isPotentialSuccessor(successor_key, keylist[i], future_key, type) > 0) {
                /*
                 * The RRSIGDNSKEY is not compared because TODO .
                 */
                if (getState(predecessor_key, KEY_STATE_TYPE_DS, future_key) != getState(keylist[i], KEY_STATE_TYPE_DS, future_key)
                    || getState(predecessor_key, KEY_STATE_TYPE_DNSKEY, future_key) != getState(keylist[i], KEY_STATE_TYPE_DNSKEY, future_key)
                    || getState(predecessor_key, KEY_STATE_TYPE_RRSIG, future_key) != getState(keylist[i], KEY_STATE_TYPE_RRSIG, future_key))
                {
                    continue;
                }
                if (successor_rec(keylist+1, keylist_size-1, successor_key, keylist[i], future_key, type, deplist_ext) > 0) {
                    return 1;
                }
            }
        }
    }

    return 0;
}

/**
 * Test if a key is a successor.
 *
 * \return A positive value if a key is a successor, zero if a key is not and a
 * negative value if an error occurred.
 */
static int
successor(key_data_t** keylist, size_t keylist_size, key_data_t* successor_key,
    key_data_t* predecessor_key, struct future_key *future_key,
    key_state_type_t type, key_dependency_list_t* deplist)
{
    int cmp;
    const key_dependency_t* dep;

    if (!keylist) {
        return -1;
    }
    if (!successor_key) {
        return -1;
    }
    if (!predecessor_key) {
        return -1;
    }
    if (!future_key) {
        return -1;
    }
    if (!future_key->key) {
        return -1;
    }
    if (!deplist) {
        return -1;
    }

    /*
     * Nothing may depend on our predecessor.
     */
    for (dep = key_dependency_list_begin(deplist); dep; dep = key_dependency_list_next(deplist)) {
        if (db_value_cmp(key_data_id(predecessor_key), key_dependency_to_key_data_id(dep), &cmp)) {
            return -1;
        }
        if (!cmp) {
            return 0;
        }
    }
    return successor_rec(keylist, keylist_size, successor_key, predecessor_key, future_key, type, deplist);
}

/**
 * TODO
 *
 * \return A positive value if a key exists, zero if a key does not exists and
 * a negative value if an error occurred.
 */
static int
exists_with_successor(key_data_t** keylist, size_t keylist_size,
    struct future_key *future_key, int same_algorithm,
    const key_state_state_t predecessor_mask[4],
    const key_state_state_t successor_mask[4], key_state_type_t type,
    key_dependency_list_t* deplist)
{
    size_t i, j;

    if (!keylist) {
        return -1;
    }
    if (!future_key) {
        return -1;
    }

    /*
     * Walk the list of keys, for each key that matches the successor mask we
     * walk the list again and check that key against the keys that match the
     * predecessor mask if has a valid successor/predecessor relationship.
     */
    for (i = 0; i < keylist_size; i++) {
        if (match(keylist[i], future_key, same_algorithm, successor_mask) < 1) {
            continue;
        }

        for (j = 0; j < keylist_size; j++) {
            if (j == i
                || match(keylist[j], future_key, same_algorithm, predecessor_mask) < 1)
            {
                continue;
            }

            if (successor(keylist, keylist_size, keylist[i], keylist[j], future_key, type, deplist) > 0) {
                return 1;
            }
        }
    }
    return 0;
}

/**
 * Test if keys are in a good unsigned state.
 *
 * \return A positive value if keys are in a good unsigned state, zero if keys
 * are not and a negative value if an error occurred.
 */
static int
unsignedOk(key_data_t** keylist, size_t keylist_size,
    struct future_key *future_key,
    const key_state_state_t mask[4], key_state_type_t type)
{
    size_t i;
    key_state_state_t cmp_mask[4];

    if (!keylist) {
        return -1;
    }
    if (!future_key) {
        return -1;
    }
    if (!future_key->key) {
        return -1;
    }

    for (i = 0; i < keylist_size; i++) {
        if (key_data_algorithm(keylist[i]) != key_data_algorithm(future_key->key)) {
            continue;
        }

        cmp_mask[0] = type == KEY_STATE_TYPE_DS
            ? getState(keylist[i], type, future_key)
            : mask[0];
        cmp_mask[1] = type == KEY_STATE_TYPE_DNSKEY
            ? getState(keylist[i], type, future_key)
            : mask[1];
        cmp_mask[2] = type == KEY_STATE_TYPE_RRSIGDNSKEY
            ? getState(keylist[i], type, future_key)
            : mask[2];
        cmp_mask[3] = type == KEY_STATE_TYPE_RRSIG
            ? getState(keylist[i], type, future_key)
            : mask[3];

        /*
         * If the state is hidden or NA for the given type this key is okay.
         */
        switch (type) {
        case KEY_STATE_TYPE_DS:
            if (cmp_mask[0] == HIDDEN || cmp_mask[0] == NA) {
                continue;
            }
            break;

        case KEY_STATE_TYPE_DNSKEY:
            if (cmp_mask[1] == HIDDEN || cmp_mask[1] == NA) {
                continue;
            }
            break;

        case KEY_STATE_TYPE_RRSIGDNSKEY:
            if (cmp_mask[2] == HIDDEN || cmp_mask[2] == NA) {
                continue;
            }
            break;

        case KEY_STATE_TYPE_RRSIG:
            if (cmp_mask[3] == HIDDEN || cmp_mask[3] == NA) {
                continue;
            }
            break;

        default:
            return -1;
        }

        if (exists(keylist, keylist_size, future_key, 1, cmp_mask) < 1) {
            return 0;
        }
    }

    return 1;
}

/* Check if ALL DS records for this algorithm are hidden
 *
 * \return 0 if !HIDDEN DS is found, 1 if no such DS where found */
static int
all_DS_hidden(key_data_t** keylist, size_t keylist_size,
    struct future_key *future_key)
{
    size_t i;
    key_state_state_t state;

    assert(keylist);
    assert(future_key);
    assert(future_key->key);

    for (i = 0; i < keylist_size; i++) {
        /*If not same algorithm. Doesn't affect us.*/
        if (key_data_algorithm(keylist[i]) != key_data_algorithm(future_key->key)) continue;
        state = getState(keylist[i], KEY_STATE_TYPE_DS, future_key);
        if (state != HIDDEN && state != NA) return 0; /*Test failed. Found DS.*/
    }
    return 1; /*No DS where found.*/
}

/**
 * Checks for existence of DS.
 *
 * \return A positive value if the rule applies, zero if the rule does not
 * apply and a negative value if an error occurred.
 */
static int
rule1(key_data_t** keylist, size_t keylist_size, struct future_key *future_key,
    int pretend_update)
{
    static const key_state_state_t mask[2][4] = {
        { OMNIPRESENT, NA, NA, NA },/* a good key state.  */
        { RUMOURED,    NA, NA, NA } /* the DS is introducing.  */
    };

    if (!keylist || !future_key || !future_key->key) {
        return -1;
    }

    future_key->pretend_update = pretend_update;

    /* Return positive value if any of the masks are found.  */
    return (exists(keylist, keylist_size, future_key, 0, mask[0]) > 0
        || exists(keylist, keylist_size, future_key, 0, mask[1]) > 0);
}

/**
 * Checks for a valid DNSKEY situation.
 *
 * \return A positive value if the rule applies, zero if the rule does not
 * apply and a negative value if an error occurred.
 */
static int
rule2(key_data_t** keylist, size_t keylist_size, struct future_key *future_key,
    int pretend_update, key_dependency_list_t* deplist)
{
    static const key_state_state_t mask[8][4] = {
        { OMNIPRESENT, OMNIPRESENT, OMNIPRESENT, NA },/*good key state.*/
        { RUMOURED,    OMNIPRESENT, OMNIPRESENT, NA },/*introducing DS state.*/
        { UNRETENTIVE, OMNIPRESENT, OMNIPRESENT, NA },/*outroducing DS state.*/
        { OMNIPRESENT, RUMOURED,    RUMOURED,    NA },/*introducing DNSKEY state.*/
        { OMNIPRESENT, OMNIPRESENT, RUMOURED,    NA },
        { OMNIPRESENT, UNRETENTIVE, UNRETENTIVE, NA },/*outroducing DNSKEY state.*/
        { OMNIPRESENT, UNRETENTIVE, OMNIPRESENT, NA },
        { HIDDEN,      OMNIPRESENT, OMNIPRESENT, NA } /*unsigned state.*/
    };

    if (!keylist || !future_key || !future_key->key) {
        return -1;
    }

    future_key->pretend_update = pretend_update;

    /* Return positive value if any of the masks are found.  */
    return (exists(keylist, keylist_size, future_key, 1, mask[0]) > 0
        || exists_with_successor(keylist, keylist_size, future_key, 1, mask[2], mask[1], KEY_STATE_TYPE_DS, deplist) > 0
        || exists_with_successor(keylist, keylist_size, future_key, 1, mask[5], mask[3], KEY_STATE_TYPE_DNSKEY, deplist) > 0
        || exists_with_successor(keylist, keylist_size, future_key, 1, mask[5], mask[4], KEY_STATE_TYPE_DNSKEY, deplist) > 0
        || exists_with_successor(keylist, keylist_size, future_key, 1, mask[6], mask[3], KEY_STATE_TYPE_DNSKEY, deplist) > 0
        || exists_with_successor(keylist, keylist_size, future_key, 1, mask[6], mask[4], KEY_STATE_TYPE_DNSKEY, deplist) > 0
        || unsignedOk(keylist, keylist_size, future_key, mask[7], KEY_STATE_TYPE_DS) > 0);
}

/**
 * Checks for a valid signature situation.
 *
 * \return A positive value if the rule applies, zero if the rule does not
 * apply and a negative value if an error occurred.
 */
static int
rule3(key_data_t** keylist, size_t keylist_size, struct future_key *future_key,
    int pretend_update, key_dependency_list_t* deplist)
{
    static const key_state_state_t mask[6][4] = {
        { NA, OMNIPRESENT, NA, OMNIPRESENT },/* good key state. */
        { NA, RUMOURED,    NA, OMNIPRESENT },/* introducing DNSKEY state. */
        { NA, UNRETENTIVE, NA, OMNIPRESENT },/* outroducing DNSKEY state. */
        { NA, OMNIPRESENT, NA, RUMOURED    },/* introducing RRSIG state. */
        { NA, OMNIPRESENT, NA, UNRETENTIVE },/* outroducing RRSIG state. */
        { NA, HIDDEN,      NA, OMNIPRESENT } /* unsigned state. */
    };

    if (!keylist || !future_key || !future_key->key) {
        return -1;
    }

    future_key->pretend_update = pretend_update;

    /* Return positive value if any of the masks are found. */
    return (exists(keylist, keylist_size, future_key, 1, mask[0]) > 0
        || exists_with_successor(keylist, keylist_size, future_key, 1, mask[2], mask[1], KEY_STATE_TYPE_DNSKEY, deplist) > 0
        || exists_with_successor(keylist, keylist_size, future_key, 1, mask[4], mask[3], KEY_STATE_TYPE_RRSIG, deplist) > 0
        || unsignedOk(keylist, keylist_size, future_key, mask[5], KEY_STATE_TYPE_DNSKEY) > 0
        || all_DS_hidden(keylist, keylist_size, future_key) > 0);
}

/**
 * Checks if transition to next_state maintains validity of zone.
 *
 * \return A positive value if the transition is allowed, zero if it is not and
 * a negative value if an error occurred.
 */
static int
dnssecApproval(key_data_t** keylist, size_t keylist_size,
    struct future_key* future_key, int allow_unsigned,
    key_dependency_list_t* deplist)
{
    if (!keylist) {
        return -1;
    }
    if (!future_key) {
        return -1;
    }
    if (!deplist) {
        return -1;
    }

    /*
     * Check if DNSSEC state will be invalid by the transition by checking that
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
    if ((allow_unsigned
            || !rule1(keylist, keylist_size, future_key, 0)
            || rule1(keylist, keylist_size, future_key, 1) > 0)
        && (!rule2(keylist, keylist_size, future_key, 0, deplist)
            || rule2(keylist, keylist_size, future_key, 1, deplist) > 0)
        && (!rule3(keylist, keylist_size, future_key, 0, deplist)
            || rule3(keylist, keylist_size, future_key, 1, deplist) > 0))
    {
        /*
         * All rules apply, we allow transition.
         */
        return 1;
    }

    return 0;
}

/**
 * At what time may this transition take place?
 *
 * Given a record, its next state, and its last change time when may
 * apply the transition? This is largely policy related.
 *
 * return a time_t with the absolute time or -1 on error.
 */
static time_t
minTransitionTime(policy_t const *policy, key_state_type_t type,
    key_state_state_t next_state, const time_t lastchange, const int ttl)
{
    if (!policy) {
        return -1;
    }

    /*
     * We may freely move a record to a uncertain state.
     */
    if (next_state == RUMOURED || next_state == UNRETENTIVE) {
        return lastchange;
    }

    switch (type) {
    case KEY_STATE_TYPE_DS:
        return addtime(lastchange, ttl
            + policy_parent_registration_delay(policy)
            + policy_parent_propagation_delay(policy));

    /* TODO: 5011 will create special case here */
    case KEY_STATE_TYPE_DNSKEY: /* intentional fall-through */
    case KEY_STATE_TYPE_RRSIGDNSKEY:
        return addtime(lastchange, ttl
            + policy_zone_propagation_delay(policy)
            + ( next_state == OMNIPRESENT
                ? policy_keys_publish_safety(policy)
                : policy_keys_retire_safety(policy) ));

    case KEY_STATE_TYPE_RRSIG:
        return addtime(lastchange, ttl
            + policy_zone_propagation_delay(policy));

    default:
        break;
    }

    return -1;
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
policyApproval(key_data_t** keylist, size_t keylist_size,
    struct future_key* future_key, key_dependency_list_t* deplist)
{
    static const key_state_state_t dnskey_algorithm_rollover[4] = { OMNIPRESENT, OMNIPRESENT, OMNIPRESENT, NA };
    static const key_state_state_t mask[14][4] = {
        /*ZSK*/
        { NA, OMNIPRESENT, NA, OMNIPRESENT },   /*This indicates a good key state.*/
        { NA, RUMOURED,    NA, OMNIPRESENT },   /*This indicates a introducing DNSKEY state.*/
        { NA, UNRETENTIVE, NA, OMNIPRESENT },   /*This indicates a outroducing DNSKEY state.*/
        { NA, OMNIPRESENT, NA, RUMOURED },      /*This indicates a introducing RRSIG state.*/
        { NA, OMNIPRESENT, NA, UNRETENTIVE },   /*This indicates a outroducing RRSIG state.*/
        { NA, HIDDEN,      NA, OMNIPRESENT },   /*This indicates an unsigned state.*/

        /*KSK*/
        { OMNIPRESENT, OMNIPRESENT, OMNIPRESENT, NA },  /*This indicates a good key state.*/
        { RUMOURED,    OMNIPRESENT, OMNIPRESENT, NA },  /*This indicates an introducing DS state.*/
        { UNRETENTIVE, OMNIPRESENT, OMNIPRESENT, NA },  /*This indicates an outroducing DS state.*/
        { OMNIPRESENT, RUMOURED,    RUMOURED,    NA },  /*These indicates an introducing DNSKEY state.*/
        { OMNIPRESENT, OMNIPRESENT, RUMOURED,    NA },
        { OMNIPRESENT, UNRETENTIVE, UNRETENTIVE, NA },  /*These indicates an outroducing DNSKEY state.*/
        { OMNIPRESENT, UNRETENTIVE, OMNIPRESENT, NA },
        { HIDDEN,      OMNIPRESENT, OMNIPRESENT, NA }   /*This indicates an unsigned state.*/
    };
    
    if (!keylist || !future_key || !future_key->key) {
        return -1;
    }

    /*
     * Once the record is introduced the policy has no influence.
     */
    if (future_key->next_state != RUMOURED) {
        return 1;
    }

    /*
     * Check if policy prevents transition if the next state is rumoured.
     */
    switch (future_key->type) {
    case KEY_STATE_TYPE_DS:
        /*
         * If we want to minimize the DS transitions make sure the DNSKEY is
         * fully propagated.
         */
        if (key_state_minimize(key_data_cached_ds(future_key->key))
            && key_state_state(key_data_cached_dnskey(future_key->key)) != OMNIPRESENT)
        {
            /*
             * DNSKEY is not fully propagated so we will not do any transitions.
             */
            return 0;
        }
        break;

    case KEY_STATE_TYPE_DNSKEY:
        if (!key_state_minimize(key_data_cached_dnskey(future_key->key))) {
            /* There are no restrictions for the DNSKEY transition so we can
             * just continue. */
            return 1;
        }
        /* Check that signatures has been propagated for CSK/ZSK. */
        if (key_data_role(future_key->key) & KEY_DATA_ROLE_ZSK ) {
            if (key_state_state(key_data_cached_rrsig(future_key->key)) == OMNIPRESENT
                || key_state_state(key_data_cached_rrsig(future_key->key)) == NA)
            {
                /* RRSIG fully propagated so we will do the transitions. */
                return 1;
            }
        }
        /* Check if the DS is introduced and continue if it is. */
        if (key_data_role(future_key->key) & KEY_DATA_ROLE_KSK ) {
            if (key_state_state(key_data_cached_ds(future_key->key)) == OMNIPRESENT
                || key_state_state(key_data_cached_ds(future_key->key)) == NA)
            {
                return 1;
            }
        }
        /* We might be doing an algorithm rollover so we check if there are
         * no other good KSK available and ignore the minimize flag if so. */
        return !(exists(keylist, keylist_size, future_key, 1, mask[6]) > 0
            || exists_with_successor(keylist, keylist_size, future_key, 1, mask[8], mask[7], KEY_STATE_TYPE_DS, deplist) > 0
            || exists_with_successor(keylist, keylist_size, future_key, 1, mask[11], mask[9], KEY_STATE_TYPE_DNSKEY, deplist) > 0);

    case KEY_STATE_TYPE_RRSIGDNSKEY:
        /*
         * The only time not to introduce RRSIG DNSKEY is when the DNSKEY is
         * still hidden.
         *
         * TODO: How do we know we are introducing the RRSIG DNSKEY? We might be
         * outroducing it.
         */
        if (key_state_state(key_data_cached_dnskey(future_key->key)) == HIDDEN) {
            return 0;
        }
        break;

    case KEY_STATE_TYPE_RRSIG:
        if (!key_state_minimize(key_data_cached_rrsig(future_key->key))) {
            /*
             * There are no restrictions for the RRSIG transition so we can
             * just continue.
             */
            break;
        }

        /*
         * Check if the DNSKEY is introduced and continue if it is.
         */
        if (key_state_state(key_data_cached_dnskey(future_key->key)) == OMNIPRESENT) {
            break;
        }

        /*
         * We might be doing an algorithm rollover so we check if there are
         * no other good ZSK available and ignore the minimize flag if so.
         *
         * TODO: How is this related to ZSK/CSK? There are no check for key_data_role().
         */
        if (exists(keylist, keylist_size, future_key, 1, mask[0]) > 0
            || exists_with_successor(keylist, keylist_size, future_key, 1, mask[2], mask[1], KEY_STATE_TYPE_DNSKEY, deplist) > 0
            || exists_with_successor(keylist, keylist_size, future_key, 1, mask[4], mask[3], KEY_STATE_TYPE_RRSIG, deplist) > 0
            )
        {
            /*
             * We found a good key, so we will not do any transition.
             */
            return 0;
        }
        break;

    default:
        return 0;
    }

    return 1;
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
static int
getZoneTTL(policy_t const *policy, zone_db_t* zone, key_state_type_t type,
    const time_t now)
{
    time_t end_date;
    int ttl;

    if (!policy) {
        return -1;
    }
    if (!zone) {
        return -1;
    }

    switch (type) {
    case KEY_STATE_TYPE_DS:
        end_date = zone_db_ttl_end_ds(zone);
        ttl = policy_parent_ds_ttl(policy);
        break;

    case KEY_STATE_TYPE_DNSKEY: /* Intentional fall-through */
    case KEY_STATE_TYPE_RRSIGDNSKEY:
        end_date = zone_db_ttl_end_dk(zone);
        ttl = policy_keys_ttl(policy);
        break;

    case KEY_STATE_TYPE_RRSIG:
        end_date = zone_db_ttl_end_rs(zone);
        ttl = max(min(policy_zone_soa_ttl(policy), policy_zone_soa_minimum(policy)),
            ( policy_denial_type(policy) == POLICY_DENIAL_TYPE_NSEC3
                ? ( policy_denial_ttl(policy) > policy_signatures_max_zone_ttl(policy)
                    ? policy_denial_ttl(policy)
                    : policy_signatures_max_zone_ttl(policy) )
                : policy_signatures_max_zone_ttl(policy) ));
        break;

    default:
        return -1;
    }

    return max((int)difftime(end_date, now), ttl);
}

/**
 * Find out if this key can be in a successor relationship
 *
 * \return A positive value if the key is in a successor relationship, zero if
 * it is not and a negative value if an error occurred.
 */
static int
isSuccessable(struct future_key* future_key)
{
    if (!future_key) {
        return -1;
    }

    if (future_key->next_state != UNRETENTIVE) {
        return 0;
    }

    switch (future_key->type) {
    case KEY_STATE_TYPE_DS:
    case KEY_STATE_TYPE_RRSIG:
        if (key_state_state(key_data_cached_dnskey(future_key->key)) != OMNIPRESENT) {
            return 0;
        }
        break;

    case KEY_STATE_TYPE_RRSIGDNSKEY:
        return 0;

    case KEY_STATE_TYPE_DNSKEY:
        if (key_state_state(key_data_cached_ds(future_key->key)) != OMNIPRESENT
            && key_state_state(key_data_cached_rrsig(future_key->key)) != OMNIPRESENT)
        {
            return 0;
        }
        break;

    default:
        return -1;
    }

    return 1;
}

/**
 * Establish relationships between keys in keylist and the future_key.
 * Also remove relationships not longer relevant for future_key.
 *
 * \return A positive value if keys where successfully marked, zero if the
 * future_key can not be a successor and a negative value if an error occurred.
 */
static int
markSuccessors(db_connection_t *dbconn, key_data_t** keylist,
    size_t keylist_size, struct future_key *future_key,
    key_dependency_list_t* deplist, const zone_db_t* zone)
{
    static const char *scmd = "markSuccessors";
    size_t i;
    key_dependency_t *key_dependency, *kd;
    key_dependency_type_t key_dependency_type;
    int cmp;

    if (!dbconn || !keylist || !future_key || !deplist || !zone) {
        return -1;
    }

    /* If key,type in deplist and new state is omnipresent it is no
     * longer relevant for the dependencies */
    if (future_key->next_state == OMNIPRESENT) {
        /* Remove any entries for this key,type tuple from successors */
        for (kd = key_dependency_list_get_begin(deplist); kd;
            key_dependency_free(kd),
            kd = key_dependency_list_get_next(deplist))
        {
            if (db_value_cmp(key_data_id(future_key->key),
                    key_dependency_to_key_data_id(kd), &cmp) == DB_OK &&
                !cmp && kd->type == (key_dependency_type_t)future_key->type)
            {
                    key_dependency_delete(kd);
            }

        }
    }

    if (isSuccessable(future_key) < 1) {
        return 0;
    }

    for (i = 0; i < keylist_size; i++) {
        if (isPotentialSuccessor(keylist[i], future_key->key, future_key, future_key->type) > 0) {
            switch (future_key->type) {
            case KEY_STATE_TYPE_DS:
                key_dependency_type = KEY_DEPENDENCY_TYPE_DS;
                break;

            case KEY_STATE_TYPE_DNSKEY:
                key_dependency_type = KEY_DEPENDENCY_TYPE_DNSKEY;
                break;

            case KEY_STATE_TYPE_RRSIGDNSKEY:
                key_dependency_type = KEY_DEPENDENCY_TYPE_RRSIGDNSKEY;
                break;

            case KEY_STATE_TYPE_RRSIG:
                key_dependency_type = KEY_DEPENDENCY_TYPE_RRSIG;
                break;

            default:
                return -1;
            }

            if (!(key_dependency = key_dependency_new(dbconn))
                || key_dependency_set_from_key_data_id(key_dependency, key_data_id(future_key->key))
                || key_dependency_set_to_key_data_id(key_dependency, key_data_id(keylist[i]))
                || key_dependency_set_type(key_dependency, key_dependency_type)
                || key_dependency_set_zone_id(key_dependency, zone_db_id(zone))
                || key_dependency_create(key_dependency))
            {
                ods_log_error("[%s] %s: unable to create key dependency between %s and %s",
                    module_str, scmd,
                    hsm_key_locator(key_data_cached_hsm_key(future_key->key)),
                    hsm_key_locator(key_data_cached_hsm_key(keylist[i])));
                key_dependency_free(key_dependency);
                return -1;
            }
            key_dependency_free(key_dependency);
        }
    }

    return 1;
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
updateZone(db_connection_t *dbconn, policy_t const *policy, zone_db_t* zone,
    const time_t now, int allow_unsigned, int *zone_updated,
    key_data_t** keylist, size_t keylist_size, key_dependency_list_t *deplist)
{
	time_t returntime_zone = -1;
	unsigned int ttl;
	static const char *scmd = "updateZone";
	size_t i;
	unsigned int j, change;
	static const key_state_type_t type[] = {
	    KEY_STATE_TYPE_DS,
	    KEY_STATE_TYPE_DNSKEY,
	    KEY_STATE_TYPE_RRSIGDNSKEY,
	    KEY_STATE_TYPE_RRSIG
	};
    struct future_key future_key;
    key_state_state_t next_state;
    key_state_state_t state;
    time_t returntime_key;
    key_state_t* key_state;
    int key_data_updated, process, key_state_created;
    const db_enum_t* state_enum, *next_state_enum, *type_enum;
	key_dependency_list_t *deplisttmp = NULL;

    if (!dbconn) {
        /* TODO: better log error */
        ods_log_error("[%s] %s: no dbconn", module_str, scmd);
        return returntime_zone;
    }
	if (!policy) {
        /* TODO: better log error */
        ods_log_error("[%s] %s: no policy", module_str, scmd);
		return returntime_zone;
	}
	if (!zone) {
        /* TODO: better log error */
        ods_log_error("[%s] %s: no zone", module_str, scmd);
		return returntime_zone;
	}
	if (!zone_updated) {
        /* TODO: better log error */
        ods_log_error("[%s] %s: no zone_updated", module_str, scmd);
		return returntime_zone;
	}
    if (!keylist) {
        /* TODO: better log error */
        ods_log_error("[%s] %s: no keylist", module_str, scmd);
        return returntime_zone;
    }
    if (!deplist) {
        /* TODO: better log error */
        ods_log_error("[%s] %s: no deplist", module_str, scmd);
        return returntime_zone;
    }

    ods_log_verbose("[%s] %s: processing %s with policyName %s", module_str, scmd, zone_db_name(zone), policy_name(policy));

    deplisttmp = zone_db_get_key_dependencies(zone);

	/*
	 * The process variable will indicate if we are processing, if something
	 * fails and sets it to 0 then it will fall through to the end.
	 */
    process = 1;

	/*
	 * This code keeps track of TTL changes. If in the past a large TTL is used,
	 * our keys *may* need to transition extra careful to make sure each
	 * resolver picks up the RRset. When this date passes we may start using the
	 * policies TTL.
	 */
	if (process && zone_db_ttl_end_ds(zone) <= now) {
		if (zone_db_set_ttl_end_ds(zone, addtime(now, policy_parent_ds_ttl(policy)))) {
            ods_log_error("[%s] %s: zone_db_set_ttl_end_ds() failed", module_str, scmd);
            process = 0;
		}
		else {
            *zone_updated = 1;
		}
	}
	if (process && zone_db_ttl_end_dk(zone) <= now) {
		/*
		 * If no DNSKEY is currently published we must take negative caching
		 * into account.
		 */
		for (i = 0; i < keylist_size; i++) {
			if (key_state_state(key_data_cached_dnskey(keylist[i])) == OMNIPRESENT) {
				break;
			}
		}
		if (keylist_size < i) {
			ttl = max(policy_keys_ttl(policy),
				min(policy_zone_soa_ttl(policy), policy_zone_soa_minimum(policy)));
		}
		else {
			ttl = policy_keys_ttl(policy);
		}
		if (zone_db_set_ttl_end_dk(zone, addtime(now, ttl))) {
            ods_log_error("[%s] %s: zone_db_set_ttl_end_dk() failed", module_str, scmd);
            process = 0;
        }
        else {
            *zone_updated = 1;
        }
	}
	if (process && zone_db_ttl_end_rs(zone) <= now) {
		if (policy_denial_type(policy) == POLICY_DENIAL_TYPE_NSEC3) {
			ttl = max(policy_signatures_max_zone_ttl(policy), policy_denial_ttl(policy));
		}
		else {
			ttl = policy_signatures_max_zone_ttl(policy);
		}
		if (zone_db_set_ttl_end_rs(zone, addtime(now, max(
			min(policy_zone_soa_ttl(policy), policy_zone_soa_minimum(policy)),
				ttl))))
		{
            ods_log_error("[%s] %s: zone_db_set_ttl_end_rs() failed", module_str, scmd);
            process = 0;
        }
        else {
            *zone_updated = 1;
        }
	}

    /*
     * Create key states that do not exist.
     */
    for (i = 0; process && i < keylist_size; i++) {
        key_state_created = 0;
        if (!key_data_cached_ds(keylist[i])) {
            if (!(key_state = key_state_new(dbconn))
                || key_state_set_key_data_id(key_state, key_data_id(keylist[i]))
                || key_state_set_type(key_state, KEY_STATE_TYPE_DS)
                || key_state_set_minimize(key_state, (key_data_minimize(keylist[i]) >> 2) & 1)
                || key_state_set_state(key_state, key_data_role(keylist[i]) & KEY_DATA_ROLE_KSK ? HIDDEN : NA)
                || key_state_set_last_change(key_state, now)
                || key_state_set_ttl(key_state, getZoneTTL(policy, zone, KEY_STATE_TYPE_DS, now))
                || key_state_create(key_state))
            {
                ods_log_error("[%s] %s: key state DS creation failed", module_str, scmd);
                process = 0;
                key_state_free(key_state);
                key_state = NULL;
                break;
            }
            key_state_created = 1;
            key_state_free(key_state);
            key_state = NULL;

            if (!zone_db_signconf_needs_writing(zone)) {
                if (zone_db_set_signconf_needs_writing(zone, 1)) {
                    ods_log_error("[%s] %s: zone_db_set_signconf_needs_writing() failed", module_str, scmd);
                    process = 0;
                    break;
                }
                else {
                    *zone_updated = 1;
                }
            }
        }
        if (!key_data_cached_dnskey(keylist[i])) {
            if (!(key_state = key_state_new(dbconn))
                || key_state_set_key_data_id(key_state, key_data_id(keylist[i]))
                || key_state_set_type(key_state, KEY_STATE_TYPE_DNSKEY)
                || key_state_set_minimize(key_state, (key_data_minimize(keylist[i]) >> 1) & 1)
                || key_state_set_state(key_state, HIDDEN)
                || key_state_set_last_change(key_state, now)
                || key_state_set_ttl(key_state, getZoneTTL(policy, zone, KEY_STATE_TYPE_DNSKEY, now))
                || key_state_create(key_state))
            {
                ods_log_error("[%s] %s: key state DNSKEY creation failed", module_str, scmd);
                process = 0;
                key_state_free(key_state);
                key_state = NULL;
                break;
            }
            key_state_created = 1;
            key_state_free(key_state);
            key_state = NULL;

            if (!zone_db_signconf_needs_writing(zone)) {
                if (zone_db_set_signconf_needs_writing(zone, 1)) {
                    ods_log_error("[%s] %s: zone_db_set_signconf_needs_writing() failed", module_str, scmd);
                    process = 0;
                    break;
                }
                else {
                    *zone_updated = 1;
                }
            }
        }
        if (!key_data_cached_rrsigdnskey(keylist[i])) {
            if (!(key_state = key_state_new(dbconn))
                || key_state_set_key_data_id(key_state, key_data_id(keylist[i]))
                || key_state_set_type(key_state, KEY_STATE_TYPE_RRSIGDNSKEY)
                || key_state_set_state(key_state, key_data_role(keylist[i]) & KEY_DATA_ROLE_KSK ? HIDDEN : NA)
                || key_state_set_last_change(key_state, now)
                || key_state_set_ttl(key_state, getZoneTTL(policy, zone, KEY_STATE_TYPE_RRSIGDNSKEY, now))
                || key_state_create(key_state))
            {
                ods_log_error("[%s] %s: key state RRSIGDNSKEY creation failed", module_str, scmd);
                process = 0;
                key_state_free(key_state);
                key_state = NULL;
                break;
            }
            key_state_created = 1;
            key_state_free(key_state);
            key_state = NULL;

            if (!zone_db_signconf_needs_writing(zone)) {
                if (zone_db_set_signconf_needs_writing(zone, 1)) {
                    ods_log_error("[%s] %s: zone_db_set_signconf_needs_writing() failed", module_str, scmd);
                    process = 0;
                    break;
                }
                else {
                    *zone_updated = 1;
                }
            }
        }
        if (!key_data_cached_rrsig(keylist[i])) {
            if (!(key_state = key_state_new(dbconn))
                || key_state_set_key_data_id(key_state, key_data_id(keylist[i]))
                || key_state_set_type(key_state, KEY_STATE_TYPE_RRSIG)
                || key_state_set_minimize(key_state, key_data_minimize(keylist[i]) & 1)
                || key_state_set_state(key_state, key_data_role(keylist[i]) & KEY_DATA_ROLE_ZSK ? HIDDEN : NA)
                || key_state_set_last_change(key_state, now)
                || key_state_set_ttl(key_state, getZoneTTL(policy, zone, KEY_STATE_TYPE_RRSIG, now))
                || key_state_create(key_state))
            {
                ods_log_error("[%s] %s: key state RRSIG creation failed", module_str, scmd);
                process = 0;
                key_state_free(key_state);
                key_state = NULL;
                break;
            }
            key_state_created = 1;
            key_state_free(key_state);
            key_state = NULL;

            if (!zone_db_signconf_needs_writing(zone)) {
                if (zone_db_set_signconf_needs_writing(zone, 1)) {
                    ods_log_error("[%s] %s: zone_db_set_signconf_needs_writing() failed", module_str, scmd);
                    process = 0;
                    break;
                }
                else {
                    *zone_updated = 1;
                }
            }
        }
        if (key_state_created) {
            if (key_data_cache_key_states(keylist[i])) {
                ods_log_error("[%s] %s: Unable to recache key states after creating some", module_str, scmd);
                process = 0;
                break;
            }
        }
    }

	/*
	 * Keep looping till there are no state changes and find the earliest update
	 * time to return.
	 */
	do {
		change = 0;
		for (i = 0; process && i < keylist_size; i++) {
			ods_log_verbose("[%s] %s: processing key %s %u", module_str, scmd,
				hsm_key_locator(key_data_cached_hsm_key(keylist[i])), key_data_minimize(keylist[i]));

			for (j = 0; process && j < (sizeof(type) / sizeof(key_state_state_t)); j++) {
                /*
                 * If the state or desired_state is invalid something went wrong
                 * and we should return.
                 */
			    if ((state = getState(keylist[i], type[j], NULL)) == KEY_STATE_STATE_INVALID
			        || (next_state = getDesiredState(key_data_introducing(keylist[i]), state)) == KEY_STATE_STATE_INVALID)
			    {
	                ods_log_error("[%s] %s: (state || next_state) == INVALID", module_str, scmd);
	                process = 0;
	                break;
			    }

			    /*
			     * If there is no change in key state we continue.
			     */
			    if (state == next_state) {
			        continue;
			    }

			    /*
			     * If the key state is a DS then we need to check if we still
			     * are waiting for user input before we can transition the key.
			     */
			    if (type[j] == KEY_STATE_TYPE_DS) {
			        if ((next_state == OMNIPRESENT
			                && key_data_ds_at_parent(keylist[i]) != KEY_DATA_DS_AT_PARENT_SEEN)
			            || (next_state == HIDDEN
			                && key_data_ds_at_parent(keylist[i]) != KEY_DATA_DS_AT_PARENT_UNSUBMITTED))
			        {
			            continue;
			        }
			    }

			    for (type_enum = key_state_enum_set_type; type_enum->text; type_enum++) {
			        if (type_enum->value == (int)type[j]) {
			            break;
			        }
			    }
                for (state_enum = key_state_enum_set_state; state_enum->text; state_enum++) {
                    if (state_enum->value == (int)state) {
                        break;
                    }
                }
                for (next_state_enum = key_state_enum_set_state; next_state_enum->text; next_state_enum++) {
                    if (next_state_enum->value == (int)next_state) {
                        break;
                    }
                }
			    ods_log_verbose("[%s] %s: May %s %s %s in state %s transition to %s?", module_str, scmd,
			        key_data_role_text(keylist[i]),
			        hsm_key_locator(key_data_cached_hsm_key(keylist[i])),
			        type_enum->text,
			        state_enum->text,
			        next_state_enum->text);

                future_key.key = keylist[i];
                future_key.type = type[j];
                future_key.next_state = next_state;

                /*
                 * Check if policy prevents transition.
                 */
                if (policyApproval(keylist, keylist_size, &future_key, deplist) < 1) {
                    continue;
                }
                ods_log_verbose("[%s] %s Policy says we can (1/3)", module_str, scmd);

                /*
                 * Check if DNSSEC state prevents transition.
                 */
                if (dnssecApproval(keylist, keylist_size, &future_key, allow_unsigned, deplisttmp) < 1) {
                    continue;
                }
                ods_log_verbose("[%s] %s DNSSEC says we can (2/3)", module_str, scmd);

                returntime_key = minTransitionTime(policy, type[j], next_state,
                    key_state_last_change(getRecord(keylist[i], type[j])),
                    getZoneTTL(policy, zone, type[j], now));

                /*
                 * If this is an RRSIG and the DNSKEY is omnipresent and next
                 * state is a certain state, wait an additional signature
                 * lifetime to allow for 'smooth rollover'.
                 */
                static const key_state_state_t mask[2][4] = {
                    {NA, OMNIPRESENT, NA, UNRETENTIVE},
                    {NA, OMNIPRESENT, NA, RUMOURED}
                };
                int zsk_out = exists(keylist, keylist_size, &future_key,
                    1, mask[0]);
                int zsk_in = exists(keylist, keylist_size, &future_key,
                    1, mask[1]);

                if (type[j] == KEY_STATE_TYPE_RRSIG
                    && key_state_state(key_data_cached_dnskey(keylist[i])) == OMNIPRESENT
                    && ((next_state == OMNIPRESENT && zsk_out)
                        || (next_state == HIDDEN && zsk_in)))
                {
                    returntime_key = addtime(returntime_key,
                        policy_signatures_jitter(policy)
                        + max(policy_signatures_validity_default(policy),
                            policy_signatures_validity_denial(policy))
                        + policy_signatures_resign(policy)
                        - policy_signatures_refresh(policy));
                }

                /*
                 * It is to soon to make this change. Schedule it.
                 */
                if (returntime_key > now) {
                    minTime(returntime_key, &returntime_zone);
                    continue;
                }

                ods_log_verbose("[%s] %s Timing says we can (3/3) now: %lu key: %lu",
                    module_str, scmd, (unsigned long)now, (unsigned long)returntime_key);

                /*
                 * A record can only reach Omnipresent if properly backed up.
                 */
                if (next_state == OMNIPRESENT) {
                    if (hsm_key_backup(key_data_cached_hsm_key(keylist[i])) == HSM_KEY_BACKUP_BACKUP_REQUIRED
                        || hsm_key_backup(key_data_cached_hsm_key(keylist[i])) == HSM_KEY_BACKUP_BACKUP_REQUESTED)
                    {
                        ods_log_crit("[%s] %s Ready for transition but key material not backed up yet (%s)",
                            module_str, scmd, hsm_key_locator(key_data_cached_hsm_key(keylist[i])));

                        /*
                         * Try again in 60 seconds
                         */
                        returntime_key = addtime(now, 60);
                        minTime(returntime_key, &returntime_zone);
                        continue;
                    }
                }

                /*
                 * If we are handling a DS we depend on the user or
                 * some other external process. We must communicate
                 * through the DSSeen and -submit flags.
                 */
                if (type[j] == KEY_STATE_TYPE_DS) {
                    key_data_updated = 0;

                    /*
                     * Ask the user to submit the DS to the parent.
                     */
                    if (next_state == RUMOURED) {
                        switch (key_data_ds_at_parent(keylist[i])) {
                        case KEY_DATA_DS_AT_PARENT_SEEN:
                        case KEY_DATA_DS_AT_PARENT_SUBMIT:
                        case KEY_DATA_DS_AT_PARENT_SUBMITTED:
                            break;

                        case KEY_DATA_DS_AT_PARENT_RETRACT:
                            /*
                             * Hypothetical case where we reintroduce keys.
                             */
                            key_data_set_ds_at_parent(keylist[i], KEY_DATA_DS_AT_PARENT_SUBMITTED);
                            key_data_updated = 1;
                            break;

                        default:
                            key_data_set_ds_at_parent(keylist[i], KEY_DATA_DS_AT_PARENT_SUBMIT);
                            key_data_updated = 1;
                        }
                    }
                    /*
                     * Ask the user to remove the DS from the parent.
                     */
                    else if (next_state == UNRETENTIVE) {
                        switch(key_data_ds_at_parent(keylist[i])) {
                        case KEY_DATA_DS_AT_PARENT_SUBMIT:
                            /*
                             * Never submitted.
                             * NOTE: not safe if we support reintroducing of keys.
                             */
                            key_data_set_ds_at_parent(keylist[i], KEY_DATA_DS_AT_PARENT_UNSUBMITTED);
                            key_data_updated = 1;
                            break;

                        case KEY_DATA_DS_AT_PARENT_UNSUBMITTED:
                        case KEY_DATA_DS_AT_PARENT_RETRACTED:
                        case KEY_DATA_DS_AT_PARENT_RETRACT:
                            break;

                        default:
                            key_data_set_ds_at_parent(keylist[i], KEY_DATA_DS_AT_PARENT_RETRACT);
                            key_data_updated = 1;
                        }
                    }

                    /*
                     * Save the changes made to the key data if any.
                     */
                    if (key_data_updated) {
                        if (key_data_update(keylist[i])) {
                            ods_log_info("[%s] %s: key data update failed", module_str, scmd);
                            process = 0;
                            break;
                        }
                        /*
                         * We now need to reread the key data object.
                         *
                         * TODO: This needs investigation how to do better.
                         */
                        if (key_data_get_by_id(keylist[i], key_data_id(keylist[i]))
                            || key_data_cache_key_states(keylist[i])
                            || key_data_cache_hsm_key(keylist[i]))
                        {
                            ods_log_error("[%s] %s: key data reread failed", module_str, scmd);
                            process = 0;
                            break;
                        }
                    }
                }

                /*
                 * We've passed all tests! Make the transition.
                 */
                key_state = NULL;

                switch (future_key.type) {
                case KEY_STATE_TYPE_DS:
                    key_state = key_data_get_cached_ds(future_key.key);
                    break;

                case KEY_STATE_TYPE_DNSKEY:
                    key_state = key_data_get_cached_dnskey(future_key.key);
                    break;

                case KEY_STATE_TYPE_RRSIG:
                    key_state = key_data_get_cached_rrsig(future_key.key);
                    break;

                case KEY_STATE_TYPE_RRSIGDNSKEY:
                    key_state = key_data_get_cached_rrsigdnskey(future_key.key);
                    break;

                default:
                    ods_log_error("[%s] %s: future key type error", module_str, scmd);
                    process = 0;
                    break;
                }

                for (next_state_enum = key_state_enum_set_state; next_state_enum->text; next_state_enum++) {
                    if (next_state_enum->value == (int)next_state) {
                        break;
                    }
                }
                ods_log_verbose("[%s] %s: Transitioning %s %s %s from %s to %s", module_str, scmd,
                    key_data_role_text(keylist[i]),
                    hsm_key_locator(key_data_cached_hsm_key(keylist[i])),
                    key_state_type_text(key_state),
                    key_state_state_text(key_state),
                    next_state_enum->text);

                if (key_state_set_state(key_state, future_key.next_state)
                    || key_state_set_last_change(key_state, now)
                    || key_state_set_ttl(key_state, getZoneTTL(policy, zone, future_key.type, now))
                    || key_state_update(key_state))
                {
                    ods_log_error("[%s] %s: key state transition failed", module_str, scmd);
                    process = 0;
		    key_state_free(key_state);
                    break;
                }
                key_state_free(key_state);

                if (!zone_db_signconf_needs_writing(zone)) {
                    if (zone_db_set_signconf_needs_writing(zone, 1)) {
                        ods_log_error("[%s] %s: zone_db_set_signconf_needs_writing() failed", module_str, scmd);
                        process = 0;
                        break;
                    }
                    else {
                        *zone_updated = 1;
                    }
                }

                if (markSuccessors(dbconn, keylist, keylist_size, &future_key, deplisttmp, zone) < 0) {
                    ods_log_error("[%s] %s: markSuccessors() error", module_str, scmd);
                    process = 0;
                    break;
                }
                /*deps have changed reload*/
				key_dependency_list_free(deplisttmp);
                deplisttmp = zone_db_get_key_dependencies(zone);


                if (key_data_cache_key_states(keylist[i])) {
                    ods_log_error("[%s] %s: Unable to recache key states after transition", module_str, scmd);
                    process = 0;
                    break;
                }

                change = true;
			}
		}
	} while (process && change);
	key_dependency_list_free(deplisttmp);
	return returntime_zone;
}

/**
 * Get a reusable key for this policy key.
 */
static const hsm_key_t*
getLastReusableKey(key_data_list_t *key_list, const policy_key_t *pkey)
{
	const key_data_t *key;
	hsm_key_t *hkey, *hkey_young = NULL;
	hsm_key_list_t* hsmkeylist;
	int match;
	int cmp;

	if (!key_list || !pkey)
		return NULL;

	hsmkeylist = hsm_key_list_new_get_by_policy_key(pkey);
	for (hkey = hsm_key_list_get_begin(hsmkeylist); hkey;
		hkey = hsm_key_list_get_next(hsmkeylist))
	{
		/** only match if the hkey has at least the role(s) of pkey */
		if ((~hsm_key_role(hkey) & policy_key_role(pkey)) != 0 ||
			/** hsmkey must be in use already. Allocating UNUSED keys is a
			 * job for the keyfactory */
			hkey->state == HSM_KEY_STATE_UNUSED ||
			hkey->state == HSM_KEY_STATE_DELETE )
		{
			hsm_key_free(hkey);
			continue;
		}

		/** Now find out if hsmkey is in used by zone */
		for (match = 0, key = key_data_list_begin(key_list); key; key = key_data_list_next(key_list)) {
			if (!db_value_cmp(key_data_hsm_key_id(key), hsm_key_id(hkey), &cmp)
				&& cmp == 0)
			{
				/** we have match, so this hsm_key is no good */
				match = 1;
				break;
			}
		}
		if (match) {
			hsm_key_free(hkey);
			continue;
		}

		/** This key matches, is it newer? */
		if (!hkey_young || hsm_key_inception(hkey_young) < hsm_key_inception(hkey)) {
			hsm_key_free(hkey_young);
			hkey_young = hkey;
		}
	}

	hsm_key_list_free(hsmkeylist);
	return hkey_young;
}

/**
 * Test for the existence of key-configuration in the policy for
 * which key could be generated.
 * 
 * \param[in] policykeylist list of policy keys that must be able to rewind.
 * \param[in] key key to be tested.
 * \return 1 if a matching policy exists, 0 otherwise. -1 on error.
 */
static int
existsPolicyForKey(policy_key_list_t *policykeylist, const key_data_t *key)
{
	static const char *scmd = "existsPolicyForKey";
	const policy_key_t *pkey;
	hsm_key_t *hkey;

	if (!policykeylist) {
		return -1;
	}
	if (!key) {
		return -1;
	}

	if (!(hkey = key_data_get_hsm_key(key))) {
		/*
		 * This key is not associated with actual key material!
		 * This is a bug or database corruption.
		 * Crashing here is an option but we just return false so the 
		 * key will be thrown away in a graceful manner.
		 */
		ods_log_verbose("[%s] %s no hsmkey!", module_str, scmd);
		return 0;
	}
	pkey = policy_key_list_begin(policykeylist);
	while (pkey) {
		if ((int)policy_key_role(pkey) == (int)key_data_role(key) &&
			hsm_key_repository(hkey) && policy_key_repository(pkey) &&
			strcmp(hsm_key_repository(hkey), policy_key_repository(pkey)) == 0 &&
			hsm_key_algorithm(hkey) == policy_key_algorithm(pkey) &&
			hsm_key_bits(hkey) == policy_key_bits(pkey))
		{
			hsm_key_free(hkey);
			return 1;
		}
		pkey = policy_key_list_next(policykeylist);
	}
	ods_log_verbose("[%s] %s not found such config", module_str, scmd);
	hsm_key_free(hkey);
	return 0;
}

static int
last_inception_policy(key_data_list_t *key_list, const policy_key_t *pkey)
{
	const key_data_t *key = NULL;
	hsm_key_t *hsmkey = NULL;
	int max_inception = -1;

	if (!key_list || !pkey) return -1;
	
	/*
	 * Must match: role, bits, algorithm and repository.
	 */
	for (key = key_data_list_begin(key_list); key;
		key = key_data_list_next(key_list))
	{
		if ((int)policy_key_role(pkey) != (int)key_data_role(key) ||
			policy_key_algorithm(pkey) != key_data_algorithm(key) ||
			(hsmkey = key_data_get_hsm_key(key)) == NULL ||
			policy_key_bits(pkey) != hsm_key_bits(hsmkey) ||
			policy_key_algorithm(pkey) != hsm_key_algorithm(hsmkey) ||
			strcmp(policy_key_repository(pkey), hsm_key_repository(hsmkey)))
		{
			hsm_key_free(hsmkey);
			hsmkey = NULL;
			continue;
		}
		hsm_key_free(hsmkey);
		hsmkey = NULL;
		/** This key matches, is it newer? */
		if (max_inception == -1 || max_inception < (signed int)key_data_inception(key))
		{
			max_inception = key_data_inception(key);
		}
	}
	return max_inception;
}

/**
 * Test for existence of a similar key.
 * 
 * \param[in] Key list
 * \param[in] Role
 * \param[in] Algorithm
 * \return existence of such a key.
 */
static int
key_for_conf(key_data_list_t *key_list, const policy_key_t *pkey)
{
	const key_data_t *key;

	if (!key_list) {
		return 0;
	}
	if (!pkey) {
		return 0;
	}

	for (key = key_data_list_begin(key_list); key;
		key = key_data_list_next(key_list))
	{
		if (policy_key_algorithm(pkey) == key_data_algorithm(key) &&
			(int)policy_key_role(pkey) == (int)key_data_role(key))
		{
			return 1;
		}
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
setnextroll(zone_db_t *zone, const policy_key_t *pkey, time_t t)
{
	assert(zone);
	assert(pkey);

	switch(policy_key_role(pkey)) {
		case POLICY_KEY_ROLE_KSK:
			zone->next_ksk_roll = (unsigned int)t;
			break;
		case POLICY_KEY_ROLE_ZSK:
			zone->next_zsk_roll = (unsigned int)t;
			break;
		case POLICY_KEY_ROLE_CSK:
			zone->next_csk_roll = (unsigned int)t;
			break;
		default:
			assert(0);
	}
}

static int
enforce_roll(const zone_db_t *zone, const policy_key_t *pkey)
{
	if (!zone) {
		return 0;
	}
	if (!pkey) {
		return 0;
	}

	switch(policy_key_role(pkey)) {
		case POLICY_KEY_ROLE_KSK:
			return zone_db_roll_ksk_now(zone);
		case POLICY_KEY_ROLE_ZSK:
			return zone_db_roll_zsk_now(zone);
		case POLICY_KEY_ROLE_CSK:
			return zone_db_roll_csk_now(zone);
		default:
			return 0;
	}
}

static int
set_roll(zone_db_t *zone, const policy_key_t *pkey, unsigned int roll)
{
	if (!zone) {
		return 0;
	}
	if (!pkey) {
		return 0;
	}

	switch(policy_key_role(pkey)) {
		case POLICY_KEY_ROLE_KSK:
			return zone_db_set_roll_ksk_now(zone, roll);
		case POLICY_KEY_ROLE_ZSK:
			return zone_db_set_roll_zsk_now(zone, roll);
		case POLICY_KEY_ROLE_CSK:
			return zone_db_set_roll_csk_now(zone, roll);
		default:
			return 1;
	}
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
updatePolicy(engine_type *engine, db_connection_t *dbconn, policy_t const *policy,
	zone_db_t *zone, const time_t now, int *allow_unsigned, int *zone_updated)
{
	time_t return_at = -1;
	key_data_list_t *keylist;
	policy_key_list_t *policykeylist;
	const key_data_t *key;
	key_data_t *mutkey = NULL;
	key_data_t *mutkey2 = NULL;
	const policy_key_t *pkey;
	const hsm_key_t *hsmkey;
	hsm_key_t *hsmkey2 = NULL;
	hsm_key_t *newhsmkey = NULL;
	static const char *scmd = "updatePolicy";
	int force_roll;
	time_t t_ret;
	key_data_role_t key_role;
	int err;
	uint16_t tag;
	int ret;

	if (!dbconn) {
		/* TODO: better log error */
		ods_log_error("[%s] %s: no dbconn", module_str, scmd);
		return now + 60;
	}
	if (!policy) {
		/* TODO: better log error */
		ods_log_error("[%s] %s: no policy", module_str, scmd);
		return now + 60;
	}
	if (!zone) {
		/* TODO: better log error */
		ods_log_error("[%s] %s: no zone", module_str, scmd);
		return now + 60;
	}
	if (!allow_unsigned) {
		/* TODO: better log error */
		ods_log_error("[%s] %s: no allow_unsigned", module_str, scmd);
		return now + 60;
	}
	if (!zone_updated) {
		/* TODO: better log error */
		ods_log_error("[%s] %s: no zone_updated", module_str, scmd);
		return now + 60;
	}

	ods_log_verbose("[%s] %s: policyName: %s", module_str, scmd, policy_name(policy));

	/*
	 * Get all policy keys (configurations) for the given policy and fetch all
	 * the policy key database objects so we can iterate over it more then once.
	 */
	if (!(policykeylist = policy_get_policy_keys(policy))) {
		/* TODO: better log error */
		ods_log_error("[%s] %s: error policy_get_policy_keys()", module_str, scmd);
		policy_key_list_free(policykeylist);
		return now + 60;
	}

	/*
	 * Get all key data objects for the given zone and fetch all the objects
	 * from the database so we can use the list again later.
	 */
	if (!(keylist = zone_db_get_keys(zone))) {
		/* TODO: better log error */
		ods_log_error("[%s] %s: error zone_db_get_keys()", module_str, scmd);
		key_data_list_free(keylist);
		policy_key_list_free(policykeylist);
		return now + 60;
	}

	/*
	 * Decommission all key data objects without any matching policy key config.
	 */
	while ((key = key_data_list_next(keylist))) {
		ret = existsPolicyForKey(policykeylist, key);
		if (ret < 0) {
			/* TODO: better log error */
			ods_log_error("[%s] %s: error existsPolicyForKey() < 0", module_str, scmd);
			key_data_list_free(keylist);
			policy_key_list_free(policykeylist);
			return now + 60;
		}
		if (!ret) {
			if (!(mutkey = key_data_new_copy(key))
				|| key_data_set_introducing(mutkey, 0)
				|| key_data_update(mutkey))
			{
				/* TODO: better log error */
				ods_log_error("[%s] %s: error update mutkey", module_str, scmd);
				key_data_free(mutkey);
				key_data_list_free(keylist);
				policy_key_list_free(policykeylist);
				return now + 60;
			}
			key_data_free(mutkey);
			mutkey = NULL;
		}
	}

	pkey = policy_key_list_begin(policykeylist);

	/*
	 * If no keys are configured an unsigned zone is okay.
	 */
	*allow_unsigned = pkey ? 0 : 1;

	/* If there are no keys configured set 'signconf_needs_writing'
	 * every time this function is called */
	if (!policy_key_list_size(policykeylist)) {
		if (zone_db_set_signconf_needs_writing(zone, 1)) {
			ods_log_error("[%s] %s: zone_db_set_signconf_needs_writing() failed", module_str, scmd);
		} else {
			*zone_updated = 1;
		}
	}

	for (; pkey; pkey = policy_key_list_next(policykeylist)) {
		newhsmkey = NULL;
		/*
		 * Check if we should roll, first get the roll state from the zone then
		 * check if the policy key is set to manual rollover and last check the
		 * key timings.
		 */
		force_roll = enforce_roll(zone, pkey);
		if (policy_key_manual_rollover(pkey)) {
			/*
			 * If this policy key is set to manual rollover and we do not have
			 * a key yet (for ex first run) then we should roll anyway.
			 */
			if (!key_for_conf(keylist, pkey)) {
				force_roll = 1;
			}
			else if (!force_roll) {
				/*
				 * Since this is set to manual rollover we do not want it to
				 * roll unless we have zone state saying that we should roll.
				 */
				continue;
			}
		}
		if (!force_roll) {
			int inception = -1;
			/*
			 * We do not need to roll but we should check if the youngest key
			 * needs to be replaced. If not we reschedule for later based on the
			 * youngest key.
			 * TODO: Describe better why the youngest?!?
			 */
			inception = last_inception_policy(keylist, pkey);
			if (inception != -1 &&
				inception + policy_key_lifetime(pkey) > now)
			{
				t_ret = addtime(inception, policy_key_lifetime(pkey));
				minTime(t_ret, &return_at);
				setnextroll(zone, pkey, t_ret);
				*zone_updated = 1;
				continue;
			}
		}
		
		/*
		 * Time for a new key
		 */
		ods_log_verbose("[%s] %s: New key needed for role %s",
			module_str, scmd, policy_key_role_text(pkey));

		/*
		 * Sanity check for unreasonable short key lifetime.
		 * This would produce silly output and give the signer lots of useless
		 * work to do otherwise.
		 */
		if ((policy_key_role(pkey) == POLICY_KEY_ROLE_KSK ||
			policy_key_role(pkey) == POLICY_KEY_ROLE_CSK) &&
			policy_parent_ds_ttl(policy) + policy_keys_ttl(policy) >=
			policy_key_lifetime(pkey))
		{
			ods_log_error("[%s] %s: For policy %s %s key lifetime of %d "
				"is unreasonably short with respect to sum of parent "
				"TTL (%d) and key TTL (%d). Will not insert key!",
				module_str, scmd, policy_name(policy), policy_key_role_text(pkey),
				policy_key_lifetime(pkey), policy_parent_ds_ttl(policy),
				policy_keys_ttl(policy));
			setnextroll(zone, pkey, now);
			*zone_updated = 1;
			continue;
		}
		if ((policy_key_role(pkey) == POLICY_KEY_ROLE_ZSK ||
			policy_key_role(pkey) == POLICY_KEY_ROLE_CSK) &&
			policy_signatures_max_zone_ttl(policy) + policy_keys_ttl(policy) >=
			policy_key_lifetime(pkey))
		{
			ods_log_crit("[%s] %s: For policy %s %s key lifetime of %d "
				"is unreasonably short with respect to sum of "
				"MaxZoneTTL (%d) and key TTL (%d). Will not insert key!",
				module_str, scmd, policy_name(policy), policy_key_role_text(pkey),
				policy_key_lifetime(pkey), policy_signatures_max_zone_ttl(policy),
				policy_keys_ttl(policy));
			setnextroll(zone, pkey, now);
			*zone_updated = 1;
			continue;
		}

		/*
		 * Get a new key, either a existing/shared key if the policy is set to
		 * share keys or create a new key.
		 */
		if (policy_keys_shared(policy)) {
			hsmkey = getLastReusableKey(keylist, pkey);

			if (!hsmkey) {
				newhsmkey = hsm_key_factory_get_key(engine, dbconn, pkey, HSM_KEY_STATE_SHARED);
				hsmkey = newhsmkey;
			}
		} else {
			newhsmkey = hsm_key_factory_get_key(engine, dbconn, pkey, HSM_KEY_STATE_PRIVATE);
			hsmkey = newhsmkey;
		}

		if (!hsmkey) {
			/*
			 * Unable to get/create a HSM key at this time, retry later.
			 */
			ods_log_warning("[%s] %s: No keys available in HSM for policy %s, retry in %d seconds",
				module_str, scmd, policy_name(policy), NOKEY_TIMEOUT);
			minTime(now + NOKEY_TIMEOUT, &return_at);
			setnextroll(zone, pkey, now);
			*zone_updated = 1;
			continue;
		}
		ods_log_verbose("[%s] %s: got new key from HSM", module_str, scmd);

		/*
		 * TODO: This will be replaced once roles are global
		 */
		key_role = KEY_DATA_ROLE_INVALID;
		switch (policy_key_role(pkey)) {
		case POLICY_KEY_ROLE_KSK:
			key_role = KEY_DATA_ROLE_KSK;
			break;

		case POLICY_KEY_ROLE_ZSK:
			key_role = KEY_DATA_ROLE_ZSK;
			break;

		case POLICY_KEY_ROLE_CSK:
			key_role = KEY_DATA_ROLE_CSK;
			break;

		default:
			break;
		}

		/*
		 * Create a new key data object.
		 */
		if (!(mutkey = key_data_new(dbconn))
			|| key_data_set_zone_id(mutkey, zone_db_id(zone))
			|| key_data_set_hsm_key_id(mutkey, hsm_key_id(hsmkey))
			|| key_data_set_algorithm(mutkey, policy_key_algorithm(pkey))
			|| key_data_set_inception(mutkey, now)
			|| key_data_set_role(mutkey, key_role)
			|| key_data_set_minimize(mutkey, policy_key_minimize(pkey))
			|| key_data_set_introducing(mutkey, 1)
			|| key_data_set_ds_at_parent(mutkey, KEY_DATA_DS_AT_PARENT_UNSUBMITTED))
		{
			/* TODO: better log error */
			ods_log_error("[%s] %s: error new key", module_str, scmd);
			key_data_free(mutkey);
			if (newhsmkey) {
			    hsm_key_factory_release_key(newhsmkey, dbconn);
			}
			hsm_key_free(newhsmkey);
			key_data_list_free(keylist);
			policy_key_list_free(policykeylist);
			return now + 60;
		}

		/*
		 * Generate keytag for the new key and set it.
		 */
		err = hsm_keytag(hsm_key_locator(hsmkey), hsm_key_algorithm(hsmkey),
			HSM_KEY_ROLE_SEP(hsm_key_role(hsmkey)), &tag);
		if (err || key_data_set_keytag(mutkey, tag))
		{
			/* TODO: better log error */
			ods_log_error("[%s] %s: error keytag", module_str, scmd);
			key_data_free(mutkey);
			if (newhsmkey) {
				hsm_key_factory_release_key(newhsmkey, dbconn);
			}
			hsm_key_free(newhsmkey);
			key_data_list_free(keylist);
			policy_key_list_free(policykeylist);
			return now + 60;
		}

		/*
		 * Create the new key in the database, if successful we set the next
		 * roll after the lifetime of the key.
		 */
		if (key_data_create(mutkey)) {
			/* TODO: better log error */
			ods_log_error("[%s] %s: error key_data_create()", module_str, scmd);
			key_data_free(mutkey);
			if (newhsmkey) {
				hsm_key_factory_release_key(newhsmkey, dbconn);
			}
			hsm_key_free(newhsmkey);
			key_data_list_free(keylist);
			policy_key_list_free(policykeylist);
			return now + 60;
		}
		t_ret = addtime(now, policy_key_lifetime(pkey));
		minTime(t_ret, &return_at);
		setnextroll(zone, pkey, t_ret);
		*zone_updated = 1;

		/*
		 * Tell similar keys to out-troduce.
		 * Similar keys are those that match role, algorithm, bits and repository
		 * and are introduced.
		 *
		 * NOTE:
		 * Will not work if a policy has 2 or more keys of the same role, algorithm,
		 * bits and repository. Unclear how to fix this since keys are not directly
		 * related to a policy key.
		 * We currently do not allow two policy keys with the same attributes.
		 */
		for (key = key_data_list_begin(keylist); key; key = key_data_list_next(keylist)) {
			if (key_data_introducing(key)
				&& key_data_role(key) == key_data_role(mutkey)
				&& key_data_algorithm(key) == key_data_algorithm(mutkey)
				&& (hsmkey2 = key_data_get_hsm_key(key))
				&& hsm_key_bits(hsmkey2) == hsm_key_bits(hsmkey)
				&& !strcmp(hsm_key_repository(hsmkey2), hsm_key_repository(hsmkey)))
			{
				if (!(mutkey2 = key_data_new_copy(key))
					|| key_data_set_introducing(mutkey2, 0)
					|| key_data_update(mutkey2))
				{
					/* TODO: better log error */
					ods_log_error("[%s] %s: error update mutkey2", module_str, scmd);
					key_data_free(mutkey2);
					hsm_key_free(hsmkey2);
					key_data_free(mutkey);
					hsm_key_free(newhsmkey);
					key_data_list_free(keylist);
					policy_key_list_free(policykeylist);
					return now + 60;
				}

				ods_log_verbose("[%s] %s: decommissioning old key: %s", module_str, scmd, hsm_key_locator(hsmkey2));

				key_data_free(mutkey2);
				mutkey2 = NULL;
			}
			hsm_key_free(hsmkey2);
			hsmkey2 = NULL;
		}

		key_data_free(mutkey);
		mutkey = NULL;
		hsm_key_free(newhsmkey);
		newhsmkey = NULL;

		/*
		 * Clear roll now (if set) in the zone for this policy key.
		 */
		if (enforce_roll(zone, pkey)) {
			if (set_roll(zone, pkey, 0)) {
				/* TODO: better log error */
				ods_log_error("[%s] %s: error set_roll()", module_str, scmd);
				key_data_list_free(keylist);
				policy_key_list_free(policykeylist);
				return now + 60;
			}
			*zone_updated = 1;
		}
	}

	key_data_list_free(keylist);
	policy_key_list_free(policykeylist);

	return return_at;
}

static time_t
removeDeadKeys(db_connection_t *dbconn, key_data_t** keylist,
	size_t keylist_size, key_dependency_list_t *deplist, const time_t now,
	const int purgetime)
{
	static const char *scmd = "removeDeadKeys";
	time_t first_purge = -1, key_time;
	size_t i, deplist2_size = 0;
	int key_purgable, cmp;
	unsigned int j;
	const key_state_t* state = NULL;
	key_dependency_t **deplist2 = NULL;

	assert(keylist);
	assert(deplist);

	deplist2_size = key_dependency_list_size(deplist);
	deplist2 = (key_dependency_t**)calloc(deplist2_size, sizeof(key_dependency_t*));
	/* deplist might be NULL but is always freeable */
	if (deplist2_size > 0)
	    deplist2[0] = key_dependency_list_get_begin(deplist);
	for (i = 1; i < deplist2_size; i++)
		deplist2[i] = key_dependency_list_get_next(deplist);
	
	for (i = 0; i < keylist_size; i++) {
		if (key_data_introducing(keylist[i])) continue;
		key_time = -1;
		key_purgable = 1;
		for (j = 0; j<4; j++) {
			switch(j){
				case 0: state = key_data_cached_ds(keylist[i]); break;
				case 1: state = key_data_cached_dnskey(keylist[i]); break;
				case 2: state = key_data_cached_rrsigdnskey(keylist[i]); break;
				case 3: state = key_data_cached_rrsig(keylist[i]);
			}
			if (key_state_state(state) == NA) continue;
			if (key_state_state(state) != HIDDEN) {
				key_purgable = 0;
				break;
			}
			if (key_time == -1 || key_state_last_change(state) > (unsigned int)key_time) {
				key_time = key_state_last_change(state);
			}
		}
        if (key_time != -1) key_time = addtime(key_time, purgetime);
        if (key_purgable) {
			/* key is purgable, is it time yet? */
            if (now >= key_time) {
                key_state_t* ks_ds = key_data_get_cached_ds(keylist[i]);
                key_state_t* ks_dk = key_data_get_cached_dnskey(keylist[i]);
                key_state_t* ks_rd = key_data_get_cached_rrsigdnskey(keylist[i]);
                key_state_t* ks_rs = key_data_get_cached_rrsig(keylist[i]);

                ods_log_info("[%s] %s deleting key: %s", module_str, scmd,
                    hsm_key_locator(key_data_cached_hsm_key(keylist[i])));

                if (   key_state_delete(ks_ds) || key_state_delete(ks_dk)
                    || key_state_delete(ks_rd) || key_state_delete(ks_rs)
                    || key_data_delete(keylist[i])
                    || hsm_key_factory_release_key_id(hsm_key_id(key_data_cached_hsm_key(keylist[i])), dbconn))
                {
                    /* TODO: better log error */
                    ods_log_error("[%s] %s: key_state_delete() || key_data_delete() || hsm_key_factory_release_key() failed", module_str, scmd);
                }
                key_state_free(ks_ds);
                key_state_free(ks_dk);
                key_state_free(ks_rd);
                key_state_free(ks_rs);
            } else {
                minTime(key_time, &first_purge);
            }
            /* we can clean up dependency because key is purgable */

            for (j = 0; j < deplist2_size; j++) {
                if (!deplist2[j]) continue;
                if (db_value_cmp(key_data_id(keylist[i]), key_dependency_from_key_data_id(deplist2[j]), &cmp)) {
                    /* TODO: better log error */
                    ods_log_error("[%s] %s: cmp deplist from failed", module_str, scmd);
                    break;
                }
                if(cmp) continue;

                if (key_dependency_delete(deplist2[j])) {
                    /* TODO: better log error */
                    ods_log_error("[%s] %s: key_dependency_delete() failed", module_str, scmd);
                    break;
                }
            }
        }
    }
    for (i = 0; i < deplist2_size; i++){
	key_dependency_free(deplist2[i]);
    }
	free(deplist2);
        
    int deleteCount = hsm_key_factory_delete_key(dbconn);
    ods_log_info("[%s] %s: keys deleted from HSM: %d", module_str, scmd, deleteCount);

    if(deleteCount > 0) {
        return -1 - deleteCount;
    } else {
        return first_purge;
    }
}

time_t
update(engine_type *engine, db_connection_t *dbconn, zone_db_t *zone, policy_t const *policy, time_t now, int *zone_updated)
{
	int allow_unsigned = 0;
    time_t policy_return_time, zone_return_time, purge_return_time = -1, return_time;
    key_data_list_t *key_list;
    const key_data_t* key;
    key_data_t** keylist = NULL;
    size_t keylist_size, i;
    key_dependency_list_t *deplist;
    static const char *scmd = "update";
    int key_data_updated;

	if (!engine) {
		ods_log_error("[%s] no engine", module_str);
		return now + 60;
	}
	if (!dbconn) {
		ods_log_error("[%s] no dbconn", module_str);
		return now + 60;
	}
	if (!zone) {
		ods_log_error("[%s] no zone", module_str);
		return now + 60;
	}
	if (!policy) {
		ods_log_error("[%s] no policy", module_str);
		return now + 60;
	}
	if (!zone_updated) {
		ods_log_error("[%s] no zone_updated", module_str);
		return now + 60;
	}

	ods_log_info("[%s] update zone: %s", module_str, zone_db_name(zone));

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


	/*
	 * Update policy.
	 */
	policy_return_time = updatePolicy(engine, dbconn, policy, zone, now, &allow_unsigned, zone_updated);

	if (allow_unsigned) {
		ods_log_info("[%s] No keys configured for %s, zone will become unsigned eventually",
		    module_str, zone_db_name(zone));
	}

    /*
     * Get all key data/state/hsm objects for later processing.
     */
    if (!(deplist = zone_db_get_key_dependencies(zone))) {
        /* TODO: better log error */
        ods_log_error("[%s] %s: error zone_db_get_key_dependencies()", module_str, scmd);
        key_dependency_list_free(deplist);
        return now + 60;
    }
    if (!(key_list = zone_db_get_keys(zone))) {
        /* TODO: better log error */
        ods_log_error("[%s] %s: error zone_db_get_keys()", module_str, scmd);
        key_data_list_free(key_list);
        key_dependency_list_free(deplist);
        return now + 60;
    }
    /*WTF DOES THIS CODE DO?*/
    if (!(keylist_size = key_data_list_size(key_list))) {
        if ((key = key_data_list_begin(key_list))) {
            while (key) {
                keylist_size++;
                key = key_data_list_next(key_list);
            }
        }
    }
    if (keylist_size) {
        if (!(keylist = (key_data_t**)calloc(keylist_size, sizeof(key_data_t*)))) {
            /* TODO: better log error */
            ods_log_error("[%s] %s: error calloc(keylist_size)", module_str, scmd);
            key_data_list_free(key_list);
            key_dependency_list_free(deplist);
            return now + 60;
        }
        for (i = 0; i < keylist_size; i++) {
            if (!i) {
                keylist[i] = key_data_list_get_begin(key_list);
            }
            else {
                keylist[i] = key_data_list_get_next(key_list);
            }
            if (!keylist[i]
                || key_data_cache_hsm_key(keylist[i])
                || key_data_cache_key_states(keylist[i]))
            {
                ods_log_error("[%s] %s: error key_data_list cache", module_str, scmd);
                for (i = 0; i < keylist_size; i++) {
                    if (keylist[i]) {
                        key_data_free(keylist[i]);
                    }
                }
                free(keylist);
                key_data_list_free(key_list);
                key_dependency_list_free(deplist);
                return now + 60;
            }
        }
    }
    key_data_list_free(key_list);


    /*
     * Only purge old keys if the policy says so.
     */
	if (policy_keys_purge_after(policy) && keylist) {
	    purge_return_time = removeDeadKeys(dbconn, keylist, keylist_size, deplist, now,
	        policy_keys_purge_after(policy));
            if(purge_return_time < -1) {
                ods_log_error("[%s] reschedule enforcing policy due to deleting keys", module_str, scmd);
                /* Keys have been deleted, we cannot continue in this same session, reschedule. */
                return now + 60;
            }
	}
    
    
    /*
     * Update zone.
     */
    zone_return_time = updateZone(dbconn, policy, zone, now, allow_unsigned, zone_updated,
	    keylist, keylist_size, deplist);


    /*
     * Always set these flags. Normally this needs to be done _only_ when the
     * Signer config needs writing. However a previous Signer config might not
     * be available, we have no way of telling. :(
     */
	for (i = 0; i < keylist_size; i++) {
	    key_data_updated = 0;

		/* hack */
		key_data_set_publish(keylist[i], 0);
		key_data_set_active_ksk(keylist[i], 0);
		key_data_set_active_zsk(keylist[i], 0);
		key_data_updated = 1;
	    /*
	     * TODO: description
	     */
	    if (key_state_state(key_data_cached_dnskey(keylist[i])) == OMNIPRESENT
	        || key_state_state(key_data_cached_dnskey(keylist[i])) == RUMOURED)
	    {
	        if (!key_data_publish(keylist[i])) {
	            if (key_data_set_publish(keylist[i], 1)) {
	                ods_log_error("[%s] %s: key_data_set_publish() failed",
	                    module_str, scmd);
	                break;
	            }

	            key_data_updated = 1;
	        }
	    }

        /*
         * TODO: description
         */
        if (key_state_state(key_data_cached_rrsigdnskey(keylist[i])) == OMNIPRESENT
            || key_state_state(key_data_cached_rrsigdnskey(keylist[i])) == RUMOURED)
        {
            if (!key_data_active_ksk(keylist[i])) {
                if (key_data_set_active_ksk(keylist[i], 1)) {
                    ods_log_error("[%s] %s: key_data_set_active_ksk() failed",
                        module_str, scmd);
                    break;
                }

                key_data_updated = 1;
            }
        }

        /*
         * TODO: description
         */
        if (key_state_state(key_data_cached_rrsig(keylist[i])) == OMNIPRESENT
            || key_state_state(key_data_cached_rrsig(keylist[i])) == RUMOURED)
        {
            if (!key_data_active_zsk(keylist[i])) {
                if (key_data_set_active_zsk(keylist[i], 1)) {
                    ods_log_error("[%s] %s: key_data_set_active_zsk() failed",
                        module_str, scmd);
                    break;
                }

                key_data_updated = 1;
            }
        }

        if (key_data_updated) {
            if (key_data_update(keylist[i])) {
                ods_log_error("[%s] %s: key_data_update() failed",
                    module_str, scmd);
                break;
            }
        }
	}
            
    /*
     * Release cached objects.
     */
    for (i = 0; i < keylist_size; i++) {
        if (keylist[i]) {
            key_data_free(keylist[i]);
        }
    }
    free(keylist);
    key_dependency_list_free(deplist);

    return_time = zone_return_time;
    minTime(policy_return_time, &return_time);
    /*
     * Take the rollover notification time into account when scheduling
     * this zone. We will need to print a message at that time.
     */
    if (zone_db_next_ksk_roll(zone) > 0
        && (zone_db_next_ksk_roll(zone) - engine->config->rollover_notification > now)) {
        minTime(zone_db_next_ksk_roll(zone) - engine->config->rollover_notification, &return_time);
    }
    else if (zone_db_next_csk_roll(zone) > 0
             && (zone_db_next_csk_roll(zone) - engine->config->rollover_notification > now)) {
        minTime(zone_db_next_csk_roll(zone) - engine->config->rollover_notification, &return_time);
    }

    minTime(purge_return_time, &return_time);
    return return_time;
}
