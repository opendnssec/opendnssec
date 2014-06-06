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

#include <ctime>
#include <iostream>

#include "enforcer/enforcerdata.h"
#include "policy/kasp.pb.h"
#include "hsmkey/hsmkey.pb.h"
#include "libhsm.h"
#include "hsmkey/hsm_key_factory.h"

#include <libhsmdns.h>
#include <ldns/ldns.h>

#include "shared/duration.h"
#include "shared/log.h"

#include "db/zone.h"
#include "db/policy.h"
#include "db/policy_key.h"
#include "db/hsm_key.h"
#include "db/key_data.h"

#include "enforcer/enforcer.h"

#define HIDDEN      KEY_STATE_STATE_HIDDEN
#define RUMOURED    KEY_STATE_STATE_RUMOURED
#define OMNIPRESENT KEY_STATE_STATE_OMNIPRESENT
#define UNRETENTIVE KEY_STATE_STATE_UNRETENTIVE
#define NA          KEY_STATE_STATE_NA

using namespace std;
using ::ods::kasp::Policy;
using ::ods::kasp::KeyList;

static const char *module_str = "enforcer";

/* be careful changing this, might mess up database*/
enum STATE {HID, RUM, OMN, UNR, NOCARE}; 
static const char* STATENAMES[] = {"HID", "RUM", "OMN", "UNR"};
/* trick to loop over our RECORD enum */
RECORD& operator++(RECORD& r){return r = (r >= REC_MAX?REC_MAX:RECORD(r+1));}
static const char* RECORDAMES[] = {"DS", "DNSKEY", "RRSIG DNSKEY", "RRSIG"};
/* \careful */

/** When no key available wait this many seconds before asking again. */
#define NOKEY_TIMEOUT 60

struct FutureKey {
	KeyData *key;
	RECORD record;
	STATE next_state;
	bool pretend_update;
};

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
 * Retrieve a KeyState structure for one of the records of a key.
 * 
 * \param[in] key, key to get the keystate from.
 * \param[in] record, specifies which keystate.
 * \return keystate
 * */
static KeyState&
getRecord(KeyData &key, const RECORD record)
{
	static const char *scmd = "getRecord";
	switch(record) {
		case DS: return key.keyStateDS();
		case DK: return key.keyStateDNSKEY();
		case RD: return key.keyStateRRSIGDNSKEY();
		case RS: return key.keyStateRRSIG();
		default: 
			ods_fatal_exit("[%s] %s Unknown record type (%d), "
				"fault of programmer. Abort.", 
				module_str, scmd, (int)record);
	}
}

/**
 * Return state of a record.
 * 
 * \param[in] key
 * \param[in] record
 * \return state of record.
 * */
static inline STATE
getState(KeyData &key, const RECORD record, 
	const struct FutureKey *future_key)
{
	if (future_key && future_key->pretend_update 
		&& &key == future_key->key 
		&& record == future_key->record)
		return future_key->next_state;
	else
		return (STATE)getRecord(key, record).state();
}

/**
 * Given goal and state, what will be the next state?
 * 
 * This is an implementation of our state diagram. State indicates
 * our current node and goal helps decide which edge to choose. 
 * Input state and return state me be the same: the record is said
 * to be stable.
 * 
 * \param[in] introducing, movement direction of key.
 * \param[in] state, current state of record.
 * \return next state
 * */
static STATE
getDesiredState(const bool introducing, const STATE state)
{
	static const char *scmd = "getDesiredState";
	if (state > NOCARE || state < HID) 
		ods_fatal_exit("[%s] %s Key in unknown state (%d), "
			"Corrupt database? Abort.",  module_str, scmd, (int)state);
	const STATE jmp[2][5] = {{HID, UNR, UNR, HID, NOCARE}, {RUM, OMN, OMN, RUM, NOCARE}};
	return jmp[introducing][(int)state];
}

/**
 * Test a key exist for certain states.
 * 
 * @param k, key to evaluate.
 * @param key, key to compare with
 * @param record, record of said key to compare with
 * @param next_state, desired state of said record. Required if 
 * 			pretend_update is set.
 * @param require_same_algorithm, search for keys with the same
 * 			algorithm as input key, else any algorithm.
 * @param pretend_update, pretend record of key is in state next_state.
 * @param mask, The states to look for in a key. respectively DS, 
 * 			DNSKEY, RRSIG DNSKEY and RRSIG state. NOCARE for a record
 * 			if any will do.
 * @return True IFF exist such key.
 * */
static bool
match(KeyData &k, const struct FutureKey *future_key,
	const bool require_same_algorithm, const STATE mask[4])
{
	if (require_same_algorithm && 
		k.algorithm() != future_key->key->algorithm())
		return false;
	/** Do we need to substitute a state of this key with 
	 * next_state? */
	for (RECORD r = REC_MIN; r < REC_MAX; ++r) {
		/** Do we need to substitute the state of THIS record? */
		if (mask[r] == NOCARE) continue;
		/** no match in this record */
		if (mask[r] != getState(k, r, future_key)) return false;
	}
	return true;
}

/**
 * Test if a key exist with certain states.
 * 
 * @param key_list, list to search in.
 * @param key, key to compare with
 * @param record, record of said key to compare with
 * @param next_state, desired state of said record. Required if 
 * 			pretend_update is set.
 * @param require_same_algorithm, search for keys with the same
 * 			algorithm as input key, else any algorithm.
 * @param pretend_update, pretend record of key is in state next_state.
 * @param mask, The states to look for in a key. respectively DS, 
 * 			DNSKEY, RRSIG DNSKEY and RRSIG state. NOCARE for a record
 * 			if any will do.
 * @return True IFF exist such key.
 * */
static bool
exists_old(KeyDataList &key_list, const struct FutureKey *future_key,
	const bool require_same_algorithm, const STATE mask[4])
{
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if (match(k, future_key, require_same_algorithm, mask))
			return true;
	}
	return false;
}

static int
not_exists(key_data_t** keylist, size_t keylist_size, key_data_t* key,
	int same_algorithm, const key_state_state_t mask[4])
{
	size_t i;

	if (!keylist) {
		return -1;
	}
	if (!key) {
		return -1;
	}

	for (i = 0; i < keylist_size; i++) {
		/*
		 * Skip checking the key we are processing now and if its not the same
		 * algorithm (if same_algorithm is set).
		 */
		if (key == keylist[i]
			|| (same_algorithm && key_data_algorithm(key) != key_data_algorithm(keylist[i])))
		{
			continue;
		}
		/*
		 * Check the states against the mask, for each mask that is not NA we
		 * need a match on that key state. If there is no match we continue.
		 */
		if ((mask[0] != NA
				&& key_state_state(key_data_cached_ds(keylist[i])) != mask[0])
			|| (mask[1] != NA
				&& key_state_state(key_data_cached_dnskey(keylist[i])) != mask[1])
			|| (mask[2] != NA
				&& key_state_state(key_data_cached_rrsigdnskey(keylist[i])) != mask[2])
			|| (mask[3] != NA
				&& key_state_state(key_data_cached_rrsig(keylist[i])) != mask[3]))
		{
			continue;
		}

		/*
		 * We have a match and do not have to continue, return non-error.
		 */
		return 0;
	}

	/*
	 * We got no match, return success.
	 */
	return 1;
}

/** Looks up KeyData from locator string.
 * TODO: find a better approach, can we trick protobuf to cross
 * reference? */
static KeyData *
stringToKeyData(KeyDataList &key_list, const string &locator)
{
	for (int i = 0; i < key_list.numKeys(); i++) {
		if (locator.compare(key_list.key(i).locator()) == 0) {
			return &key_list.key(i);
		}
	}
	return NULL;
}

static bool
isPotentialSuccessor(KeyData &pred_key, const struct FutureKey *future_key, KeyData &succ_key, const RECORD succRelRec)
{
	static const char *scmd = "isPotentialSuccessor";
	/** must at least have record introducing */
	if (getState(succ_key, succRelRec, future_key) != RUM) return false;
	if (pred_key.algorithm() != succ_key.algorithm()) return false;
	switch(future_key->record) {
		case DS: /** intentional fall-through */
		case RS: 
			return getState(succ_key, DK, future_key) == OMN;
		case DK: 
			return  (getState(pred_key, DS, future_key) == OMN) && 
					(getState(succ_key, DS, future_key) == OMN) ||
					(getState(pred_key, RS, future_key) == OMN) && 
					(getState(succ_key, RS, future_key) == OMN) ;
		case RD:
			return false;
		default: 
			ods_fatal_exit("[%s] %s Unknown record type (%d), "
				"fault of programmer. Abort.",
				module_str, scmd, (int)future_key->record);
	}
}

/** True if a path from k_succ to k_pred exists */
static bool
successor_rec(KeyDataList &key_list, KeyDependencyList &dep_list, KeyData &k_succ, 
		const string &k_pred,
		struct FutureKey *future_key, const RECORD succRelRec) 
{
	/** trivial case where there is a direct relation in the present */
	for (int i = 0; i < dep_list.numDeps(); i++) {
		KeyDependency &dep = dep_list.dep(i);
		if (dep.rrType() == succRelRec &&
			dep.fromKey().compare( k_pred ) == 0 &&
			dep_list.dep(i).toKey().compare( k_succ.locator() ) == 0 ) 
			return true;
	}

	/** trivial case where there is a direct relation in the future */
	if (future_key->pretend_update && 
		future_key->key->locator().compare(k_pred) == 0 && 
		isPotentialSuccessor(*future_key->key, future_key, k_succ, succRelRec))
		return true;
	KeyData *prKey = stringToKeyData(key_list, k_pred);
	/** There is no direct relation. Check for indirect where X depends
	 * on S and X in same state as P and X successor of P*/
	for (int i = 0; i < dep_list.numDeps(); i++) {
		KeyDependency &dep = dep_list.dep(i);
		if (dep.rrType() != succRelRec ||
				dep.toKey().compare( k_succ.locator()) != 0) continue;
		//fromKey() is candidate now, must be in same state as k_pred
		KeyData *fromKey = stringToKeyData(key_list, dep.fromKey());
		//TODO, make fine grained. depending on record
		if (getState(*prKey, DS, future_key) != getState(*fromKey, DS, future_key)) continue;
		if (getState(*prKey, DK, future_key) != getState(*fromKey, DK, future_key)) continue;
		if (getState(*prKey, RS, future_key) != getState(*fromKey, RS, future_key)) continue;
		/** state maches, can be build a chain? */
		if (successor_rec(key_list, dep_list, *fromKey, k_pred, future_key, succRelRec)) {
			return true;
		}
	}
	/** There is no direct relation. Check for indirect where X depends
	 * on S and X in same state as P and X successor of P*/
	 //for all X, is S succ of X?
	if (future_key->pretend_update) {
		for (int i = 0; i < key_list.numKeys(); i++) {
			if (key_list.key(i).locator().compare(k_pred) == 0) continue; 
			if (isPotentialSuccessor(key_list.key(i), future_key, k_succ, succRelRec)) {
				if (getState(*prKey, DS, future_key) != getState(key_list.key(i), DS, NULL)) continue;
				if (getState(*prKey, DK, future_key) != getState(key_list.key(i), DK, NULL)) continue;
				if (getState(*prKey, RS, future_key) != getState(key_list.key(i), RS, NULL)) continue;
				if (successor_rec(key_list, dep_list, k_succ, key_list.key(i).locator(), future_key, succRelRec)) {
					return true;
				}
			}
		}
	}
	return false;
}

/** X is a successor of Y if:
 * 		- Exists no Z depending on Y and
 * 		- (Y depends on X or
 * 		- Exist a Z where
 * 			- Z in same state as Y and
 * 			- Z depends on X */
/** True if k_succ is a successor of k_pred */
static bool
successor(KeyDataList &key_list, KeyDependencyList &dep_list, 
		KeyData &k_succ, KeyData &k_pred,
		struct FutureKey *future_key, const RECORD succRelRec) 
{
	/** Nothing may depend on our predecessor */
	for (int i = 0; i < dep_list.numDeps(); i++)
		if ( dep_list.dep(i).toKey().compare( k_pred.locator() ) == 0)
			return false;
	return successor_rec(key_list, dep_list, k_succ, k_pred.locator(), 
		future_key, succRelRec);
}

//Seek 
static bool
exists_with_successor(KeyDependencyList &dep_list, 
	KeyDataList &key_list, struct FutureKey *future_key,
	const bool require_same_algorithm, const STATE mask_pred[4], 
	const STATE mask_succ[4], const RECORD succRelRec)
{
	//Seek potential successor keys
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k_succ = key_list.key(i);
		/** Do we have a key matching mask_succ? */
		if (!match(k_succ, future_key, 
				require_same_algorithm, mask_succ)) {
			continue;
		}
		for (int j = 0; j < key_list.numKeys(); j++) {
			KeyData &k_pred = key_list.key(j);
			/** Do we have a key matching mask_pred? */
			if (!match(k_pred, future_key, require_same_algorithm, mask_pred))
				continue;
			if (successor(key_list, dep_list, k_succ, k_pred, future_key, succRelRec))
				return true;
		}
	}
	return false;
}


/**
 * Simpler exists function without another key,record as reference.
 * 
 * @param key_list, list to search in.
 * @param mask, The states to look for in a key. respectively DS, 
 * 			DNSKEY, RRSIG DNSKEY and RRSIG state. NOCARE for a record
 * 			if any will do.
 * @return True IFF exist such key.
 * */
static bool
exists_anon(KeyDataList &key_list, const STATE mask[4])
{
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		bool match = true;
		for (RECORD r = REC_MIN; r < REC_MAX; ++r) {
			/** Do we need to substitute the state of THIS record? */
			if (mask[r] == NOCARE) continue;
			/** no match in this record, try next key */
			if (mask[r] != getState(k, r, NULL)) {
				match = false;
				break;
			}
		}
		if (match) return true;
	}
	return false;
}

/**
 * Test if all keys are in a good unsigned state.
 * 
 * @param key_list, list to search in.
 * @param key, key to compare with
 * @param record, record of said key to compare with
 * @param next_state, desired state of said record. Required if 
 * 			pretend_update is set.
 * @param pretend_update, pretend record of key is in state next_state.
 * @param mask, The states to look for in a key. respectively DS, 
 * 			DNSKEY, RRSIG DNSKEY and RRSIG state. NOCARE for a record
 * 			if any will do.
 * @param mustHID, the record which must be HIDDEN for each key, 
 * 			otherwise mask must apply.
 * @return True IFF all keys are securely insecure.
 * */
static bool
unsignedOk(KeyDataList &key_list, const struct FutureKey *future_key, 
	const STATE mask[4], const RECORD mustHID)
{
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if (k.algorithm() != future_key->key->algorithm()) continue;
		
		STATE cmp_msk[4];
		for (RECORD r = REC_MIN; r < REC_MAX; ++r)
			cmp_msk[r] = (r == mustHID)?getState(k, r, future_key):mask[r];
		/** If state is hidden this key is okay. */
		if (cmp_msk[mustHID] == HID || cmp_msk[mustHID] == NOCARE)
			continue;
		/** Otherwise, we must test mask */
		if (!exists_old(key_list, future_key, true, cmp_msk))
			return false;
	}
	return true;
}

/** 
 * Checks for existence of DS.
 * 
 * @param key_list, list to search in.
 * @param key, key to compare with
 * @param record, record of said key to compare with
 * @param next_state, desired state of said record. Required if 
 * 			pretend_update is set.
 * @param pretend_update, pretend record of key is in state next_state.
 * @return True IFF a introducing DS exists.
 * */
static bool
rule1_old(KeyDependencyList &dep_list, KeyDataList &key_list,
	struct FutureKey *future_key, bool pretend_update)
{
	const STATE mask_triv[] =  {OMN, NOCARE, NOCARE, NOCARE};
	const STATE mask_dsin[] =  {RUM, NOCARE, NOCARE, NOCARE};
	
	future_key->pretend_update = pretend_update;
	return  
		exists_old(key_list, future_key, false, mask_triv) ||
		exists_old(key_list, future_key, false, mask_dsin);
}
static int
rule1(key_data_t** keylist, size_t keylist_size, key_data_t* key)
{
	static const key_state_state_t mask[2][4] = {
		/*
		 * This indicates a good key state.
		 */
		{ OMNIPRESENT, NA, NA, NA },
		/*
		 * This indicates that the DS is introducing.
		 */
		{ RUMOURED, NA, NA, NA }
	};

	if (!keylist) {
		return -1;
	}
	if (!key) {
		return -1;
	}

	if (not_exists(keylist, keylist_size, key, 1, mask[0])
		&& not_exists(keylist, keylist_size, key, 1, mask[1]))
	{
		/*
		 * None of the required mask was found, return non-zero to indicate that
		 * the rule has been broken.
		 */
		return 1;
	}
	return 0;
}

/** 
 * Checks for a valid DNSKEY situation.
 * 
 * @param key_list, list to search in.
 * @param key, key to compare with
 * @param record, record of said key to compare with
 * @param next_state, desired state of said record. Required if 
 * 			pretend_update is set.
 * @param pretend_update, pretend record of key is in state next_state.
 * @return True IFF one of requirements is met.
 * */
static bool
rule2_old(KeyDependencyList &dep_list, KeyDataList &key_list,
	struct FutureKey *future_key, bool pretend_update)
{
	const STATE mask_unsg[] =  {HID, OMN, OMN, NOCARE};
	const STATE mask_triv[] =  {OMN, OMN, OMN, NOCARE};
	const STATE mask_ds_i[] =  {RUM, OMN, OMN, NOCARE};
	const STATE mask_ds_o[] =  {UNR, OMN, OMN, NOCARE};
	const STATE mask_k_i1[] =  {OMN, RUM, RUM, NOCARE};
	const STATE mask_k_i2[] =  {OMN, OMN, RUM, NOCARE};
	const STATE mask_k_o1[] =  {OMN, UNR, UNR, NOCARE};
	const STATE mask_k_o2[] =  {OMN, UNR, OMN, NOCARE};

	future_key->pretend_update = pretend_update;
	/** for performance the lighter, more-likely-to-be-true test are
	 * performed first. */
	
	return
		exists_old(key_list, future_key, true, mask_triv) ||
		
		exists_with_successor(dep_list, key_list, future_key, true, mask_ds_o, mask_ds_i, DS) ||

		exists_with_successor(dep_list, key_list, future_key, true, mask_k_o1, mask_k_i1, DK) ||
		exists_with_successor(dep_list, key_list, future_key, true, mask_k_o1, mask_k_i2, DK) ||
		exists_with_successor(dep_list, key_list, future_key, true, mask_k_o2, mask_k_i1, DK) ||
		exists_with_successor(dep_list, key_list, future_key, true, mask_k_o2, mask_k_i2, DK) ||
		
		unsignedOk(key_list, future_key, mask_unsg, DS);
}
static int
rule2(key_data_t** keylist, size_t keylist_size, key_data_t* key)
{
	static const key_state_state_t mask[1][4] = {
		/*
		 * This indicates a good key state.
		 */
		{ OMNIPRESENT, OMNIPRESENT, OMNIPRESENT, NA }
	};

	if (!keylist) {
		return -1;
	}
	if (!key) {
		return -1;
	}

	if (not_exists(keylist, keylist_size, key, 1, mask[0]))
	{
		/*
		 * None of the required mask was found, return non-zero to indicate that
		 * the rule has been broken.
		 */
		return 1;
	}
	return 0;
}

/** 
 * Checks for a valid signature situation.
 * 
 * @param key_list, list to search in.
 * @param key, key to compare with
 * @param record, record of said key to compare with
 * @param next_state, desired state of said record. Required if 
 * 			pretend_update is set.
 * @param pretend_update, pretend record of key is in state next_state.
 * @return True IFF one of requirements is met.
 * */
static bool
rule3_old(KeyDependencyList &dep_list, KeyDataList &key_list,
	struct FutureKey *future_key, bool pretend_update)
{
	const STATE mask_triv[] =  {NOCARE, OMN, NOCARE, OMN};
	const STATE mask_keyi[] =  {NOCARE, RUM, NOCARE, OMN};
	const STATE mask_keyo[] =  {NOCARE, UNR, NOCARE, OMN};
	const STATE mask_sigi[] =  {NOCARE, OMN, NOCARE, RUM};
	const STATE mask_sigo[] =  {NOCARE, OMN, NOCARE, UNR};
	const STATE mask_unsg[] =  {NOCARE, HID, NOCARE, OMN};

	future_key->pretend_update = pretend_update;
	/** for performance the lighter, more-likely-to-be-true test are
	 * performed first. */
	return
		exists_old(key_list, future_key, true, mask_triv) ||
		exists_with_successor(dep_list, key_list, future_key, true, mask_keyo, mask_keyi, DK) ||
		exists_with_successor(dep_list, key_list, future_key, true, mask_sigo, mask_sigi, RS) ||
		unsignedOk(key_list, future_key, mask_unsg, DK);
}
static int
rule3(key_data_t** keylist, size_t keylist_size, key_data_t* key)
{
	static const key_state_state_t mask[2][4] = {
		/*
		 * This indicates a good key state.
		 */
		{ NA, OMNIPRESENT, NA, OMNIPRESENT }
	};

	if (!keylist) {
		return -1;
	}
	if (!key) {
		return -1;
	}

	if (not_exists(keylist, keylist_size, key, 1, mask[0]))
	{
		/*
		 * None of the required mask was found, return non-zero to indicate that
		 * the rule has been broken.
		 */
		return 1;
	}
	return 0;
}

/**
 * Checks of transition to next_state maintains validity of zone.
 * 
 * Check all 3 rules. Any of the rules that are true in the current 
 * situation (ideally all) must be true in the desired situation.
 * No decay is allowed.
 * 
 * @param key_list, list to search in.
 * @param key, key to compare with
 * @param record, record of said key to compare with
 * @param next_state, desired state of said record.
 * @return True if transition is okay DNSSEC-wise.
 * */
static bool
dnssecApproval(KeyDependencyList &dep_list, KeyDataList &key_list, 
	struct FutureKey *future_key, bool allow_unsigned)
{
	return 
		(allow_unsigned ||
		 !rule1_old(dep_list, key_list, future_key, false) ||
		  rule1_old(dep_list, key_list, future_key, true ) ) &&
		(!rule2_old(dep_list, key_list, future_key, false) ||
		  rule2_old(dep_list, key_list, future_key, true ) ) &&
		(!rule3_old(dep_list, key_list, future_key, false) ||
		  rule3_old(dep_list, key_list, future_key, true ) );
}

/**
 * At what time may this transition take place?
 * 
 * Given a record, its next state, and its last change time when may 
 * apply the transition? This is largely policy related.
 * 
 * @param zone
 * @param record we are testing
 * @param next_state of record 
 * @param lastchange of record
 * @param ttl of record, *may* be different from policy.
 * @return absolute time
 * */
static time_t
minTransitionTime(EnforcerZone &zone, const RECORD record,
	const STATE next_state, const time_t lastchange, const int ttl)
{
	static const char *scmd = "minTransitionTime";
	const Policy *policy = zone.policy();

	/** We may freely move a record to a uncertain state. */
	if (next_state == RUM || next_state == UNR) return lastchange;

	switch(record) {
		case DS:
			return addtime(lastchange, ttl
					+ policy->parent().registrationdelay()
					+ policy->parent().propagationdelay());
		/* TODO: 5011 will create special case here */
		case DK: /** intentional fall-through */
		case RD:
			return addtime(lastchange, ttl
				+ policy->zone().propagationdelay()
				+ (next_state == OMN
					? policy->keys().publishsafety()
					: policy->keys().retiresafety()));
		case RS:
			return addtime(lastchange, ttl
				+ policy->zone().propagationdelay());
		default: 
			ods_fatal_exit("[%s] %s Unknown record type (%d), "
				"fault of programmer. Abort.",
				module_str, scmd, (int)record);
	}
}

/**
 * Make sure records are introduced in correct order.
 * 
 * Make sure records are introduced in correct order. Only look at the 
 * policy, timing and validity is done in another function.
 * 
 * \param[in] key
 * \param[in] record
 * \param[in] next_state 
 * \return True iff policy allows transition of record to state.
 * */
static bool
policyApproval(KeyDataList &key_list, struct FutureKey *future_key)
{
	static const char *scmd = "policyApproval";
	
	/** once the record is introduced the policy has no influence. */
	if (future_key->next_state != RUM) return true;
	
	const STATE mask_sig[] =  {NOCARE, OMN, NOCARE, OMN};
	const STATE mask_dnskey[] =  {OMN, OMN, OMN, NOCARE};
	
	switch(future_key->record) {
		case DS:
			/** If we want to minimize the DS transitions make sure
			 * the DNSKEY is fully propagated. */
			return !future_key->key->keyStateDS().minimize() || 
				getState(*future_key->key, DK, NULL) == OMN;
		case DK:
			/** 1) there are no restrictions */
			if (!future_key->key->keyStateDNSKEY().minimize()) return true;
			/** 2) If minimize, signatures must ALWAYS be propagated 
			 * for CSK and ZSK */
			if (getState(*future_key->key, RS, NULL) != OMN && 
				getState(*future_key->key, RS, NULL) != NOCARE)
				return false;
			/** 3) wait till DS is introduced */
			if (getState(*future_key->key, DS, NULL) == OMN ||
				getState(*future_key->key, DS, NULL) == NOCARE)
				return true;
			/** 4) Except, we might be doing algorithm rollover.
			 * if no other good KSK available, ignore minimize flag*/
			return !exists_old(key_list, future_key, true, mask_dnskey);
		case RD:
			/** The only time not to introduce RRSIG DNSKEY is when the
			 * DNSKEY is still hidden. */
			return getState(*future_key->key, DK, NULL) != HID;
		case RS:
			/** 1) there are no restrictions */
			if (!future_key->key->keyStateRRSIG().minimize()) return true;
			/** 2) wait till DNSKEY is introduced */
			if (getState(*future_key->key, DK, NULL) == OMN) return true;
			/** 3) Except, we might be doing algorithm rollover
			 * if no other good ZSK available, ignore minimize flag */
			return !exists_old(key_list, future_key, true, mask_sig);
		default: 
			ods_fatal_exit("[%s] %s Unknown record type (%d), "
				"fault of programmer. Abort.",
				module_str, scmd, (int)future_key->record);
	}
}

/** given the zone, what TTL should be used for record?
 * 
 * Normally we use the TTL from the policy. However a larger TTL might
 * have been published in the near past causing this record to take 
 * extra time to propagate */
static int
getZoneTTL(EnforcerZone &zone, const RECORD record, const time_t now)
{
	static const char *scmd = "getTTL";
	const Policy *policy = zone.policy();
	
	time_t endDate;
	int recordTTL;
	
	switch(record) {
		case DS:
			endDate = zone.ttlEnddateDs();
			recordTTL = policy->parent().ttlds();
			break;
		case DK: /** intentional fall-through */
		case RD:
			endDate = zone.ttlEnddateDk();
			recordTTL = policy->keys().ttl();
			break;
		case RS:
			endDate = zone.ttlEnddateRs();
			recordTTL = max(min(policy->zone().ttl(),
							policy->zone().min()), 
							zone.max_zone_ttl());
			break;				  
		default: 
			ods_fatal_exit("[%s] %s Unknown record type (%d), "
				"fault of programmer. Abort.",
				module_str, scmd, (int)record);
	}
	return max((int)difftime(endDate, now), recordTTL);
}

/**
 * Update the state of a record. Save the time of this change for
 * later use.
 * 
 * @param key
 * @param record
 * @param state
 * @param now, the current time.
 * */
static void
setState(EnforcerZone &zone, const struct FutureKey *future_key, 
	const time_t now)
{
	KeyState &ks = getRecord(*future_key->key, future_key->record);
	ks.setState(future_key->next_state);
	ks.setLastChange(now);
	ks.setTtl(getZoneTTL(zone, future_key->record, now));
	zone.setSignerConfNeedsWriting(true);
}

/** Find out if this key can be in a successor relation */
static bool
isSuccessable(const struct FutureKey *future_key)
{
	static const char *scmd = "isSuccessable";
	
	if (future_key->next_state != UNR) return false;
	switch(future_key->record) {
		case DS: /** intentional fall-through */
		case RS: 
			if (getState(*future_key->key, DK, NULL) != OMN) return false;
			break;
		case RD:
			return false;
		case DK: 
			if ((getState(*future_key->key, DS, NULL) != OMN) && 
					(getState(*future_key->key, RS, NULL) != OMN))
				return false;
			break;
		default: 
			ods_fatal_exit("[%s] %s Unknown record type (%d), "
				"fault of programmer. Abort.",
				module_str, scmd, (int)future_key->record);
	}
	return true;
}

static void
markSuccessors(KeyDependencyList &dep_list, KeyDataList &key_list, 
	struct FutureKey *future_key)
{
	static const char *scmd = "markSuccessors";
	if (!isSuccessable(future_key)) return;
	/** Which keys can be potential successors? */
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &key_i = key_list.key(i);
		//TODO: do this for any record type?
		if (isPotentialSuccessor(*future_key->key, future_key, key_i, future_key->record)) 
			dep_list.addNewDependency(future_key->key, &key_i, future_key->record);
	}
}

static int
processKeyState(zone_t* zone, int *zone_updated, key_data_t** keylist,
	size_t keylist_size, key_data_t* key, key_state_t* state,
	int* change, int allow_unsigned)
{
	key_state_state_t desired_state = KEY_STATE_STATE_INVALID;
	static const char *scmd = "processKeyState";
	size_t i;
	static const key_state_state_t dnskey_algorithm_rollover[4] = { OMNIPRESENT, OMNIPRESENT, OMNIPRESENT, NA };
	static const key_state_state_t rrsig_algorithm_rollover[4] = { NA, OMNIPRESENT, NA, OMNIPRESENT };

	/*
	 * Given goal and state, what will be the next state?
	 */
	if (!key_data_introducing(key)) {
		/*
		 * We are outroducing this key so we would like to move rumoured and
		 * omnipresent keys to unretentive and unretentive keys to hidden.
		 */
		switch (key_state_state(state)) {
		case HIDDEN:
			desired_state = HIDDEN;
			break;

		case RUMOURED:
			desired_state = UNRETENTIVE;
			break;

		case OMNIPRESENT:
			desired_state = UNRETENTIVE;
			break;

		case UNRETENTIVE:
			desired_state = HIDDEN;
			break;

		case NA:
			desired_state = NA;
			break;

		default:
			break;
		}
	}
	else {
		/*
		 * We are introducing this key so we would like to move hidden and
		 * unretentive keys to rumoured and rumoured keys to omnipresent.
		 */
		switch (key_state_state(state)) {
		case HIDDEN:
			desired_state = RUMOURED;
			break;

		case RUMOURED:
			desired_state = OMNIPRESENT;
			break;

		case OMNIPRESENT:
			desired_state = OMNIPRESENT;
			break;

		case UNRETENTIVE:
			desired_state = RUMOURED;
			break;

		case NA:
			desired_state = NA;
			break;

		default:
			break;
		}
	}

	/*
	 * The desired_state is invalid something went wrong and we should return
	 * an error.
	 */
	if (desired_state == KEY_STATE_STATE_INVALID) {
		return 1;
	}

	/*
	 * If there is no change in key state we return.
	 */
	if (key_state_state(state) == desired_state) {
		return 0;
	}

	/*
	 * If the key state is a DS then we need to check if we still are waiting
	 * for user input before we can transition the key.
	 */
	if (key_state_type(state) == KEY_STATE_TYPE_DS) {
		if ((desired_state == OMNIPRESENT
				&& key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_SEEN)
			|| (desired_state == HIDDEN
				&& key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_UNSUBMITTED))
		{
			return 0;
		}
	}

	ods_log_verbose("[%s] %s: May %s in state %s transition to %s?", module_str, scmd,
		hsm_key_locator(key_data_cached_hsm_key(key)),
		key_state_state_text(state),
		key_state_enum_set_state[desired_state]);

	/*
	 * Check if policy prevents transition if the next state is rumoured.
	 */
	if (desired_state == RUMOURED) {
		switch (key_state_type(state)) {
		case KEY_STATE_TYPE_DS:
			/*
			 * If we want to minimize the DS transitions make sure the DNSKEY is
			 * fully propagated.
			 */
			if (key_state_minimize(state)
				&& key_state_state(key_data_cached_dnskey(key)) != OMNIPRESENT)
			{
				/*
				 * DNSKEY is not fully propagated so we will not do any transitions.
				 */
				return 0;
			}
			break;

		case KEY_STATE_TYPE_DNSKEY:
			if (!key_state_minimize(state)) {
				/*
				 * There are no restrictions for the DNSKEY transition so we can
				 * just continue.
				 */
				break;
			}

			/*
			 * Check that signatures has been propagated for CSK/ZSK.
			 *
			 * TODO: How is this related to CSK/ZSK, there is no check for key_data_role().
			 */
			if (key_state_state(key_data_cached_rrsig(key)) != OMNIPRESENT
				&& key_state_state(key_data_cached_rrsig(key)) != NA)
			{
				/*
				 * RRSIG not fully propagated so we will not do any transitions.
				 */
				return 0;
			}

			/*
			 * Check if the DS is introduced and continue if it is.
			 */
			if (key_state_state(key_data_cached_ds(key)) == OMNIPRESENT
				|| key_state_state(key_data_cached_ds(key)) == NA)
			{
				break;
			}

			/*
			 * We might be doing an algorithm rollover so we check if there are
			 * no other good KSK available and ignore the minimize flag if so.
			 *
			 * TODO: How is this related to KSK/CSK? There are no check for key_data_role().
			 */
			if (!not_exists(keylist, keylist_size, key, 1, dnskey_algorithm_rollover)) {
				/*
				 * We found a good key, so we will not do any transition.
				 */
				return 0;
			}
			break;

		case KEY_STATE_TYPE_RRSIGDNSKEY:
			/*
			 * The only time not to introduce RRSIG DNSKEY is when the DNSKEY is
			 * still hidden.
			 *
			 * TODO: How do we know we are introducing the RRSIG DNSKEY? We might be
			 * outroducing it.
			 */
			if (key_state_state(key_data_cached_dnskey(key)) == HIDDEN) {
				return 0;
			}
			break;

		case KEY_STATE_TYPE_RRSIG:
			if (!key_state_minimize(state)) {
				/*
				 * There are no restrictions for the RRSIG transition so we can
				 * just continue.
				 */
				break;
			}

			/*
			 * Check if the DNSKEY is introduced and continue if it is.
			 */
			if (key_state_state(key_data_cached_dnskey(key)) == OMNIPRESENT) {
				break;
			}

			/*
			 * We might be doing an algorithm rollover so we check if there are
			 * no other good ZSK available and ignore the minimize flag if so.
			 *
			 * TODO: How is this related to ZSK/CSK? There are no check for key_data_role().
			 */
			if (!not_exists(keylist, keylist_size, key, 1, rrsig_algorithm_rollover)) {
				/*
				 * We found a good key, so we will not do any transition.
				 */
				return 0;
			}
			break;

		default:
			return 1;
		}
	}

	/*
	 * Check if DNSSEC state will be invalid by the transition.
	 *
	 * Process all DNSSEC rules, if anyone returns non-zero it means that
	 * its rule has been broken and we can not transition.
	 *
	 * rule1 - If signed, check valid DS state
	 * rule2 - TODO
	 * rule3 - TODO
	 */
	if ((!allow_unsigned && rule1(keylist, keylist_size, key))
		|| rule2(keylist, keylist_size, key)
		|| rule3(keylist, keylist_size, key))
	{
		return 0;
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
updateZone(policy_t* policy, zone_t* zone, const time_t now,
	int allow_unsigned, int *zone_updated)
{
	time_t returntime_zone = -1;
	unsigned int ttl;
	key_data_list_t *key_list;
	const key_data_t* key;
	key_data_t** keylist = NULL;
	static const char *scmd = "updateZone";
	size_t keylist_size, i;
	int change;

	if (!policy) {
		return returntime_zone;
	}
	if (!zone) {
		return returntime_zone;
	}
	if (!zone_updated) {
		return returntime_zone;
	}

	/*
	 * Get all key data/state/hsm objects for later processing.
	 */
	if (!(key_list = zone_get_keys(zone))
		|| key_data_list_fetch_all(key_list))
	{
		/* TODO: better log error */
		ods_log_debug("[%s] %s: error zone_get_keys() || key_data_list_fetch_all()", module_str, scmd);
		key_data_list_free(key_list);
		return returntime_zone;
	}
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
			ods_log_debug("[%s] %s: error calloc(keylist_size)", module_str, scmd);
			key_data_list_free(key_list);
			return returntime_zone;
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
				ods_log_debug("[%s] %s: error key_data_list cache", module_str, scmd);
				for (i = 0; i < keylist_size; i++) {
					if (keylist[i]) {
						key_data_free(keylist[i]);
					}
				}
				free(keylist);
				key_data_list_free(key_list);
				return returntime_zone;
			}
		}
	}
	key_data_list_free(key_list);

	/*
	 * This code keeps track of TTL changes. If in the past a large TTL is used,
	 * our keys *may* need to transition extra careful to make sure each
	 * resolver picks up the RRset. When this date passes we may start using the
	 * policies TTL.
	 */
	if (zone_ttl_end_ds(zone) <= now) {
		if (!zone_set_ttl_end_ds(zone, addtime(now, policy_parent_ds_ttl(policy)))) {
			*zone_updated = 1;
		}
	}
	if (zone_ttl_end_dk(zone) <= now) {
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
		if (!zone_set_ttl_end_dk(zone, ttl)) {
			*zone_updated = 1;
		}
	}
	if (zone_ttl_end_rs(zone) <= now) {
		if (policy_denial_type(policy) == POLICY_DENIAL_TYPE_NSEC3) {
			ttl = max(policy_signatures_max_zone_ttl(policy), policy_denial_ttl(policy));
		}
		else {
			ttl = policy_signatures_max_zone_ttl(policy);
		}
		if (!zone_set_ttl_end_rs(zone, addtime(now, max(
			min(policy_zone_soa_ttl(policy), policy_zone_soa_minimum(policy)),
				ttl))))
		{
			*zone_updated = 1;
		}
	}

	/*
	 * Keep looping till there are no state changes and find the earliest update
	 * time to return.
	 */
	do {
		change = 0;
		for (i = 0; i < keylist_size; i++) {
			ods_log_verbose("[%s] %s: processing key %s", module_str, scmd,
				hsm_key_locator(key_data_cached_hsm_key(keylist[i])));

			if (processKeyState(zone, zone_updated, keylist, keylist_size, keylist[i], key_data_get_cached_ds(keylist[i]), &change, allow_unsigned)
				|| processKeyState(zone, zone_updated, keylist, keylist_size, keylist[i], key_data_get_cached_dnskey(keylist[i]), &change, allow_unsigned)
				|| processKeyState(zone, zone_updated, keylist, keylist_size, keylist[i], key_data_get_cached_rrsigdnskey(keylist[i]), &change, allow_unsigned)
				|| processKeyState(zone, zone_updated, keylist, keylist_size, keylist[i], key_data_get_cached_rrsig(keylist[i]), &change, allow_unsigned))
			{
				/* TODO: handle error */
			}
		}
	} while (change);

	/*
	 * Release the cached objects.
	 */
	for (i = 0; i < keylist_size; i++) {
		if (keylist[i]) {
			key_data_free(keylist[i]);
		}
	}
	free(keylist);

	return returntime_zone;
}

static time_t
updateZone_old(EnforcerZone &zone, const time_t now, bool allow_unsigned,
	HsmKeyFactory &keyfactory)
{
	time_t returntime_zone = -1;
	time_t returntime_key;
	bool change;
	KeyDependencyList &dep_list = zone.keyDependencyList();
	KeyDataList &key_list = zone.keyDataList();
	const Policy *policy = zone.policy();
	static const char *scmd = "updateZone";
	ods_log_verbose("[%s] %s", module_str, scmd);
	int ttl;
	const STATE omnkey[] =  {NOCARE, OMN, NOCARE, NOCARE};
	struct FutureKey future_key;

	/** This code keeps track of TTL changes. If in the past a large
	 * TTL is used, our keys *may* need to transition extra 
	 * careful to make sure each resolver picks up the RRset.
	 * When this date passes we may start using the policies TTL. */
	if (zone.ttlEnddateDs() <= now)
		zone.setTtlEnddateDs(addtime(now, policy->parent().ttlds()));
	if (zone.ttlEnddateDk() <= now) {
		if (!exists_anon(key_list, omnkey)) {
			/** If no DNSKEY is currently published we must take
			 * negative caching into account. */
			ttl = max(policy->keys().ttl(), min(policy->zone().ttl(), 
				policy->zone().min()));
		} else {
			ttl = policy->keys().ttl();
		}
		zone.setTtlEnddateDk(addtime(now, ttl));
	}
	if (zone.ttlEnddateRs() <= now)
		zone.setTtlEnddateRs(addtime(now, 
				max(min(policy->zone().ttl(), policy->zone().min()), 
					zone.max_zone_ttl()))); 

	/** Keep looping till there are no state changes.
	 * Find the earliest update time */
	do {
		change = false;
		for (int i = 0; i < key_list.numKeys(); i++) {
			KeyData &key = key_list.key(i);
			ods_log_verbose("[%s] %s processing key %s", module_str, 
				scmd, key.locator().c_str());

			/** 
			 * Note: We *could* make a check here to see if
			 * DS && DK || DK && RS .minimize() == True
			 * if so, we could do:
			 *  - nothing (key will probably get stuck, current situation)
			 *  - fatal exit (because we suspect db corruption)
			 *  - flip one of the bits, log, continue
			 **/
			
			future_key.key = &key;
			
			for (RECORD record = REC_MIN; record < REC_MAX; ++record) {
				STATE state = getState(key, record, NULL);
				STATE next_state = getDesiredState(key.introducing(), state);
				
				future_key.record = record;
				future_key.next_state = next_state;
				
				/** record is stable */
				if (state == next_state) continue;
				/** This record waits for user input */
				if (record == DS) {
					if (next_state == OMN && key.dsAtParent() != DS_SEEN)
						continue;
					if (next_state == HID && key.dsAtParent() != DS_UNSUBMITTED)
						continue;
				}
				ods_log_verbose("[%s] %s May %s transition to %s?", 
					module_str, scmd, RECORDAMES[(int)record], 
					STATENAMES[(int)next_state]);
				
				/** Policy prevents transition */
				if (!policyApproval(key_list, &future_key)) continue;
				ods_log_verbose("[%s] %s Policy says we can (1/3)", 
					module_str, scmd);
				
				/** Would be invalid DNSSEC state */
				if (!dnssecApproval(dep_list, key_list, &future_key, allow_unsigned))
					continue;
				ods_log_verbose("[%s] %s DNSSEC says we can (2/3)", 
					module_str, scmd);
				
				time_t returntime_key = minTransitionTime(zone, record, 
					next_state, getRecord(key, record).lastChange(), 
					getZoneTTL(zone, record, now));

				/** If this is an RRSIG and the DNSKEY is omnipresent
				 * and next state is a certain state, wait an additional 
				 * signature lifetime to allow for 'smooth rollover'. */
				if  (record == RS && getState(key, DK, NULL) == OMN &&
						(next_state == OMN || next_state == HID) ) {
					/** jitter and valdefault default to 0 */
					returntime_key = addtime(returntime_key, 
							policy->signatures().jitter() + 
							max(policy->signatures().valdefault(), 
								policy->signatures().valdenial()) +
							policy->signatures().resign() - 
							policy->signatures().refresh() );
				}

				/** It is to soon to make this change. Schedule it. */
				if (returntime_key > now) {
					minTime(returntime_key, &returntime_zone);
					continue;
				}

				ods_log_verbose("[%s] %s Timing says we can (3/3) now: %d key: %d", 
					module_str, scmd, now, returntime_key);

				/** A record can only reach Omnipresent if properly backed up */
				HsmKey *hsmkey;
				if (next_state == OMN) {
					if (!keyfactory.GetHsmKeyByLocator(key.locator(), 
						&hsmkey)) {
						/* fishy, this key has no key material! */
						ods_fatal_exit("[%s] %s Key material associated with "
								"key (%s) not found in database. Abort.",
								module_str, scmd, key.locator().c_str());
					} 
					/* if backup required but not backed up: deny transition */
					if (hsmkey->requirebackup() && !hsmkey->backedup()) {
						ods_log_crit("[%s] %s Ready for transition "
							"but key material not backed up yet (%s)", 
							module_str, scmd, key.locator().c_str());
						/* Try again in 60 seconds */
						returntime_key = addtime(now, 60); 
						minTime(returntime_key, &returntime_zone);
						continue;
					}
				}

				/** If we are handling a DS we depend on the user or 
				 * some other external process. We must communicate
				 * through the DSSeen and -submit flags */
				if (record == DS) {
					/** Ask the user to submit the DS to the parent */
					if (next_state == RUM) {
						switch(key.dsAtParent()) {
							case DS_SEEN:
							case DS_SUBMIT:
							case DS_SUBMITTED:
								break;
							case DS_RETRACT:
								/** Hypothetical case where we 
								 * reintroduce keys */
								key.setDsAtParent(DS_SUBMITTED);
								break;
							default:
								key.setDsAtParent(DS_SUBMIT);
						}
					}
					/** Ask the user to remove the DS from the parent */
					else if (next_state == UNR) {
						switch(key.dsAtParent()) {
							case DS_SUBMIT:
								/** Never submitted
								 * NOTE: not safe if we support 
								 * reintroduction of keys. */
								key.setDsAtParent(DS_UNSUBMITTED);
								break;
							case DS_UNSUBMITTED:
							case DS_RETRACTED:
							case DS_RETRACT:
								break;
							default:
								key.setDsAtParent(DS_RETRACT);
						}
					}
				}

				/** We've passed all tests! Make the transition */
				setState(zone, &future_key, now);
				markSuccessors(dep_list, key_list, &future_key);
				change = true;
			}
		}
	} while (change);
	return returntime_zone;
}

/**
 * Search for youngest key in use by any zone with this policy
 * with at least the roles requested. See if it isn't expired.
 * also, check if it isn't in zone already. Also length, algorithm
 * must match and it must be a first generation key.
 * */
//~ bool 
//~ getLastReusableKey(EnforcerZone &zone,
	//~ const Policy *policy, const KeyRole role,
	//~ int bits, const string &repository, int algorithm, 
	//~ const time_t now, HsmKey **ppKey,
	//~ HsmKeyFactory &keyfactory, int lifetime)
//~ {
	//~ static const char *scmd = "getLastReusableKey";
	//~ 
	//~ if (!keyfactory.UseSharedKey(bits, repository, policy->name(), 
		//~ algorithm, role, zone.name(), ppKey))
		//~ return false;
	//~ 
	//~ /** UseSharedKey() promised us a match, we'd better crash. */
	//~ if (*ppKey == NULL)
		//~ ods_fatal_exit("[%s] %s Keyfactory promised key but did not give it",
			//~ module_str, scmd);
	//~ 
	//~ /** Key must (still) be in use */
	//~ if (now < (*ppKey)->inception() + lifetime) return true;
	//~ 
	//~ /** Clean up, was set by default by UseSharedKey(), unset */
	//~ (*ppKey)->setUsedByZone(zone.name(), false);
	//~ return false;
//~ }

static const hsm_key_t*
getLastReusableKey(key_data_list_t *key_list, const policy_key_t *pkey)
{
	const key_data_t *key;
	const hsm_key_t *hkey, *hkey_young = NULL;
	hsm_key_list_t* hsmkeylist;
	int match;
	int cmp;

	if (!key_list) {
		return NULL;
	}
	if (!pkey) {
		return NULL;
	}

	/*
	 * Get a reusable key for this policy key.
	 */

	/* TODO: We still need to filter on role and not-in-use by zone */
	
	hsmkeylist = hsm_key_list_new_get_by_policy_key(pkey);
	for (hkey = hsm_key_list_begin(hsmkeylist); hkey;
		hsm_key_list_next(hsmkeylist))
	{
		/** only match if the hkey has at least the role(s) of pkey */
		if ((~hsm_key_role(hkey) & policy_key_role(pkey)) != 0)
			continue;

		/** Now find out if hsmkey is in used by zone */
		for (match = 0, key = key_data_list_begin(key_list); key; key_data_list_next(key_list)) {
			if (!db_value_cmp(key_data_hsm_key_id(key), hsm_key_id(hkey), &cmp)
				&& cmp == 0)
			{
				/** we have match, so this hsm_key is no good */
				match = 1;
				break;
			}
		}
		if (match) continue;

		/** This key matches, is it newer? */
		if (!hkey_young || hsm_key_inception(hkey_young) < hsm_key_inception(hkey))
			hkey_young = hkey;
	}

	hsm_key_list_free(hsmkeylist);
	return hkey_young;
}

/**
 * Abstraction to generalize different kind of keys. 
 * return number of keys _in_a_policy_ 
 * */
static int
numberOfKeyConfigs(const KeyList &policyKeys, const KeyRole role)
{
	static const char *scmd = "numberOfKeyConfigs";
	switch (role) {
		case KSK: return policyKeys.ksk_size();
		case ZSK: return policyKeys.zsk_size();
		case CSK: return policyKeys.csk_size();
		default:
			ods_fatal_exit("[%s] %s Unknow Role: (%d)", 
					module_str, scmd, role); /* report a bug! */
	}
}

/**
 * Finds the policy parameters of the Nth key with role. 
 * 
 * Abstraction to generalize different kind of keys. 
 * Note: a better solution would be inheritance.
 * 
 * \param[in] policyKeys, Keys structure from Policy
 * \param[in] index, Nth key in policyKeys, see numberOfKeyConfigs() 
 * 					for count
 * \param[in] role, sort of key you are looking for.
 * \param[out] bits
 * \param[out] algorithm
 * \param[out] lifetime
 * \param[out] repository
 * \param[out] manual
 * */
static void
keyProperties(const KeyList &policyKeys, const int index, const KeyRole role,
	int *bits, int *algorithm, int *lifetime, string &repository,
	bool *manual, int *rollover_type)
{
	static const char *scmd = "keyProperties";
	
	/** Programming error, report a bug! */
	if (index >= numberOfKeyConfigs(policyKeys, role)) 
		ods_fatal_exit("[%s] %s Index out of bounds", module_str, scmd); 
		
	switch (role) {
		case KSK:
			*bits	   = policyKeys.ksk(index).bits();
			*algorithm = policyKeys.ksk(index).algorithm();
			*lifetime  = policyKeys.ksk(index).lifetime();
			*manual    = policyKeys.ksk(index).manual_rollover();
			repository.assign(policyKeys.ksk(index).repository());
			*rollover_type = policyKeys.ksk(index).rollover_type();
			break;
		case ZSK:
			*bits	   = policyKeys.zsk(index).bits();
			*algorithm = policyKeys.zsk(index).algorithm();
			*lifetime  = policyKeys.zsk(index).lifetime();
			*manual    = policyKeys.zsk(index).manual_rollover();
			repository.assign(policyKeys.zsk(index).repository());
			*rollover_type = policyKeys.zsk(index).rollover_type();
			break;
		case CSK:
			*bits	   = policyKeys.csk(index).bits();
			*algorithm = policyKeys.csk(index).algorithm();
			*lifetime  = policyKeys.csk(index).lifetime();
			*manual    = policyKeys.csk(index).manual_rollover();
			repository.assign(policyKeys.csk(index).repository());
			*rollover_type = policyKeys.csk(index).rollover_type();
			break;
		default:
			/** Programming error, report a bug! */
			ods_fatal_exit("[%s] %s Unknow Role: (%d)",
				module_str, scmd, role);
	}
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
existsPolicyForKey(policy_key_list *policykeylist, const key_data_t *key)
{
	static const char *scmd = "existsPolicyForKey";
	const policy_key *pkey;
	hsm_key_t *hkey;

	if (!policykeylist) {
		return -1;
	}
	if (!key) {
		return -1;
	}

	if (!(hkey = key_data_get_hsm_key(key))) {
		/** This key is not associated with actual key material! 
		 * This is a bug or database corruption.
		 * Crashing here is an option but we just return false so the 
		 * key will be thrown away in a graceful manner.*/
		ods_log_verbose("[%s] %s no hsmkey!", module_str, scmd);
		return 0;
	}
	pkey = policy_key_list_begin(policykeylist);
	while (pkey) {
		if (hsm_key_repository(hkey) && policy_key_repository(pkey) &&
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

static const key_data_t*
youngestKeyForConfig(key_data_list_t *key_list, const policy_key_t *pkey)
{
	const key_data_t *key = NULL, *youngest = NULL;
	hsm_key_t *hsmkey = NULL;

	if (!key_list) {
		return NULL;
	}
	if (!pkey) {
		return NULL;
	}
	
	/*
	 * Must match: role, bits, algorithm and repository.
	 */
	for (key = key_data_list_begin(key_list); key;
		key_data_list_next(key_list))
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
		if (!youngest || key_data_inception(youngest) > key_data_inception(key))
			youngest = key;
	}
	return youngest;
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
		key_data_list_next(key_list))
	{
		if (policy_key_algorithm(pkey) == key_data_algorithm(key) &&
			(int)policy_key_role(pkey) == (int)key_data_role(key))
		{
			return 1;
		}
	}
	return 0;
}

/* 0 == ok, otherwise dberr or -1. */
static int 
setnextroll(zone_t *zone, const policy_key_t *pkey, time_t t)
{
	if (!zone) {
		return -1;
	}
	if (!pkey) {
		return -1;
	}

	switch(policy_key_role(pkey)) {
		case POLICY_KEY_ROLE_KSK:
			if (zone_next_ksk_roll(zone) > t)
				return zone_set_next_ksk_roll(zone, (unsigned int)t);
			return 0;
		case POLICY_KEY_ROLE_ZSK:
			if (zone_next_zsk_roll(zone) > t)
				return zone_set_next_zsk_roll(zone, (unsigned int)t);
			return 0 ;
		case POLICY_KEY_ROLE_CSK:
			if (zone_next_csk_roll(zone) > t)
				return zone_set_next_csk_roll(zone, (unsigned int)t);
			return 0;
		default:
			return 1;
	}
}

/** 
 * Calculate keytag
 * @param loc: Locator of keydata on HSM
 * @param alg: Algorithm of key
 * @param ksk: 0 for zsk, positive int for ksk|csk
 * @param[out] success: set if returned keytag is meaningfull.
 * return: keytag
 * */
static uint16_t 
keytag(const char *loc, int alg, int ksk, bool *success)
{
	uint16_t tag;
	hsm_ctx_t *hsm_ctx;
	hsm_sign_params_t *sign_params;
	libhsm_key_t *hsmkey;
	ldns_rr *dnskey_rr;

	if (!loc) {
		return 0;
	}
	if (!success) {
		return 0;
	}

	*success = false;

	if (!(hsm_ctx = hsm_create_context())) {
		return 0;
	}
	if (!(sign_params = hsm_sign_params_new())) {
		hsm_destroy_context(hsm_ctx);
		return 0;
	}

	/* The owner name is not relevant for the keytag calculation.
	 * However, a ldns_rdf_clone down the path will trip over it. */
	sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "dummy");
	sign_params->algorithm = (ldns_algorithm) alg;
	sign_params->flags = LDNS_KEY_ZONE_KEY;
	if (ksk)
		sign_params->flags |= LDNS_KEY_SEP_KEY;

	hsmkey = hsm_find_key_by_id(hsm_ctx, loc);
	if (!hsmkey) {
		hsm_sign_params_free(sign_params);
		hsm_destroy_context(hsm_ctx);
		return 0;
	}

	dnskey_rr = hsm_get_dnskey(hsm_ctx, hsmkey, sign_params);
	if (!dnskey_rr) {
		libhsm_key_free(hsmkey);
		hsm_sign_params_free(sign_params);
		hsm_destroy_context(hsm_ctx);
		return 0;
	}

	tag = ldns_calc_keytag(dnskey_rr);

	ldns_rr_free(dnskey_rr);
	libhsm_key_free(hsmkey);
	hsm_sign_params_free(sign_params);
	hsm_destroy_context(hsm_ctx);
	*success = true;
	return tag;
}

static int
enforce_roll(const zone_t *zone, const policy_key_t *pkey)
{
	if (!zone) {
		return 0;
	}
	if (!pkey) {
		return 0;
	}

	switch(policy_key_role(pkey)) {
		case POLICY_KEY_ROLE_KSK:
			return zone_roll_ksk_now(zone);
		case POLICY_KEY_ROLE_ZSK:
			return zone_roll_zsk_now(zone);
		case POLICY_KEY_ROLE_CSK:
			return zone_roll_csk_now(zone);
		default:
			return 0;
	}
}

static int
set_roll(zone_t *zone, const policy_key_t *pkey, unsigned int roll)
{
	if (!zone) {
		return 0;
	}
	if (!pkey) {
		return 0;
	}

	switch(policy_key_role(pkey)) {
		case POLICY_KEY_ROLE_KSK:
			return zone_set_roll_ksk_now(zone, roll);
		case POLICY_KEY_ROLE_ZSK:
			return zone_set_roll_zsk_now(zone, roll);
		case POLICY_KEY_ROLE_CSK:
			return zone_set_roll_csk_now(zone, roll);
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
updatePolicy(engine_type *engine, db_connection_t *dbconn, policy_t *policy,
	zone_t *zone, const time_t now, int *allow_unsigned, int *zone_updated)
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
	const key_data_t *youngest;
	time_t t_ret;
	key_data_role_t key_role;
	bool success;
	uint16_t tag;
	int ret;

	if (!dbconn) {
		/* TODO: better log error */
		ods_log_debug("[%s] %s: no dbconn", module_str, scmd);
		return now + 60;
	}
	if (!policy) {
		/* TODO: better log error */
		ods_log_debug("[%s] %s: no policy", module_str, scmd);
		return now + 60;
	}
	if (!zone) {
		/* TODO: better log error */
		ods_log_debug("[%s] %s: no zone", module_str, scmd);
		return now + 60;
	}
	if (!allow_unsigned) {
		/* TODO: better log error */
		ods_log_debug("[%s] %s: no allow_unsigned", module_str, scmd);
		return now + 60;
	}
	if (!zone_updated) {
		/* TODO: better log error */
		ods_log_debug("[%s] %s: no zone_updated", module_str, scmd);
		return now + 60;
	}

	ods_log_verbose("[%s] %s: policyName: %s", module_str, scmd, policy_name(policy));

	/*
	 * Get all policy keys (configurations) for the given policy and fetch all
	 * the policy key database objects so we can iterate over it more then once.
	 */
	if (!(policykeylist = policy_get_policy_keys(policy))
		|| policy_key_list_fetch_all(policykeylist))
	{
		/* TODO: better log error */
		ods_log_debug("[%s] %s: error policy_get_policy_keys() || policy_key_list_fetch_all()", module_str, scmd);
		policy_key_list_free(policykeylist);
		return now + 60;
	}

	/*
	 * Get all key data objects for the given zone and fetch all the objects
	 * from the database so we can use the list again later.
	 */
	if (!(keylist = zone_get_keys(zone))
		|| key_data_list_fetch_all(keylist))
	{
		/* TODO: better log error */
		ods_log_debug("[%s] %s: error zone_get_keys() || key_data_list_fetch_all()", module_str, scmd);
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
			ods_log_debug("[%s] %s: error existsPolicyForKey() < 0", module_str, scmd);
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
				ods_log_debug("[%s] %s: error update mutkey", module_str, scmd);
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
	*allow_unsigned = pkey ? 1 : 0;

	for (; pkey; pkey = policy_key_list_next(policykeylist)) {
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
			/*
			 * We do not need to roll but we should check if the youngest key
			 * needs to be replaced. If not we reschedule for later based on the
			 * youngest key.
			 * TODO: Describe better why the youngest?!?
			 */
			if ((youngest = youngestKeyForConfig(keylist, pkey)) &&
				key_data_inception(youngest) + policy_key_lifetime(pkey) > now)
			{
				t_ret = addtime(key_data_inception(youngest), policy_key_lifetime(pkey));
				minTime(t_ret, &return_at);
				if (setnextroll(zone, pkey, t_ret)) {
					/* TODO: log error */
					ods_log_debug("[%s] %s: error setnextroll 1", module_str, scmd);
					key_data_list_free(keylist);
					policy_key_list_free(policykeylist);
					return now + 60;
				}
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
			ods_log_crit("[%s] %s: For policy %s %s key lifetime of %d "
				"is unreasonably short with respect to sum of parent "
				"TTL (%d) and key TTL (%d). Will not insert key!",
				module_str, scmd, policy_name(policy), policy_key_role_text(pkey),
				policy_key_lifetime(pkey), policy_parent_ds_ttl(policy),
				policy_keys_ttl(policy));
			if (setnextroll(zone, pkey, now)) {
				/* TODO: better log error */
				ods_log_debug("[%s] %s: error setnextroll 2", module_str, scmd);
				key_data_list_free(keylist);
				policy_key_list_free(policykeylist);
				return now + 60;
			}
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
			if (setnextroll(zone, pkey, now)) {
				/* TODO: better log error */
				ods_log_debug("[%s] %s: error setnextroll 3", module_str, scmd);
				key_data_list_free(keylist);
				policy_key_list_free(policykeylist);
				return now + 60;
			}
			*zone_updated = 1;
			continue;
		}

		/*
		 * Get a new key, either a existing/shared key if the policy is set to
		 * share keys or create a new key.
		 */
		if (policy_keys_shared(policy)) {
			hsmkey = getLastReusableKey(keylist, pkey);
			if (!newhsmkey) {
				newhsmkey = hsm_key_factory_get_key(engine, dbconn, pkey, HSM_KEY_STATE_SHARED);
				hsmkey = newhsmkey;
			}
		}
		else {
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
			if (setnextroll(zone, pkey, now)) {
				/* TODO: better log error */
				ods_log_debug("[%s] %s: error setnextroll 4", module_str, scmd);
				key_data_list_free(keylist);
				policy_key_list_free(policykeylist);
				return now + 60;
			}
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
			|| key_data_set_zone_id(mutkey, zone_id(zone))
			|| key_data_set_hsm_key_id(mutkey, hsm_key_id(hsmkey))
			|| key_data_set_algorithm(mutkey, policy_key_algorithm(pkey))
			|| key_data_set_inception(mutkey, now)
			|| key_data_set_role(mutkey, key_role)
			|| key_data_set_introducing(mutkey, 1)
			|| key_data_set_ds_at_parent(mutkey, KEY_DATA_DS_AT_PARENT_UNSUBMITTED))
		{
			/* TODO: better log error */
			ods_log_debug("[%s] %s: error new key", module_str, scmd);
			key_data_free(mutkey);
			/* TODO: release hsm key? */
			hsm_key_free(newhsmkey);
			key_data_list_free(keylist);
			policy_key_list_free(policykeylist);
			return now + 60;
		}

		/*
		 * Generate keytag for the new key and set it.
		 */
		tag = keytag(hsm_key_locator(hsmkey), hsm_key_algorithm(hsmkey),
			((hsm_key_role(hsmkey) == HSM_KEY_ROLE_KSK
				|| hsm_key_role(hsmkey) == HSM_KEY_ROLE_CSK)
				? 1 : 0),
			&success);
		if (!success
			|| key_data_set_keytag(mutkey, tag))
		{
			/* TODO: better log error */
			ods_log_debug("[%s] %s: error keytag", module_str, scmd);
			key_data_free(mutkey);
			/* TODO: release hsm key? */
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
			ods_log_debug("[%s] %s: error key_data_create()", module_str, scmd);
			key_data_free(mutkey);
			/* TODO: release hsm key? */
			hsm_key_free(newhsmkey);
			key_data_list_free(keylist);
			policy_key_list_free(policykeylist);
			return now + 60;
		}
		t_ret = addtime(now, policy_key_lifetime(pkey));
		minTime(t_ret, &return_at);
		if (setnextroll(zone, pkey, t_ret)) {
			/* TODO: better log error */
			ods_log_debug("[%s] %s: error setnextroll 5", module_str, scmd);
			key_data_free(mutkey);
			/* TODO: release hsm key? */
			hsm_key_free(newhsmkey);
			key_data_list_free(keylist);
			policy_key_list_free(policykeylist);
			return now + 60;
		}
		*zone_updated = 1;

		/*
		 * Tell similar keys to out-troduce.
		 * Similar keys are those that match role, algorithm, bits and repository
		 * and are introduced.
		 *
		 * IMPORTANT TODO BUG:
		 * Will not work if a policy has 2 or more keys of the same role, algorithm,
		 * bits and repository. Unclear how to fix this since keys are not directly
		 * related to a policy key.
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
					ods_log_debug("[%s] %s: error update mutkey2", module_str, scmd);
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
				ods_log_debug("[%s] %s: error set_roll()", module_str, scmd);
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

/**
 * Removes all keys from list that are no longer used.
 * 
 * \param[in] key_list list to filter.
 * \param[in] now
 * \param[in] purgetime period after which dead keys may be removed
 * \return time_t Next key purgable. 
 * */
static time_t
removeDeadKeys(KeyDataList &key_list, const time_t now, 
	const int purgetime, EnforcerZone &zone)
{
	static const char *scmd = "removeDeadKeys";
	time_t firstPurge = -1;
	
	KeyDependencyList &key_dep = zone.keyDependencyList();
	
	for (int i = key_list.numKeys()-1; i >= 0; i--) {
		KeyData &key = key_list.key(i);
		if (key.introducing()) continue;
		
		time_t keyTime = -1;
		bool keyPurgable = true;
		for (RECORD r = REC_MIN; r < REC_MAX; ++r) {
			if (getState(key, r, NULL) == NOCARE) continue;
			if (getState(key, r, NULL) != HID) {
				keyPurgable = false;
				break;
			}
			time_t recordTime = getRecord(key, r).lastChange();
			if (recordTime > keyTime) keyTime = recordTime;
		}
		if (keyTime != -1) keyTime = addtime(keyTime, purgetime);
		if (keyPurgable) {
			if (now >= keyTime) {
				ods_log_info("[%s] %s delete key: %s", module_str, scmd,
					key.locator().c_str());
				key_list.delKey(i);
			} else {
				minTime(keyTime, &firstPurge);
			}
			/** It might not be time to purge the key just yet, but we
			 * can already assume no other key depends on it. */
			key_dep.delDependency( &key );
		}
	}
	return firstPurge;
}

time_t
update(engine_type *engine, db_connection_t *dbconn, zone_t *zone, policy_t *policy, time_t now, int *zone_updated)
{
	int allow_unsigned;
	time_t policy_return_time, zone_return_time;

	if (!engine) {
		ods_log_debug("[%s] no engine", module_str);
		return now + 5;
	}
	if (!dbconn) {
		ods_log_debug("[%s] no dbconn", module_str);
		return now + 5;
	}
	if (!zone) {
		ods_log_debug("[%s] no zone", module_str);
		return now + 5;
	}
	if (!policy) {
		ods_log_debug("[%s] no policy", module_str);
		return now + 5;
	}
	if (!zone_updated) {
		ods_log_debug("[%s] no zone_updated", module_str);
		return now + 5;
	}

	ods_log_info("[%s] update zone: %s", module_str, zone_name(zone));

	policy_return_time = updatePolicy(engine, dbconn, policy, zone, now, &allow_unsigned, zone_updated);
	if (allow_unsigned)
		ods_log_info("[%s] No keys configured for %s, zone will become unsigned eventually", module_str, zone_name(zone));
	zone_return_time = updateZone(policy, zone, now, allow_unsigned, zone_updated);

	return now + 5;
}

/* see header file */
time_t 
update_old(EnforcerZone &zone, const time_t now, HsmKeyFactory &keyfactory)
{
	time_t policy_return_time, zone_return_time, purge_return_time = -1;
	bool allow_unsigned;
	KeyDataList &key_list = zone.keyDataList();
	const Policy *policy = zone.policy();
	static const char *scmd = "update";

	ods_log_info("[%s] %s Zone: %s", module_str, scmd, zone.name().c_str());

	//~ policy_return_time = updatePolicy(zone, now, keyfactory, key_list, allow_unsigned);
	if (allow_unsigned)
		ods_log_info(
			"[%s] %s No keys configured, zone will become unsigned eventually",
			module_str, scmd);
	zone_return_time = updateZone_old(zone, now, allow_unsigned, keyfactory);

	/** Only purge old keys if the configuration says so. */
	if (policy->keys().has_purge())
		purge_return_time = removeDeadKeys(key_list, now, policy->keys().purge(), zone);

	/** Always set these flags. Normally this needs to be done _only_
	 * when signerConfNeedsWriting() is set. However a previous
	 * signerconf might not be available, we have no way of telling. :(
	 * */
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		k.setPublish(getState(k, DK, NULL) == OMN || getState(k, DK, NULL) == RUM);
		k.setActiveKSK(getState(k, RD, NULL) == OMN || getState(k, RD, NULL) == RUM);
		k.setActiveZSK(getState(k, RS, NULL) == OMN || getState(k, RS, NULL) == RUM);
	}

	minTime(policy_return_time, &zone_return_time);
	minTime(purge_return_time,  &zone_return_time);
	return zone_return_time;
}
