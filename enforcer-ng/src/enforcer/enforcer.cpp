/* 
 * 
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
 * */

#include <ctime>
#include <iostream>

#include "enforcer/enforcer.h"
#include "enforcer/enforcerdata.h"
#include "policy/kasp.pb.h"
#include "hsmkey/hsmkey.pb.h"

#include "shared/duration.h"
#include "shared/log.h"

using namespace std;
using ::ods::kasp::Policy;
using ::ods::kasp::KeyList;

static const char *module_str = "enforcer";

/* be careful changing this, might mess up database*/
enum STATE {HID, RUM, OMN, UNR, NOCARE}; 
static const char* STATENAMES[] = {"HID", "RUM", "OMN", "UNR"};
#undef DS /* DS is defined somewhere on SunOS 5.10 and breaks this enum */
enum RECORD {REC_MIN, DS = REC_MIN, DK, RD, RS, REC_MAX};
/* trick to loop over our RECORD enum */
RECORD& operator++(RECORD& r){return r = (r >= REC_MAX?REC_MAX:RECORD(r+1));}
static const char* RECORDAMES[] = {"DS", "DNSKEY", "RRSIG DNSKEY", "RRSIG"};
/* \careful */

/** When no key available wait this many seconds before asking again. */
#define NOKEY_TIMEOUT 60

/**
 * Stores the minimum of parm1 and parm2 in parm2.
 * 
 * Stores smallest of two times in min. Avoiding negative values,
 * which mean no update necessary. Any other time in the past: ASAP.
 * 
 * \param t[in], some time to test
 * \param min[in,out], smallest of t and min.
 * */
inline void 
minTime(const time_t t, time_t &min)
{
	if ( (t < min || min < 0) && t >= 0 ) min = t;
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
time_t
addtime(const time_t t, const int seconds)
{
	struct tm *tp = localtime(&t);
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
KeyState&
getRecord(KeyData &key, const RECORD record)
{
	const char *scmd = "getRecord";
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
inline STATE
getState(KeyData &key, const RECORD record)
{
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
STATE
getDesiredState(const bool introducing, const STATE state)
{
	const char *scmd = "getDesiredState";
	if (state > NOCARE || state < HID) 
		ods_fatal_exit("[%s] %s Key in unknown state (%d), "
			"Corrupt database? Abort.",  module_str, scmd, (int)state);
	const STATE jmp[2][5] = {{HID, UNR, UNR, HID, NOCARE}, {RUM, OMN, OMN, RUM, NOCARE}};
	return jmp[introducing][(int)state];
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
bool
exists(KeyDataList &key_list, KeyData &key, 
	const RECORD record,const STATE next_state, 
	const bool require_same_algorithm, const bool pretend_update, 
	const STATE mask[4])
{
		for (int i = 0; i < key_list.numKeys(); i++) {
			KeyData &k = key_list.key(i);
			if (require_same_algorithm && k.algorithm() != key.algorithm())
				continue;
			/** Do we need to substitute a state of this key with 
			 * next_state? */
			bool sub_key = pretend_update && &key == &k;
			bool match = true;
			for (RECORD r = REC_MIN; r < REC_MAX; ++r) {
				/** Do we need to substitute the state of THIS record? */
				bool sub_rec = sub_key && record == r;
				if (mask[r] == NOCARE) continue;
				/** Use actual state or next state */
				STATE state = (sub_rec?next_state:getState(k, r));
				/** no match in this record, try next key */
				if (mask[r] != state) {
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
bool
unsignedOk(KeyDataList &key_list, KeyData &key, const RECORD record, 
	const STATE next_state, const bool pretend_update, 
	const STATE mask[4], const RECORD mustHID)
{
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if (k.algorithm() != key.algorithm()) continue;
		bool substitute = pretend_update && &key == &k;
		
		STATE cmp_msk[4];
		for (RECORD r = REC_MIN; r < REC_MAX; ++r) {
			/** all records should satisfy mask */
			if (r != mustHID) 
				cmp_msk[r] = mask[r];
			/** except mustHid, which should be hidden.
			 * MustHid=record=r: pretend update */
			else if (substitute && record==r)
				cmp_msk[r] = next_state;
			else
				cmp_msk[r] = getState(k, r);
		}
		/** If state is hidden this key is okay. */
		if (cmp_msk[mustHID] == HID || cmp_msk[mustHID] == NOCARE) 
			continue;
		/** Otherwise, we must test mask */
		if (!exists(key_list, key, record, next_state, true, 
			pretend_update, cmp_msk))
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
bool
rule1(KeyDataList &key_list, KeyData &key, const RECORD record, 
	const STATE next_state, const bool pretend_update)
{
	const STATE mask_triv[] =  {OMN, NOCARE, NOCARE, NOCARE};
	const STATE mask_dsin[] =  {RUM, NOCARE, NOCARE, NOCARE};
	
	return  
		exists(key_list, key, record, next_state, false, pretend_update, mask_triv) ||
		exists(key_list, key, record, next_state, false, pretend_update, mask_dsin);
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
bool
rule2(KeyDataList &key_list, KeyData &key, const RECORD record, 
	const STATE next_state, const bool pretend_update)
{
	const STATE mask_unsg[] =  {HID, OMN, OMN, NOCARE};
	const STATE mask_triv[] =  {OMN, OMN, OMN, NOCARE};
	const STATE mask_ds_i[] =  {RUM, OMN, OMN, NOCARE};
	const STATE mask_ds_o[] =  {UNR, OMN, OMN, NOCARE};
	const STATE mask_k_i1[] =  {OMN, RUM, RUM, NOCARE};
	const STATE mask_k_i2[] =  {OMN, OMN, RUM, NOCARE};
	const STATE mask_k_o1[] =  {OMN, UNR, UNR, NOCARE};
	const STATE mask_k_o2[] =  {OMN, UNR, OMN, NOCARE};

	/** for performance the lighter, more-likely-to-be-true test are
	 * performed first. */
	
	return
		exists(key_list, key, record, next_state, true, pretend_update, mask_triv) ||
		
		exists(key_list, key, record, next_state, true, pretend_update, mask_ds_i) &&
		exists(key_list, key, record, next_state, true, pretend_update, mask_ds_o) ||
		
		(exists(key_list, key, record, next_state, true, pretend_update, mask_k_i1) ||
		 exists(key_list, key, record, next_state, true, pretend_update, mask_k_i2) )&&
		(exists(key_list, key, record, next_state, true, pretend_update, mask_k_o1) ||
		 exists(key_list, key, record, next_state, true, pretend_update, mask_k_o2) ) ||

		unsignedOk(key_list, key, record, next_state, pretend_update, mask_unsg, DS);
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
bool
rule3(KeyDataList &key_list, KeyData &key, const RECORD record, 
	const STATE next_state, const bool pretend_update)
{
	const STATE mask_triv[] =  {NOCARE, OMN, NOCARE, OMN};
	const STATE mask_keyi[] =  {NOCARE, RUM, NOCARE, OMN};
	const STATE mask_keyo[] =  {NOCARE, UNR, NOCARE, OMN};
	const STATE mask_sigi[] =  {NOCARE, OMN, NOCARE, RUM};
	const STATE mask_sigo[] =  {NOCARE, OMN, NOCARE, UNR};
	const STATE mask_unsg[] =  {NOCARE, HID, NOCARE, OMN};

	/** for performance the lighter, more-likely-to-be-true test are
	 * performed first. */

	return
		exists(key_list, key, record, next_state, true, pretend_update, mask_triv) ||
		
		exists(key_list, key, record, next_state, true, pretend_update, mask_keyi) &&
		exists(key_list, key, record, next_state, true, pretend_update, mask_keyo) ||
		
		exists(key_list, key, record, next_state, true, pretend_update, mask_sigi) &&
		exists(key_list, key, record, next_state, true, pretend_update, mask_sigo) ||

		unsignedOk(key_list, key, record, next_state, pretend_update, mask_unsg, DK);
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
bool
dnssecApproval(KeyDataList &key_list, KeyData &key, const RECORD record, 
	const STATE next_state, bool allow_unsigned)
{
	return 
		(allow_unsigned ||
		 !rule1(key_list, key, record, next_state, false) ||
		  rule1(key_list, key, record, next_state, true ) ) &&
		(!rule2(key_list, key, record, next_state, false) ||
		  rule2(key_list, key, record, next_state, true ) ) &&
		(!rule3(key_list, key, record, next_state, false) ||
		  rule3(key_list, key, record, next_state, true ) );
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
time_t
minTransitionTime(EnforcerZone &zone, const RECORD record,
	const STATE next_state, const time_t lastchange, const int ttl)
{
	const char *scmd = "minTransitionTime";
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
bool
policyApproval(KeyDataList &key_list, KeyData &key, const RECORD record, const STATE next_state)
{
	const char *scmd = "policyApproval";
	
	/** once the record is introduced the policy has no influence. */
	if (next_state != RUM) return true;
	
	const STATE mask_sig[] =  {NOCARE, OMN, NOCARE, OMN};
	const STATE mask_dnskey[] =  {OMN, OMN, OMN, NOCARE};
	
	switch(record) {
		case DS:
			/** If we want to minimize the DS transitions make sure
			 * the DNSKEY is fully propagated. */
			return !key.keyStateDS().minimize() || 
				getState(key, DK) == OMN;
		case DK:
			/** 1) there are no restrictions */
			if (!key.keyStateDNSKEY().minimize()) return true;
			/** 2) If minimize, signatures must ALWAYS be propagated 
			 * for CSK and ZSK */
			if (getState(key, RS) != OMN && getState(key, RS) != NOCARE)
				return false;
			/** 3) wait till DS is introduced */
			if (getState(key, DS) == OMN) return true;
			/** 4) Except, we might be doing algorithm rollover.
			 * if no other good KSK available, ignore minimize flag*/
			return !exists(key_list, key, DK,NOCARE, 
				true, false, mask_dnskey);
		case RD:
			/** The only time not to introduce RRSIG DNSKEY is when the
			 * DNSKEY is still hidden. */
			return getState(key, DK) != HID;
		case RS:
			/** 1) there are no restrictions */
			if (!key.keyStateRRSIG().minimize()) return true;
			/** 2) wait till DNSKEY is introduced */
			if (getState(key, DK) == OMN) return true;
			/** 3) Except, we might be doing algorithm rollover
			 * if no other good ZSK available, ignore minimize flag */
			return !exists(key_list, key, RS,NOCARE, 
				true, false, mask_sig);
		default: 
			ods_fatal_exit("[%s] %s Unknown record type (%d), "
				"fault of programmer. Abort.",
				module_str, scmd, (int)record);
	}
}

/** given the zone, what TTL should be used for record?
 * 
 * Normally we use the TTL from the policy. However a larger TTL might
 * have been published in the near past causing this record to take 
 * extra time to propagate */
int
getZoneTTL(EnforcerZone &zone, const RECORD record, const time_t now)
{
	const char *scmd = "getTTL";
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
			recordTTL = max(policy->signatures().valdenial(), 
							policy->signatures().max_zone_ttl());
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
void
setState(EnforcerZone &zone, KeyData &key, const RECORD record, const STATE state, 
	const time_t now)
{
	KeyState &ks = getRecord(key, record);
	ks.setState(state);
	ks.setLastChange(now);
	ks.setTtl(getZoneTTL(zone, record, now));
	zone.setSignerConfNeedsWriting(true);
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
time_t
updateZone(EnforcerZone &zone, const time_t now, bool allow_unsigned)
{
	time_t returntime_zone = -1;
	time_t returntime_key;
	bool change;
	KeyDataList &key_list = zone.keyDataList();
	const Policy *policy = zone.policy();
	const char *scmd = "updateZone";
	ods_log_verbose("[%s] %s", module_str, scmd);

	/** This code keeps track of TTL changes. If in the past a large
	 * TTL is used, our keys *may* need to transition extra 
	 * careful to make sure each resolver picks up the RRset.
	 * When this date passes we may start using the policies TTL. */
	if (zone.ttlEnddateDs() <= now)
		zone.setTtlEnddateDs(addtime(now, policy->parent().ttlds()));
	if (zone.ttlEnddateDk() <= now)
		zone.setTtlEnddateDk(addtime(now, policy->keys().ttl()));
	if (zone.ttlEnddateRs() <= now)
		zone.setTtlEnddateRs(addtime(now, 
				max(policy->signatures().valdenial(), 
					policy->signatures().max_zone_ttl()))); 

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

			for (RECORD record = REC_MIN; record < REC_MAX; ++record) {
				STATE state = getState(key, record);
				STATE next_state = getDesiredState(key.introducing(), state);
				
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
				if (!policyApproval(key_list, key, record, next_state)) continue;
				ods_log_verbose("[%s] %s Policy says we can (1/3)", 
					module_str, scmd);
				
				/** Would be invalid DNSSEC state */
				if (!dnssecApproval(key_list, key, record, next_state, allow_unsigned))
					continue;
				ods_log_verbose("[%s] %s DNSSEC says we can (2/3)", 
					module_str, scmd);

				time_t returntime_key = minTransitionTime(zone, record, 
					next_state, getRecord(key, record).lastChange(), 
					getRecord(key, record).ttl());

				/** If this is an RRSIG and next state is omnipresent
				 * and the DNSKEY is omnipresent, wait an additional 
				 * signature lifetime to allow for 'smooth' key 
				 * rollover. */
				if ((record == RS && next_state == OMN && 
						getState(key, DK) == OMN) ||
						(record == DK && next_state == HID && 
						getState(key, RS) == HID)) {
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
					minTime(returntime_key, returntime_zone);
					continue;
				}

				ods_log_verbose("[%s] %s Timing says we can (3/3) now: %d key: %d", 
					module_str, scmd, now, returntime_key);

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
				setState(zone, key, record, next_state, now);
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
bool 
getLastReusableKey(EnforcerZone &zone,
	const Policy *policy, const KeyRole role,
	int bits, const string &repository, int algorithm, 
	const time_t now, HsmKey **ppKey,
	HsmKeyFactory &keyfactory, int lifetime)
{
	const char *scmd = "getLastReusableKey";
	
	if (!keyfactory.UseSharedKey(bits, repository, policy->name(), 
		algorithm, role, zone.name(), ppKey))
		return false;
	
	/** UseSharedKey() promised us a match, we'd better crash. */
	if (*ppKey == NULL)
		ods_fatal_exit("[%s] %s Keyfactory promised key but did not give it",
			module_str, scmd);
	
	/** Key must (still) be in use */
	if (now < (*ppKey)->inception() + lifetime) return true;
	
	/** Clean up, was set by default by UseSharedKey(), unset */
	(*ppKey)->setUsedByZone(zone.name(), false);
	return false;
}

/**
 * Abstraction to generalize different kind of keys. 
 * return number of keys _in_a_policy_ 
 * */
int 
numberOfKeyConfigs(const KeyList &policyKeys, const KeyRole role)
{
	const char *scmd = "numberOfKeyConfigs";
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
void 
keyProperties(const KeyList &policyKeys, const int index, const KeyRole role,
	int *bits, int *algorithm, int *lifetime, string &repository,
	bool *manual, int *rollover_type)
{
	const char *scmd = "keyProperties";
	
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
 * @param keyfactory
 * @param policyKeys
 * @param key
 * @return bool True if a matching policy exists
 * */
bool
existsPolicyForKey(HsmKeyFactory &keyfactory, const KeyList &policyKeys, 
	KeyData &key)
{
	const char *scmd = "existsPolicyForKey";
	/** 1: fetch hsmkey */
	HsmKey *hsmkey;
	if (!keyfactory.GetHsmKeyByLocator(key.locator(), &hsmkey)) {
		/** This key is not associated with actual key material! 
		 * This is a bug or database corruption.
		 * Crashing here is an option but we just return false so the 
		 * key will be thrown away in a graceful manner.*/
		ods_log_verbose("[%s] %s no hsmkey!", module_str, scmd);
		return false;
	}
	
	/** 2: loop over all configs for this role */
	for (int i = 0; i < numberOfKeyConfigs(policyKeys, key.role()); i++)
	{
		int p_bits, p_alg, p_life, p_rolltype;
		string p_rep;
		bool p_man;
		keyProperties(policyKeys, i, key.role(), &p_bits, &p_alg, 
			&p_life, p_rep, &p_man, &p_rolltype); 
		if (p_bits == hsmkey->bits() && p_alg == key.algorithm() &&
			!p_rep.compare(hsmkey->repository()) )
			return true;
	}
	ods_log_verbose("[%s] %s not found such config", module_str, scmd);
	return false;
}

bool
youngestKeyForConfig(HsmKeyFactory &keyfactory, const KeyList &policyKeys, 
	const KeyRole role, const int index, 
	KeyDataList &key_list, KeyData **key)
{
	int p_bits, p_alg, p_life, p_rolltype;
	string p_rep;
	bool p_man;
	
	/** fetch characteristics of config */
	keyProperties(policyKeys, index, role, &p_bits, &p_alg, &p_life,
		p_rep, &p_man, &p_rolltype); 
	
	*key = NULL;
	for (int j = 0; j < key_list.numKeys(); j++) {
		KeyData &k = key_list.key(j);
		HsmKey *hsmkey;
		/** if we have a match, remember youngest */
		if (keyfactory.GetHsmKeyByLocator(k.locator(), &hsmkey) &&
			k.role() == role &&
			p_bits == hsmkey->bits() && p_alg == k.algorithm() &&
			!p_rep.compare(hsmkey->repository())  &&
			(!(*key) || k.inception() > (*key)->inception()) )
			*key = &k;
	}
	return (*key) != NULL;
}

/**
 * Test for existence of a similar key.
 * 
 * \param[in] Key list
 * \param[in] Role
 * \param[in] Algorithm
 * \return existence of such a key.
 */
bool
keyForAlgorithm(KeyDataList &key_list, const KeyRole role, const int algorithm)
{
	for (int j = 0; j < key_list.numKeys(); j++) {
		KeyData &k = key_list.key(j);
		if (k.role() == role && algorithm == k.algorithm() )
			return true;
	}
	return false;
}

/**
 * See what needs to be done for the policy 
 * 
 * @param zone
 * @param now
 * @param keyfactory
 * @param key_list
 * @param[out] allow_unsigned, true when no keys are configured.
 * @return time_t
 * */
time_t 
updatePolicy(EnforcerZone &zone, const time_t now, 
	HsmKeyFactory &keyfactory, KeyDataList &key_list, bool &allow_unsigned)
{
	time_t return_at = -1;
	const Policy *policy = zone.policy();
	KeyList policyKeys = policy->keys();
	const string policyName = policy->name();
	const char *scmd = "updatePolicy";

	ods_log_verbose("[%s] %s policyName: %s", module_str, scmd, 
		policyName.c_str());

	/** Decommision all keys without any matching config */
	for (int j = 0; j < key_list.numKeys(); j++) {
		KeyData &key = key_list.key(j);
		if (!existsPolicyForKey(keyfactory, policyKeys, key))
			key.setIntroducing(false);
	}

	/** If no keys are configured an unsigned zone is okay. */
	allow_unsigned = (0 == (numberOfKeyConfigs(policyKeys, ZSK) + 
							numberOfKeyConfigs(policyKeys, KSK) + 
							numberOfKeyConfigs(policyKeys, CSK) ));

	/** Visit every type of key-configuration, not pretty but we can't
	 * loop over enums. Include MAX in enum? */
	for ( int role = 1; role < 4; role++ ) {
		/** NOTE: we are not looping over keys, but configurations */
		for ( int i = 0; i < numberOfKeyConfigs( policyKeys, (KeyRole)role ); i++ ) {
			string repository;
			int bits, algorithm, lifetime, p_rolltype;
			bool manual_rollover;

			/** select key properties of key i in KeyRole role */
			keyProperties(policyKeys, i, (KeyRole)role, &bits, 
				&algorithm, &lifetime, repository, &manual_rollover, 
				&p_rolltype);

			bool forceRoll = false;
			/** Should we do a manual rollover *now*? */
			if (manual_rollover) {
				switch((KeyRole)role) {
					case KSK: forceRoll = zone.rollKskNow(); break;
					case ZSK: forceRoll = zone.rollZskNow(); break;
					case CSK: forceRoll = zone.rollCskNow(); break;
					default:
						/** Programming error, report a bug! */
						ods_fatal_exit("[%s] %s Unknow Role: (%d)",
						module_str, scmd, role);
				}
				/** If no similar key available, roll. */
				forceRoll |= !keyForAlgorithm(key_list, (KeyRole)role, 
					algorithm);
				/** No reason to roll at all */
				if (!forceRoll) continue;
			}
			/** Try an automatic roll */
			if (!forceRoll) {
				/** Is there a predecessor key? */
				KeyData *key;
				if (youngestKeyForConfig(keyfactory, policyKeys, 
					(KeyRole)role, i, key_list, &key) && 
					key->inception() + lifetime > now)
				{
					/** yes, but no need to roll at this time. Schedule 
					 * for later */
					minTime( addtime(key->inception(), lifetime), return_at );
					continue;
				}
				/** No, or key is expired, we need a new one. */
			}

			/** time for a new key */
			ods_log_verbose("[%s] %s New key needed for role %d", 
				module_str, scmd, role);
			HsmKey *newkey_hsmkey;
			bool got_key;

			/** Sanity check. This would produce silly output and give
			 * the signer lots of useless work */
			if (role&KSK && policy->parent().ttlds() + policy->keys().ttl() >= lifetime || 
					role&ZSK && policy->signatures().max_zone_ttl() + policy->keys().ttl() >= lifetime) {
				ods_log_crit("[%s] %s Key lifetime unreasonably short "
					"with respect to TTL. Will not insert key!",
					module_str, scmd);
				continue;
			}

			if ( policyKeys.zones_share_keys() )
				/** Try to get an existing key or ask for new shared */
				got_key = getLastReusableKey( zone, policy, 
					(KeyRole)role, bits, repository, algorithm, now, 
					&newkey_hsmkey, keyfactory, lifetime) ||
					keyfactory.CreateSharedKey(bits, repository, policyName,
					algorithm, (KeyRole)role, zone.name(),&newkey_hsmkey );
			else
				got_key = keyfactory.CreateNewKey(bits,repository,
					policyName, algorithm, (KeyRole)role, &newkey_hsmkey );
			
			if ( !got_key ) {
				/** The factory was not ready, return later */
				minTime( now + NOKEY_TIMEOUT, return_at);
				ods_log_warning("[%s] %s No keys available on hsm, retry in %d seconds", 
					module_str, scmd, NOKEY_TIMEOUT);
				continue;
			}
			ods_log_verbose("[%s] %s got new key from HSM", module_str, 
				scmd);
			
			/** Make new key from HSM_key and set defaults */
			KeyData &new_key = zone.keyDataList().addNewKey( algorithm, 
				now, (KeyRole)role, p_rolltype);
			new_key.setLocator( newkey_hsmkey->locator() );

			new_key.setDsAtParent(DS_UNSUBMITTED);
			
			setState(zone, new_key, DS, (role&KSK?HID:NOCARE), now);
			setState(zone, new_key, DK, HID, now);
			setState(zone, new_key, RD, (role&KSK?HID:NOCARE), now);
			setState(zone, new_key, RS, (role&ZSK?HID:NOCARE), now);
			
			new_key.setIntroducing(true);

			/** New key inserted, come back after its lifetime */
			minTime( now + lifetime, return_at );

			/** Tell similar keys to outroduce, skip new key */
			for (int j = 0; j < key_list.numKeys(); j++) {
				KeyData &key = key_list.key(j);
				HsmKey *key_hsmkey;
				if (&key == &new_key) continue;
				/* now check role and algorithm, also skip if already 
				 * outroducing. */
				if (!key.introducing() || key.role() != new_key.role() ||
					key.algorithm() != new_key.algorithm() )
					continue;
				/* compare key material */
				if (!keyfactory.GetHsmKeyByLocator(key.locator(), &key_hsmkey) ||
					key_hsmkey->bits() != newkey_hsmkey->bits() || 
					newkey_hsmkey->repository().compare(key_hsmkey->repository()))
						continue;
				/* key and new_key have the same properties, so they are
				 * generated from the same configuration. */
				key.setIntroducing(false);
				ods_log_verbose("[%s] %s decommissioning old key: %s", 
					module_str, scmd, key.locator().c_str());
			}
			
			/* The user explicitly requested a rollover, request 
			 * succeeded. We can now stop try to roll manually.  */
			if (manual_rollover) {
				switch((KeyRole)role) {
					case KSK: zone.setRollKskNow(false); break;
					case ZSK: zone.setRollZskNow(false); break;
					case CSK: zone.setRollCskNow(false); break;
					default:
						/** Programming error, report a bug! */
						ods_fatal_exit("[%s] %s Unknow Role: (%d)",
						module_str, scmd, role);
				}
			}
		} /** loop over keyconfigs */
	} /** loop over KeyRole */
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
time_t
removeDeadKeys(KeyDataList &key_list, const time_t now, const int purgetime)
{
	const char *scmd = "removeDeadKeys";
	time_t firstPurge = -1;
	
	for (int i = key_list.numKeys()-1; i >= 0; i--) {
		KeyData &key = key_list.key(i);
		if (key.introducing()) continue;
		
		time_t keyTime = -1;
		bool keyPurgable = true;
		for (RECORD r = REC_MIN; r < REC_MAX; ++r) {
			if (getState(key, r) == NOCARE) continue;
			if (getState(key, r) != HID) {
				keyPurgable = false;
				break;
			}
			time_t recordTime = getRecord(key, r).lastChange();
			if (recordTime > keyTime) keyTime = recordTime;
		}
		if (keyTime != -1) keyTime = addtime(keyTime, purgetime);
		if (keyPurgable) {
			if (now >= keyTime) {
				ods_log_info("[%s] %s delete key: %s", module_str, scmd, key.locator().c_str());
				key_list.delKey(i);
			} else {
				minTime(keyTime, firstPurge);
			}
		}
	}
	return firstPurge;
}

/* see header file */
time_t 
update(EnforcerZone &zone, const time_t now, HsmKeyFactory &keyfactory)
{
	time_t policy_return_time, zone_return_time, purge_return_time = -1;
	bool allow_unsigned;
	KeyDataList &key_list = zone.keyDataList();
	const Policy *policy = zone.policy();
	const char *scmd = "update";

	ods_log_info("[%s] %s Zone: %s", module_str, scmd, zone.name().c_str());

	policy_return_time = updatePolicy(zone, now, keyfactory, key_list, allow_unsigned);
	if (allow_unsigned)
		ods_log_info(
			"[%s] %s No keys configured, zone will become unsigned eventually",
			module_str, scmd);
	zone_return_time = updateZone(zone, now, allow_unsigned);

	/** Only purge old keys if the configuration says so. */
	if (policy->keys().has_purge())
		purge_return_time = removeDeadKeys(key_list, now, policy->keys().purge());

	/** Always set these flags. Normally this needs to be done _only_
	 * when signerConfNeedsWriting() is set. However a previous
	 * signerconf might not be available, we have no way of telling. :(
	 * */
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		k.setPublish(getState(k, DK) == OMN || getState(k, DK) == RUM);
		k.setActiveKSK(getState(k, RD) == OMN || getState(k, RD) == RUM);
		k.setActiveZSK(getState(k, RS) == OMN || getState(k, RS) == RUM);
	}

	minTime(policy_return_time, zone_return_time);
	minTime(purge_return_time,  zone_return_time);
	return zone_return_time;
}
