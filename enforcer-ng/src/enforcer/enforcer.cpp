#include <ctime>
#include <iostream>
#include <cassert>

#include "enforcer/enforcer.h"
#include "enforcer/enforcerdata.h"
#include "policy/kasp.pb.h"
#include "keystate/keystate.pb.h" /* for human names */

/* Interface of this cpp file is used by C code, we need to declare
 * extern "C" to prevent linking errors. */
extern "C" {
	#include "shared/duration.h"
	#include "shared/log.h"
}

using namespace std;
using ::ods::kasp::Policy;

static const char *module_str = "enforcer";

/* be careful changing this, might mess up database*/
enum STATE {HID, RUM, OMN, UNR, NOCARE}; 
static const char* STATENAMES[] = {"HID", "RUM", "OMN", "UNR"};
enum RECORD {REC_MIN, DS = REC_MIN, DK, RD, RS, REC_MAX};
/* trick to loop over our enum */
RECORD& operator++(RECORD& r){return r = (r >= REC_MAX)?REC_MAX:RECORD(r+1);}
static const char* RECORDAMES[] = {"DS", "DNSKEY", "RRSIG DNSKEY", "RRSIG"};
/* \careful */


/* When no key available wait this many seconds before asking again. */
#define NOKEY_TIMEOUT 60
/* TODO: Temporary placeholder, must figure this out from policy. */
#define ALLOW_UNSIGNED false

/**
 * Stores smallest of two times in *min.
 * Avoiding negative values, which mean no update necessary
 * Any other time in the past: ASAP.
 * */
inline void 
minTime(const time_t t, time_t &min)
{
	if ( (t < min || min < 0) && t >= 0 ) min = t;
}

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

void
setState(KeyData &key, const RECORD record, const STATE state, 
	const time_t now)
{
	KeyState &ks = getRecord(key, record);
	ks.setState(state);
	ks.setLastChange(now);

}

STATE
getState(KeyData &key, const RECORD record)
{
	return (STATE)getRecord(key, record).state();
}

/**
 * Given goal and state, what will be the next state?
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
 * The policy approval function makes sure records are introduced in
 * correct order.
 * */
bool
policy_approval(KeyData &key, const RECORD record, const STATE next_state)
{
	const char *scmd = "getDesiredState";
	if (next_state != RUM) return true; /* already introducing */
	switch(record) {
		case DS:
			return !key.keyStateDS().minimize() || 
				getState(key, DK) == OMN;
		case DK:
			return !key.keyStateDNSKEY().minimize() || 
				(getState(key, DS) == OMN && getState(key, RS) == OMN);
		case RD:
			return getState(key, DK) != HID;
		case RS:
			return !key.keyStateRRSIG().minimize() || 
				getState(key, DK) == OMN;
		default: 
			ods_fatal_exit("[%s] %s Unknown record type (%d), "
				"fault of programmer. Abort.",
				module_str, scmd, (int)record);
	}
}

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
			bool sub_key = pretend_update && !key.locator().compare(k.locator());
			//~ ods_log_verbose("[%s] %d %d %s %s", module_str, sub_key, pretend_update, key.locator().c_str(), k.locator().c_str());
			bool match = true;
			for (RECORD r = REC_MIN; r < REC_MAX; ++r) {
				bool sub_rec = sub_key && record == r;
				if (mask[r] == NOCARE) continue;
				/* if key and record match and pretend_update
				 * pretend the record has state next_state */
				STATE state = sub_rec?next_state:getState(k, r);
				if (mask[r] != state) {
					match = false;
					break;
				}
			}
			if (match) return true;
		}
	return false;
}

bool
unsigned_ok(KeyDataList &key_list, KeyData &key, const RECORD record, 
	const STATE next_state, const bool pretend_update, 
	const STATE mask[4], const RECORD mustHID)
{
	//check all keys
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if (k.algorithm() != key.algorithm()) continue;
		STATE k_state[4];
		for (RECORD r = REC_MIN; r < REC_MAX; ++r)
			k_state[r] = (pretend_update && record==r && !key.locator().compare(k.locator()))?next_state:getState(k, r);
		if (k_state[mustHID] == HID || k_state[mustHID] == NOCARE) continue;
		STATE amask[4];
		for (RECORD r = REC_MIN; r < REC_MAX; ++r)
			amask[r] = (mustHID==r)?k_state[r]:mask[r];
		if (!exists(key_list, key, record, next_state, true, pretend_update, amask))
			return false; //we can't satisfy this condition
	}
	return true;
}

bool
rule1(KeyDataList &key_list, KeyData &key, const RECORD record, 
	const STATE next_state, const bool pretend_update)
{
	const STATE mask1[] =  {RUM, NOCARE, NOCARE, NOCARE};
	const STATE mask2[] =  {OMN, NOCARE, NOCARE, NOCARE};
	return  exists(key_list, key, record, next_state, false, pretend_update, mask1) ||
			exists(key_list, key, record, next_state, false, pretend_update, mask2);
}

bool
rule2(KeyDataList &key_list, KeyData &key, const RECORD record, 
	const STATE next_state, const bool pretend_update)
{
	const STATE mask1[] =  {RUM, OMN, OMN, NOCARE};
	const STATE mask2[] =  {UNR, OMN, OMN, NOCARE};
	const STATE mask3[] =  {OMN, OMN, OMN, NOCARE};
	const STATE mask4[] =  {OMN, RUM, RUM, NOCARE};
	const STATE mask5[] =  {OMN, OMN, RUM, NOCARE};
	const STATE mask6[] =  {OMN, UNR, UNR, NOCARE};
	const STATE mask7[] =  {OMN, UNR, OMN, NOCARE};
	const STATE mask_unsg[] =  {HID, OMN, OMN, NOCARE};

	//~ return
	//~ unsigned_ok(key_list, key, record, next_state, pretend_update, mask_unsg, DS);
	return
	unsigned_ok(key_list, key, record, next_state, pretend_update, mask_unsg, DS) ||
	
	exists(key_list, key, record, next_state, true, pretend_update, mask1) &&
	exists(key_list, key, record, next_state, true, pretend_update, mask2) ||
	
	exists(key_list, key, record, next_state, true, pretend_update, mask3) ||
	
	(exists(key_list, key, record, next_state, true, pretend_update, mask4) ||
	 exists(key_list, key, record, next_state, true, pretend_update, mask5) )&&
	(exists(key_list, key, record, next_state, true, pretend_update, mask6) ||
	 exists(key_list, key, record, next_state, true, pretend_update, mask7) );
}

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

	return
	unsigned_ok(key_list, key, record, next_state, pretend_update, mask_unsg, DK) ||
	
	exists(key_list, key, record, next_state, true, pretend_update, mask_triv) ||
	
	exists(key_list, key, record, next_state, true, pretend_update, mask_keyi) &&
	exists(key_list, key, record, next_state, true, pretend_update, mask_keyo) ||
	
	exists(key_list, key, record, next_state, true, pretend_update, mask_sigi) &&
	exists(key_list, key, record, next_state, true, pretend_update, mask_sigo);
}

bool
dnssec_approval(KeyDataList &key_list, KeyData &key, const RECORD record, 
	const STATE next_state)
{
	bool a = rule1(key_list, key, record, next_state, false);
	bool b = rule2(key_list, key, record, next_state, false);
	bool c = rule3(key_list, key, record, next_state, false);
	bool d = rule1(key_list, key, record, next_state, true);
	bool e = rule2(key_list, key, record, next_state, true);
	bool f = rule3(key_list, key, record, next_state, true);
	
	ods_log_verbose("[%s] %d%d%d %d%d%d", module_str, a,b,c,d,e,f);

	
	return 
		(!rule1(key_list, key, record, next_state, false) ||
		  rule1(key_list, key, record, next_state, true ) ) &&
		(!rule2(key_list, key, record, next_state, false) ||
		  rule2(key_list, key, record, next_state, true ) ) &&
		(!rule3(key_list, key, record, next_state, false) ||
		  rule3(key_list, key, record, next_state, true ) );
}

time_t
addtime(const time_t &t, const int seconds)
{
	struct tm *tp = localtime(&t);
	tp->tm_sec += seconds;
	return mktime(tp);
}

time_t
min_transition_time(const Policy *policy, const RECORD record, const STATE state, 
	const STATE next_state, const time_t lastchange)
{
	const char *scmd = "min_transition_time";

	/* if previous state was a certain state record may
	 * transition directly. TODO improve comment */
	if (next_state == RUM || next_state == UNR) return lastchange;
	
	//~ ods_log_verbose("[%s] %d %d %d %d %d %d %d %d %d %d", module_str, 
	//~ policy->parent().ttlds(),
	//~ policy->parent().registrationdelay(),
	//~ policy->parent().propagationdelay(),
	//~ policy->keys().ttl(),
	//~ policy->zone().propagationdelay(),
	//~ policy->keys().publishsafety(),
	//~ policy->keys().retiresafety(),
	//~ policy->signatures().ttl(),
	//~ policy->zone().propagationdelay(),
	//~ lastchange
	//~ );
	
	switch(record) {
		case DS:
			return addtime(lastchange,
				  policy->parent().ttlds()
				+ policy->parent().registrationdelay()
				+ policy->parent().propagationdelay());
		/* TODO: 5011 will create special case here */
		case DK: /* intentional fall-through */
		case RD:
			return addtime(lastchange,
				  policy->keys().ttl()
				+ policy->zone().propagationdelay()
				+ (next_state == OMN)
					? policy->keys().publishsafety()
					: policy->keys().retiresafety());
		case RS:
			return addtime(lastchange,
				  policy->signatures().ttl()
				+ policy->zone().propagationdelay());
		default: 
			ods_fatal_exit("[%s] %s Unknown record type (%d), "
				"fault of programmer. Abort.",
				module_str, scmd, (int)record);
	}
}

/**
 * Try to push each key for this zone to a next state. If one changes
 * visit the rest again. Loop stops when no changes can be made without
 * advance of time. Return time of first possible event. 
 * */
time_t
updateZone(EnforcerZone &zone, const time_t now)
{
	time_t returntime_zone = -1;
	time_t returntime_key;
	bool change;
	KeyDataList &key_list = zone.keyDataList();
	const ::ods::kasp::Policy *policy = zone.policy();
	const char *scmd = "updateZone";
	ods_log_verbose("[%s] %s", module_str, scmd);

	/* Keep looping till there are no state changes.
	 * Find the soonest update time */
	do {
		change = false;
		/* Loop over all keys */
		for (int i = 0; i < key_list.numKeys(); i++) {
			KeyData &key = key_list.key(i);
			ods_log_verbose("[%s] %s processing key %s", module_str, scmd, key.locator().c_str());
			/* Loop over records */
			for (RECORD record = REC_MIN; record < REC_MAX; ++record) {
				STATE state = getState(key, record);
				STATE next_state = getDesiredState(key.introducing(), state);
				if (state == next_state) continue;
				ods_log_verbose("[%s] %s May %s transition to %s?", module_str, scmd, RECORDAMES[(int)record], STATENAMES[(int)next_state]);
				
				if (!policy_approval(key, record, next_state)) continue;
				ods_log_verbose("[%s] %s Policy says we can (1/3)", module_str, scmd);
				
				if (!dnssec_approval(key_list, key, record, next_state)) continue;
				ods_log_verbose("[%s] %s DNSSEC says we can (2/3)", module_str, scmd);
				/* do time stuff */
				time_t returntime_key = min_transition_time(policy, record, 
					state, next_state, getRecord(key, record).lastChange());
				//~ ods_log_verbose("[%s] %s retkey %d", module_str, scmd, returntime_key);

				if (returntime_key > now) {
					minTime(returntime_key, returntime_zone);
					continue;
				}
				ods_log_verbose("[%s] %s Timing says we can (3/3) now: %d key: %d", module_str, scmd, now, returntime_key);
				setState(key, record, next_state, now); //now == next change?
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
	if (!keyfactory.UseSharedKey(bits, repository, policy->name(), algorithm,
									 role, zone.name(), ppKey))
		return false;
	assert(*ppKey != NULL); /* FindSharedKeys() promised us. */
	/* Key must (still) be in use */
	if (now < (*ppKey)->inception() + lifetime)
		return true;
	/* Was set by default, unset */
	(*ppKey)->setUsedByZone(zone.name(), false);
	return false;
}

/* Abstraction to generalize different kind of keys. 
 * return number of keys _in_a_policy_ */
int 
numberOfKeys(const ::ods::kasp::Keys *policyKeys, const KeyRole role)
{
	const char *scmd = "numberOfKeys";
	switch (role) {
		case KSK: return policyKeys->ksk_size();
		case ZSK: return policyKeys->zsk_size();
		case CSK: return policyKeys->csk_size();
		default:
			ods_fatal_exit("[%s] %s Unknow Role: (%d)", 
					module_str, scmd, role); /* report a bug! */
	}
}

/* Abstraction to generalize different kind of keys. 
 * Note: a better solution would be inheritance. */
void 
keyProperties(const ::ods::kasp::Keys *policyKeys, const KeyRole role,
		const int index, int *bits, int *algorithm, int *lifetime,
        string &repository)
{
	const char *scmd = "keyProperties";
	assert(index < numberOfKeys(policyKeys, role)); /* programming error */
	
	switch (role) {
		case KSK:
			*bits	   = policyKeys->ksk(index).bits();
			*algorithm = policyKeys->ksk(index).algorithm();
			*lifetime  = policyKeys->ksk(index).lifetime();
            repository.assign(policyKeys->ksk(index).repository());
			break;
		case ZSK:
			*bits	   = policyKeys->zsk(index).bits();
			*algorithm = policyKeys->zsk(index).algorithm();
			*lifetime  = policyKeys->zsk(index).lifetime();
            repository.assign(policyKeys->zsk(index).repository());
			break;
		case CSK:
			*bits	   = policyKeys->csk(index).bits();
			*algorithm = policyKeys->csk(index).algorithm();
			*lifetime  = policyKeys->csk(index).lifetime();
            repository.assign(policyKeys->csk(index).repository());
			break;
		default:
			ods_fatal_exit("[%s] %s Unknow Role: (%d)",
					module_str, scmd, role); /* report a bug! */
	}
}

/**
 * Finds the last inserted key in the list. It's role must be a
 * subset or equal to role.
 * \param[in] keys list of keys to search in
 * \param[in] role minimum role target must have
 * \return time_t inception time of youngest matching key. -1 iff none found
 * */
time_t most_recent_inception(KeyDataList &keys, KeyRole role) {
	time_t most_recent = -1; /* default answer when no keys available */

	for (int k=0; k<keys.numKeys(); ++k) {
		KeyData &key = keys.key(k);
		if (!key.revoke() && (key.role()&role) == role && key.inception()) {
			if (key.inception() > most_recent)
				most_recent = key.inception();
		}
	}
	return most_recent;
}

/* See what needs to be done for the policy */
time_t updatePolicy(EnforcerZone &zone, const time_t now, HsmKeyFactory &keyfactory,
		KeyDataList &key_list) {
	time_t return_at = -1;
	const ::ods::kasp::Policy *policy = zone.policy();

	/* first look at policy */
	::ods::kasp::Keys policyKeys = policy->keys();
	const string policyName = policy->name();
	const char *scmd = "updatePolicy";

	ods_log_verbose("[%s] %s policyName: %s", module_str, scmd, policyName.c_str());

	int bits, algorithm, lifetime;
	time_t last_insert, next_insert;
	/* Visit every type of key-configuration, not pretty but we can't
	 * loop over enums. Include MAX in enum? */
	for ( int role = 1; role < 4; role++ ) {
		last_insert = most_recent_inception(zone.keyDataList(),(KeyRole)role); /* search all keys for this zone */
		/* NOTE: we are not looping over keys, but configurations */
		for ( int i = 0; i < numberOfKeys( &policyKeys, (KeyRole)role ); i++ ) {
			string repository;
			/* select key properties of key i in KeyRole role */
			keyProperties(&policyKeys, (KeyRole)role, i, &bits, &algorithm,
                			&lifetime, repository);
			next_insert = last_insert + lifetime;
			ods_log_verbose("[%s] %s last insert %d", module_str, scmd, last_insert);
			ods_log_verbose("[%s] %s lifetime %d", module_str, scmd, lifetime);
			if ( now < next_insert && last_insert != -1 ) {
				/* No need to change key, come back at */
				minTime( next_insert, return_at );
				continue;
			}

			/* time for a new key */
			ods_log_verbose("[%s] %s New key needed for role %d", module_str, scmd, role);
			string locator;
			HsmKey *hsm_key;
			bool got_key;

			if ( policyKeys.zones_share_keys() )
				got_key = getLastReusableKey(
					zone, policy, (KeyRole)role, bits, repository, algorithm, now,
					&hsm_key, keyfactory, lifetime)
				?
					true
				:
					keyfactory.CreateSharedKey(bits, repository, policyName,
					algorithm, (KeyRole)role, zone.name(),&hsm_key );
			else
				got_key = keyfactory.CreateNewKey(bits,repository, policyName,
                                                  algorithm, (KeyRole)role,
                                                  &hsm_key );
			if ( !got_key ) {
				/* The factory was not ready, return in 60s */
				minTime( now + NOKEY_TIMEOUT, return_at);
				ods_log_warning("[%s] %s No keys available on hsm, retry in %d seconds", module_str, scmd, NOKEY_TIMEOUT);
				continue;
			}

			ods_log_verbose("[%s] %s got new key from HSM", module_str, scmd);

			KeyData &new_key = zone.keyDataList().addNewKey( algorithm, now,
				(KeyRole)role, false, false, false);
			new_key.setLocator( hsm_key->locator() );
			/* fill next_key */
			new_key.setDSSeen( false );
			new_key.setSubmitToParent( false );
			new_key.keyStateDS().setState((role&KSK)?HID:NOCARE);
			new_key.keyStateDNSKEY().setState(HID);
			new_key.keyStateRRSIGDNSKEY().setState((role&KSK)?HID:NOCARE);
			new_key.keyStateRRSIG().setState((role&ZSK)?HID:NOCARE);
			new_key.keyStateDS().setLastChange(now);
			new_key.keyStateDNSKEY().setLastChange(now);
			new_key.keyStateRRSIGDNSKEY().setLastChange(now);
			new_key.keyStateRRSIG().setLastChange(now);
			new_key.setIntroducing(true);

			/* New key inserted, come back after its lifetime */
			minTime( now + lifetime, return_at );

			/* Tell similar keys to outroduce, skip new key*/
			for (int j = 0; j < key_list.numKeys(); j++) {
				KeyData &key = key_list.key(j);
				if (	!key.introducing() ||
					!(key.role() & role)||
					key.locator().compare(new_key.locator()) == 0)
					continue;
				key.setIntroducing(false);
				ods_log_verbose("[%s] %s decommissioning old key: %s", 
					module_str, scmd, key.locator().c_str());
			}
		}
	} /* loop over KeyRole */
	return return_at;
}

/* Removes all keys from list that are no longer used. */
inline void removeDeadKeys(KeyDataList &key_list) {
	const char *scmd = "removeDeadKeys";

	for (int i = key_list.numKeys()-1; i >= 0; i--) {
		KeyData &key = key_list.key(i);
		/* TODO make loop for this */
		if (	(getState(key, DS) == HID || getState(key, DS) == NOCARE) &&
				(getState(key, DK) == HID || getState(key, DK) == NOCARE) &&
				(getState(key, RD) == HID || getState(key, RD) == NOCARE) &&
				(getState(key, RS) == HID || getState(key, RS) == NOCARE) &&
				!key.introducing()) {
			ods_log_info("[%s] %s delete key: %s", module_str, scmd, key.locator().c_str());
			key_list.delKey(i);
		}
	}
}

/* see header file */
time_t update(EnforcerZone &zone, const time_t now, HsmKeyFactory &keyfactory) {
	time_t policy_return_time, zone_return_time;
	KeyDataList &key_list = zone.keyDataList();
	const char *scmd = "update";

	//~ ods_log_verbose("[%s] %s -----------------------", module_str, scmd, zone.name().c_str());
	ods_log_info("[%s] %s Zone: %s", module_str, scmd, zone.name().c_str());
	//~ ods_log_verbose("[%s] %s time: %d", module_str, scmd, now);

	policy_return_time = updatePolicy(zone, now, keyfactory, key_list);
	zone_return_time = updateZone(zone, now);

	removeDeadKeys(key_list);

	/* Always set these flags. Normally this needs to be done _only_
	 * when signerConfNeedsWriting() is set. However a previous
	 * signerconf might not be available, we have no way of telling. :(
	 * */
	/* if (zone.signerConfNeedsWriting()) { ... }*/
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &key = key_list.key(i);
		key.setPublish(getState(key, DK) == OMN || getState(key, DK) == RUM);
		key.setActive(getState(key, RS) == OMN || getState(key, RS) == RUM);
	}

	minTime(policy_return_time, zone_return_time);
	return zone_return_time;
}
