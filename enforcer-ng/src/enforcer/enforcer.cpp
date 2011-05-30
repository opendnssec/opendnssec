#include <ctime>
#include <iostream>
#include <cassert>

#include "enforcer/enforcer.h"
#include "enforcer/enforcerdata.h"
#include "policy/kasp.pb.h"

// Interface of this cpp file is used by C code, we need to declare
// extern "C" to prevent linking errors.
extern "C" {
	#include "shared/duration.h"
	#include "shared/log.h"
}

using namespace std;

static const char *module_str = "enforcer";

/* Move this to enforcerdata at later time?
 * Hidden, rumoured, comitted, omnipresent, unretentive, postcomitted
 * revoked
 * */
enum RecordState { HID, RUM, COM, OMN, UNR, PCM, REV };
string STATE_NAME[] = {"HID", "RUM", "COM", "OMN", "UNR", "PCM", "REV"};

/* When no key available wait this many seconds before asking again. */
#define NOKEY_TIMEOUT 60

/* Stores smallest of two times in *min.
 * Avoiding negative values, which mean no update necessary
 * */
inline void minTime(const time_t t, time_t &min) {
	if ( (t < min || min < 0) && t >= 0 )
		min = t;
}

/* Search for youngest key in use by any zone with this policy
 * with at least the roles requested. See if it isn't expired.
 * also, check if it isn't in zone already. Also length, algorithm
 * must match and it must be a first generation key.
 * */
bool getLastReusableKey(EnforcerZone &zone,
		const ::ods::kasp::Policy *policy, const KeyRole role,
        int bits, const string &repository, int algorithm, const time_t now, HsmKey **ppKey,
		HsmKeyFactory &keyfactory, int lifetime) {
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

/* Applies new state to record and keeps additional administration.
 * */
void setState(KeyState &record_state, const RecordState new_state,
		const time_t now ) {
	const char *scmd = "setState";
	
	ods_log_verbose("[%s] %s to %s", module_str, scmd, 
			STATE_NAME[new_state].c_str());
	record_state.setState(new_state);
	record_state.setLastChange(now);
}

/* A DS|DNSKEY|RRSIG RR is considered reliable (useable in a validation
 * chain) if it is known to all caches or it is being introduced and
 * another DS|DNSKEY|RRSIG is decommissioned at the same time.
 * */
bool reliableDs(KeyDataList &key_list, KeyData &key) {
	if (key.keyStateDS().state() == OMN) return true;
	if (key.keyStateDS().state() != COM) return false;
	int alg = key.algorithm();
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if  (k.keyStateDS().state() == PCM &&
				k.algorithm() == alg)
			return true;
	}
	return false;
}
bool reliableDnskey(KeyDataList &key_list, KeyData &key) {
	if (key.keyStateDNSKEY().state() == OMN) return true;
	if (key.keyStateDNSKEY().state() != COM) return false;
	int alg = key.algorithm();
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if  (k.keyStateDNSKEY().state() == PCM &&
				k.algorithm() == alg)
			return true;
	}
	return false;
}
bool reliableRrsig(KeyDataList &key_list, KeyData &key) {
	if (key.keyStateRRSIG().state() == OMN) return true;
	if (key.keyStateRRSIG().state() != COM) return false;
	int alg = key.algorithm();
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if  (k.keyStateRRSIG().state() == PCM &&
				k.algorithm() == alg)
			return true;
	}
	return false;
}

bool updateDs(EnforcerZone &zone, KeyDataList &key_list, KeyData &key,
		const time_t now, time_t &next_update_for_record) {
	bool record_changed = false;
	int num_keys = key_list.numKeys();
	const ::ods::kasp::Policy *policy = zone.policy();
	KeyData *k;
	time_t Tprop;

	bool exists_ds_postcomitted;
	bool forall;
	bool ds_omni_or_com;

	const char *scmd = "updateDs";

	KeyState &record_state = key.keyStateDS();
	ods_log_verbose("[%s] %s state %s", module_str, scmd, 
			STATE_NAME[record_state.state()].c_str());
	switch ( record_state.state() ) {

	case HID:
	if (!key.introducing() || key.standby()) break;
	if (!record_state.minimize()) {
		int similar_ksks = 0;
		if (key.keyStateDNSKEY().state() == OMN) {
			setState(record_state, RUM, now);
			record_changed = true;
			/* The DS record must be submit to the parent */
			key.setSubmitToParent(true);
			key.setDSSeen(false);
			/* The signer configuration does not change */
			break;
		}
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if (k->algorithm() == key.algorithm() &&
					reliableDs(key_list, *k) &&
					reliableDnskey(key_list, *k)) {
				setState(record_state, RUM, now);
				record_changed = true;
				/* The DS record must be submit to the parent */
				key.setSubmitToParent(true);
				key.setDSSeen(false);
				/* The signer configuration does not change */
				break;
			}
		}
	}
	if (key.keyStateDNSKEY().state() == OMN) {
		setState(record_state, COM, now);
		record_changed = true;
		/* The DS record must be submit to the parent */
		key.setSubmitToParent(true);
		key.setDSSeen(false);
		/* The signer configuration does not change */
	}
	break;

	case RUM:
	if (!key.introducing()) {
		setState(record_state, UNR, now);
		record_changed = true;
		/* The DS record withdrawal must be submit to the parent */
		key.setSubmitToParent(true);
		key.setDSSeen(false);
		/* The signer configuration does not change */
	} else if (key.isDSSeen()) {
		Tprop = record_state.lastChange() + policy->parent().ttlds()
				+ policy->parent().registrationdelay()
				+ policy->parent().propagationdelay();
		if (now >= Tprop) {
			setState(record_state, OMN, now);
			record_changed = true;
			/* There is no next update scheduled for this record
			 * since it is now omnipresent and introducing */
		} else {
			/* All requirements are met but not the propagation time
			 * ask to come back at a later date. */
			next_update_for_record = Tprop;
		}
	}
	break;

	case COM:
	if (!key.isDSSeen()) break;
	Tprop = record_state.lastChange() + policy->parent().ttlds()
			+ policy->parent().registrationdelay()
			+ policy->parent().propagationdelay();
	if (now >= Tprop) {
		setState(record_state, OMN, now);
		record_changed = true;
		/* There is no next update scheduled for this record
		 * since it is now omnipresent and introducing */
	} else {
		/* All requirements are met but not the propagation time
		 * ask to come back at a later date. */
		next_update_for_record = Tprop;
	}
	break;

	case OMN:
	if (key.introducing()) break; /* already there */
	if (key.keyStateDNSKEY().state() != OMN) {
		bool exists_ds_comitted = false;
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if (k->keyStateDS().state() == COM) {
				exists_ds_comitted = true;
				break;
			}
		}
		if (exists_ds_comitted) {
			setState(record_state, PCM, now);
			record_changed = true;
			/* The DS record withdrawal must be submit to the parent */
			key.setSubmitToParent(true);
			key.setDSSeen(false);
			/* The signer configuration does not change */
			break; /* from switch */
		}
	}

	if (key.keyStateDNSKEY().state() == PCM) break;

	exists_ds_postcomitted = false;
	for (int i = 0; i < num_keys; i++) {
		k = &key_list.key(i);
		if (k->keyStateDS().state() == PCM) {
			exists_ds_postcomitted = true;
			break;
		}
	}
	forall = true;
	ds_omni_or_com = false;
	for (int i = 0; i < num_keys; i++) {
		k = &key_list.key(i);
		ds_omni_or_com |= k != &key && (k->keyStateDS().state() == OMN ||
				(k->keyStateDS().state() == COM && exists_ds_postcomitted));
		if (k->algorithm() != key.algorithm() ) continue;
		if (k->keyStateDS().state() == HID) continue;
		if (reliableDnskey(key_list, *k)) continue;

		/* Leave innerloop as last check,
		 * for performance. */
		bool hasReplacement = false;
		KeyData *l;
		for (int j = 0; j < num_keys; j++) {
			l = &key_list.key(j);
			if (l->algorithm() == k->algorithm() && l != &key
					&& reliableDs(key_list, *l) && reliableDnskey(key_list, *l)) {
				hasReplacement = true;
				break;
			}
		}
		if (!hasReplacement) {
			forall = false;
			break;
		}
	}

	if (ds_omni_or_com && forall) {
		setState(record_state, UNR, now);
		record_changed = true;
		/* The DS record withdrawal must be submit to the parent */
		key.setSubmitToParent(true);
		key.setDSSeen(false);
		/* The signer configuration does not change */
	}
	break;

	case UNR:
	/* We might *not* allow this, for simplicity */
	if (key.introducing()) {
		setState(record_state, RUM, now);
		record_changed = true;
		/* The DS record withdrawal must be submit to the parent */
		key.setSubmitToParent(true);
		key.setDSSeen(false);
		/* The signer configuration does not change */
		break;
	}
	Tprop = record_state.lastChange() + policy->parent().ttlds()
			+ policy->parent().registrationdelay()
			+ policy->parent().propagationdelay();
	if (now >= Tprop) {
		setState(record_state, HID, now);
		record_changed = true;
	} else {
		next_update_for_record = Tprop;
	}
	break;

	case PCM:
	Tprop = record_state.lastChange() + policy->parent().ttlds()
			+ policy->parent().registrationdelay()
			+ policy->parent().propagationdelay();
	if (now >= Tprop) {
		setState(record_state, HID, now);
		record_changed = true;
		/* no need to notify signer. Nothing changes in
		 * its perspective. */
	} else {
		next_update_for_record = Tprop;
	}
	break;

	case REV:
		/* NOT IMPL */
	break;

	default:
		assert(0); /* Nonexistent state. */
	}

	return record_changed;
}

bool updateDnskey(EnforcerZone &zone, KeyDataList &key_list,
		KeyData &key, const time_t now, time_t &next_update_for_record) {
	bool record_changed = false;
	bool signer_needs_update = false;
	next_update_for_record = -1;
	const ::ods::kasp::Policy *policy = zone.policy();
	int num_keys = key_list.numKeys();
	KeyData *k, *l;
	time_t Tprop;

	const char *scmd = "updateDnskey";

	KeyState &record_state = key.keyStateDNSKEY();
	ods_log_verbose("[%s] %s state %s", module_str, scmd, 
			STATE_NAME[record_state.state()].c_str());
	switch ( record_state.state() ) {

	case HID:
	if (!key.introducing()) break;
	if (record_state.minimize() && (key.keyStateDS().state() == OMN ||
		!(key.role() & KSK)) &&
		(key.keyStateRRSIG().state() == OMN ||
		!(key.role() & ZSK)) ) {
		setState(record_state, COM, now);
		record_changed = true;
		/* The DNSKEY now needs to be published. */
		signer_needs_update = true;
		break;
	}
	if (record_state.minimize() && !key.standby()) {
		bool noneExist = true;
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if (!(key.algorithm() == k->algorithm() &&
					reliableDnskey(key_list, *k) &&
					key.role() & KSK)){
				noneExist = false;
				break;
			}
		}
		if (!noneExist) break;
	}
	if (!reliableRrsig(key_list, key)) {
		bool oneExist = false;
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if (key.algorithm() == k->algorithm() &&
					reliableDnskey(key_list, *k) &&
					reliableRrsig(key_list, *k)){
				oneExist = true;
				break;
			}
		}
		if (!oneExist) break;
	}
	setState(record_state, RUM, now);
	record_changed = true;
	/* The DNSKEY now needs to be published. */
	signer_needs_update = true;
	break;

	case RUM:
	if (!key.introducing()) {
		setState(record_state, UNR, now);
		record_changed = true;
		signer_needs_update = true;
		break;
	}
	Tprop = record_state.lastChange() + policy->keys().ttl()
			+ policy->keys().publishsafety()
			+ policy->zone().propagationdelay();
	if (now >= Tprop) {
		setState(record_state, OMN, now);
		record_changed = true;
		break;
	}
	next_update_for_record = Tprop;
	break;

	case COM:
	Tprop = record_state.lastChange() + policy->keys().ttl()
			+ policy->keys().publishsafety()
			+ policy->zone().propagationdelay();
	if (now >= Tprop) {
		setState(record_state, OMN, now);
		record_changed = true;
		break;
	}
	next_update_for_record = Tprop;
	break;

	case OMN:
	if (key.introducing() || key.keyStateDS().state() == PCM ||
		key.keyStateRRSIG().state() == PCM ) break;
	if ( key.keyStateDS().state() == OMN &&
		key.keyStateRRSIG().state() == OMN &&
		!key.revoke()) {
		bool hasReplacement = false;
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if ( k->keyStateDNSKEY().state() == COM &&
					key.algorithm() == k->algorithm() &&
					key.role() == k->role() ) {
				hasReplacement = true;
				break;
			}
		}
		if ( hasReplacement ) {
		/* withdraw stuff */
		setState(record_state, PCM, now);
		record_changed = true;
		break;
		}
	}
	if ( key.keyStateDS().state() != PCM &&
			key.keyStateRRSIG().state() != PCM ) {
		/* We must check if any other key depend on 'key'
		 * if so, we can not take an action */
		bool all = true;
		/* forall */
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			//~ if (&key == k) continue;
			bool ksk_ok, zsk_ok;
			ksk_ok = !(k->role() & KSK) || k->keyStateDS().state() == HID ||
				(k != &key && reliableDnskey(key_list, *k));
			zsk_ok = !(k->role() & ZSK) || k->keyStateRRSIG().state() == HID ||
				(k != &key && reliableRrsig(key_list, *k));
			if (ksk_ok && zsk_ok) continue;
			/* This key breaks the chain, see if there is a
			 * candidate that fixes this. */
			/* exists */
			for ( int j = 0; j < num_keys; j++ ) {
				l = &key_list.key(j);
				if ( 		k == l ||
						k->algorithm() == l->algorithm() ||
	                                        reliableDnskey( key_list, *l ) )
					continue;
				ksk_ok |= reliableDs( key_list, *l );
				zsk_ok |= reliableRrsig( key_list, *l );
				if (ksk_ok && zsk_ok) break; /* inner loop */
			}
			if ( !ksk_ok || !zsk_ok ) {
				all = false;
				break; /* outer loop */
			}
		}
		if ( all ) {
			setState(record_state, key.revoke() ? REV : UNR, now);
			record_changed = true;
			/* submit or revoke stuff */
		}
	}
	break;

	case REV:
	Tprop = 0 /* TODO */;
	if (now >= Tprop) {
		setState(record_state, UNR, now);
		record_changed = true;
	} else {
		next_update_for_record = Tprop;
	}
	break;

	case UNR:
	Tprop = record_state.lastChange() + policy->keys().ttl()
			+ policy->keys().retiresafety()
			+ policy->zone().propagationdelay();
	if (key.introducing()) {
		/* submit,
		 * key->dnskey_state = Key::ST_UNRETENTIVE;
		 * record_changed = true;
		 * */
	} else if (now >= Tprop) {
		setState(record_state, HID, now);
		record_changed = true;
	} else {
		next_update_for_record = Tprop;
	}
	break;

	case PCM:
	break;

	}

	if (signer_needs_update) zone.setSignerConfNeedsWriting(true);
	return record_changed;
}

bool updateRrsig(EnforcerZone &zone, KeyDataList &key_list, KeyData &key,
		const time_t now, time_t &next_update_for_record) {
	bool record_changed = false;
	bool signer_needs_update = false;
	next_update_for_record = -1;
	const ::ods::kasp::Policy *policy = zone.policy();
	int num_keys = key_list.numKeys();
	KeyData *k;
	time_t Tprop;
	const char *scmd = "updateRrsig";

	bool exists;
	bool safeToWithdraw;

	KeyState &record_state = key.keyStateRRSIG();
	ods_log_verbose("[%s] %s state %s", module_str, scmd, 
			STATE_NAME[record_state.state()].c_str());
	switch ( record_state.state() ) {

	case HID:
	if ( !key.introducing() || key.standby() ) {
		ods_log_info("[%s] %s, not introducing or standby ", module_str, scmd);
		break;
	}
	exists = false;
	if (!record_state.minimize()) {
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if ( key.algorithm() == k->algorithm() &&
					reliableRrsig(key_list, *k) ) {
				exists = true;
				break;
			}
		}
	}
	if ( !exists || !record_state.minimize() ) {
		/* submit stuff */
		ods_log_info("[%s] %s, not exists", module_str, scmd);
		setState(record_state, RUM, now);
		record_changed = true;
		break;
	}
	if ( key.keyStateRRSIG().minimize() &&
			key.keyStateDNSKEY().state() == OMN) {
		/* submit stuff */
		ods_log_info("[%s] %s, minimize", module_str, scmd);
		setState(record_state, COM, now);
		record_changed = true;
		break;
	}
	ods_log_info("[%s] %s, no match", module_str, scmd);
	break;

	case RUM:
	//ods_log_info("[%s] %s, info sigttl %d", module_str, scmd, policy->signatures().ttl());
	//ods_log_info("[%s] %s, info prpdly %d", module_str, scmd, policy->zone().propagationdelay());
	Tprop = record_state.lastChange() + policy->signatures().ttl()
			+ policy->zone().propagationdelay();
	if ( !key.introducing() ) {
		/* withdraw stuff */
		setState(record_state, UNR, now);
		record_changed = true;
		break;
	} else if ( now >= Tprop ) {
		/* do stuff */
		setState(record_state, OMN, now);
		record_changed = true;
		break;
	} else {
		next_update_for_record = Tprop;
	}
	break;

	case COM:
	Tprop = record_state.lastChange() + policy->signatures().ttl()
			+ policy->zone().propagationdelay();
	if ( now >= Tprop ) {
		/* do stuff */
		setState(record_state, OMN, now);
		record_changed = true;
		break;
	}
	break;

	case OMN:
	if ( key.introducing() ) break;
	if ( key.keyStateDNSKEY().state() == OMN ) {
		bool exist3 = false;
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if ( k->keyStateRRSIG().state() == COM &&
					key.algorithm() == k->algorithm() ) {
				exist3 = true;
				break;
			}
		}
		if ( exist3 ) {
			setState(record_state, HID, now);
			record_changed = true;
			break;
		}
	}
	if ( key.keyStateDNSKEY().state() == PCM ) break;

	safeToWithdraw = ( key.keyStateDNSKEY().state() == HID );
	if ( !safeToWithdraw ) {
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if ( &key != k && key.algorithm() == k->algorithm() &&
					reliableDnskey(key_list, *k) &&
					reliableRrsig(key_list, *k)) {
				safeToWithdraw = true;
				break;
			}
		}
	}
	if ( safeToWithdraw ) {
		/* submit stuff */
		setState(record_state, UNR, now);
		record_changed = true;
		break;
	}
	break;

	case REV:
	break;

	case UNR:
	Tprop = record_state.lastChange() + policy->signatures().ttl()
			+ policy->zone().propagationdelay();
	if ( key.introducing()) {
	    /* submit
	     * state -> rumoured
	     break;*/
	} if ( now >= Tprop ) {
		setState(record_state, HID, now);
		record_changed = true;
	    break;
	} else {
		next_update_for_record = Tprop;
	}
	break;

	case PCM:
	Tprop = record_state.lastChange() + policy->signatures().ttl()
			+ policy->zone().propagationdelay();
	if ( now >= Tprop ) {
		setState(record_state, HID, now);
		record_changed = true;
	    break;
	} else {
		next_update_for_record = Tprop;
	}

	break;

    }

    if (signer_needs_update)
		zone.setSignerConfNeedsWriting(true);
    return record_changed;
}

/* updateKey
 * Updates all relevant (with respect to role) records of a key.
 *
 * @return: true on any changes within this key */
bool updateKey(EnforcerZone &zone, KeyDataList &key_list, KeyData &key,
		const time_t now, time_t &next_update_for_key) {
	time_t next_update_for_record = -1;
	next_update_for_key = -1;
	bool key_changed = false;
	const char *scmd = "updateKey";

	ods_log_info("[%s] %s %s", module_str, scmd, key.locator().c_str());
	
	if (key.role() & KSK) { /* KSK and CSK */
		key_changed |= updateDs(zone, key_list, key, now, next_update_for_record);
		minTime(next_update_for_record, next_update_for_key);
	}

	key_changed |= updateDnskey(zone, key_list, key, now, next_update_for_record);
	minTime(next_update_for_record, next_update_for_key);

	if (key.role() & ZSK) { /* ZSK and CSK */
		key_changed |= updateRrsig(zone, key_list, key, now, next_update_for_record);
		minTime(next_update_for_record, next_update_for_key);
	}
	return key_changed;
}

/**
 * Try to push each key for this zone to a next state. If one changes
 * visit the rest again. Loop stops when no changes can be made without
 * advance of time. Return time of first possible event. */
time_t updateZone(EnforcerZone &zone, const time_t now) {
	time_t return_at = -1;
	time_t next_update_for_key;
	KeyDataList &key_list = zone.keyDataList();
	const char *scmd = "updateZone";
	int dbg_cnt = 0;
	
	ods_log_verbose("[%s] %s", module_str, scmd);

	/* Keep looping till there are no state changes.
	 * Find the soonest update time */
	bool a_key_changed = true;
	while (a_key_changed) {
		a_key_changed = false;
		/* Loop over all keys */
		for (int i = 0; i < key_list.numKeys(); i++) {
			if (updateKey(zone, key_list, key_list.key(i), now, next_update_for_key)) {
				a_key_changed = true;
				dbg_cnt++;
			}
			minTime(next_update_for_key, return_at);
		}
	}
	ods_log_verbose("[%s] %s %d changes in keylist", module_str, scmd, dbg_cnt);
	return return_at;
}

/* Abstraction to generalize different kind of keys. */
int numberOfKeys(const ::ods::kasp::Keys *policyKeys, const KeyRole role) {
	const char *scmd = "numberOfKeys";
	
	switch (role) {
		case KSK:
			return policyKeys->ksk_size();
		case ZSK:
			return policyKeys->zsk_size();
		case CSK:
			return policyKeys->csk_size();
		default:
			ods_fatal_exit("[%s] %s Unknow Role: (%d)", 
					module_str, scmd, role); /* report a bug! */
	}
}

/* Abstraction to generalize different kind of keys. */
void keyProperties(const ::ods::kasp::Keys *policyKeys, const KeyRole role,
		const int index, int *bits, int *algorithm, int *lifetime,
        string &repository) {
	const char *scmd = "keyProperties";

	switch (role) {
		case KSK:
			assert(index < policyKeys->ksk_size());
			*bits	   = policyKeys->ksk(index).bits();
			*algorithm = policyKeys->ksk(index).algorithm();
			*lifetime  = policyKeys->ksk(index).lifetime();
            repository.assign(policyKeys->ksk(index).repository());
			return;
		case ZSK:
			assert(index < policyKeys->zsk_size());
			*bits	   = policyKeys->zsk(index).bits();
			*algorithm = policyKeys->zsk(index).algorithm();
			*lifetime  = policyKeys->zsk(index).lifetime();
            repository.assign(policyKeys->zsk(index).repository());
			return;
		case CSK:
			assert(index < policyKeys->csk_size());
			*bits	   = policyKeys->csk(index).bits();
			*algorithm = policyKeys->csk(index).algorithm();
			*lifetime  = policyKeys->csk(index).lifetime();
            repository.assign(policyKeys->csk(index).repository());
			return;
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
				ods_log_info("[%s] %s No keys available on hsm, retry in %d seconds", module_str, scmd, NOKEY_TIMEOUT);
				continue;
			}


			ods_log_verbose("[%s] %s got new key from HSM", module_str, scmd);

			KeyData &new_key = zone.keyDataList().addNewKey( algorithm, now,
				(KeyRole)role, false, false, false);
			new_key.setLocator( hsm_key->locator() );
			/* fill next_key */
			new_key.setDSSeen( false );
			new_key.setSubmitToParent( false );
			new_key.keyStateDS().setState(HID);
			new_key.keyStateDNSKEY().setState(HID);
			new_key.keyStateRRSIG().setState(HID);
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
		if (	key.keyStateDS().state() == HID &&
				key.keyStateDNSKEY().state() == HID &&
				key.keyStateRRSIG().state() == HID &&
				!key.introducing()) {
			ods_log_verbose("[%s] %s delete key: %s", module_str, scmd, key.locator().c_str());
			key_list.delKey(i);
		}
	}
}

/* see header file */
time_t update(EnforcerZone &zone, const time_t now, HsmKeyFactory &keyfactory) {
	time_t policy_return_time, zone_return_time;
	KeyDataList &key_list = zone.keyDataList();
	const char *scmd = "update";

	ods_log_verbose("[%s] %s -----------------------", module_str, scmd, zone.name().c_str());
	ods_log_info("[%s] %s zoneName: %s", module_str, scmd, zone.name().c_str());
	ods_log_verbose("[%s] %s time: %d", module_str, scmd, now);

	policy_return_time = updatePolicy(zone, now, keyfactory, key_list);
	zone_return_time = updateZone(zone, now);

	removeDeadKeys(key_list);

	/* Always set these flags. Normally this needs to be done _only_
	 * when signerConfNeedsWriting() is set. However a previous
	 * signerconf might not be available, we have no way of telling. :(
	 * */
	/* if (zone.signerConfNeedsWriting()) { ... }*/
	KeyData *key;
	for (int i = 0; i < key_list.numKeys(); i++) {
		key = &key_list.key(i);
		key->setPublish(
			key->keyStateDNSKEY().state() == OMN ||
			key->keyStateDNSKEY().state() == RUM ||
			key->keyStateDNSKEY().state() == COM);
		key->setActive(
			key->keyStateRRSIG().state() == OMN ||
			key->keyStateRRSIG().state() == RUM ||
			key->keyStateRRSIG().state() == COM);
	}

	minTime(policy_return_time, zone_return_time);
	return zone_return_time;
}
