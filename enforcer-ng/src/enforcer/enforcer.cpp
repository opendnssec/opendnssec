#include <ctime>
#include <iostream>
#include <cassert>

#include "enforcer/enforcerdata.h"
#include "policy/kasp.pb.h"
#include "enforcer/enforcer.h"

// Interface of this cpp file is used by C code, we need to declare
// extern "C" to prevent linking errors.
extern "C" {
	#include "shared/duration.h"
}

/* Move this to enforcerdata at later time?
 * Hidden, rumoured, comitted, omnipresent, unretentive, postcomitted
 * revoked
 * */
enum RecordState { HID, RUM, COM, OMN, UNR, PCM, REV };

#define NOKEY_TIMEOUT 60

using namespace std;

/* Stores smallest of two times in *min.
 * Avoiding negative values, which mean no update necessary
 * */
inline void minTime(const time_t t, time_t &min) {
	if ( (t < min or min < 0) and t >= 0 )
		min = t;
}

/* Search for youngest key in use by any zone with this policy
 * with at least the roles requested. See if it isn't expired.
 * also, check if it isn't in zone already. Also length, algorithm
 * must match and it must be a first generation key. 
 * */
bool getLastReusableKey( EnforcerZone &zone,
		const ::ods::kasp::Policy *policy, const KeyRole role,
		int bits, int algorithm, const time_t now, HsmKey **ppKey,
		HsmKeyFactory &keyfactory, int lifetime) {
	if (not keyfactory.UseSharedKey(bits, policy->name(), algorithm,
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

void setState( KeyState &record_state, const RecordState new_state, const time_t now ) {
	record_state.setState(new_state);
	record_state.setLastChange(now);
}

bool reliableDs(KeyDataList &key_list, KeyData *key) {
	if (key->keyStateDS().state() == OMN) return true;
	if (key->keyStateDS().state() != COM) return false;
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if  (k.keyStateDS().state() == PCM and
				k.algorithm() == key->algorithm())
			return true;
	}
	return false;
}

bool reliableDnskey(KeyDataList &key_list, KeyData *key) {
	if (key->keyStateDNSKEY().state() == OMN) return true;
	if (key->keyStateDNSKEY().state() != COM) return false;
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if  (k.keyStateDNSKEY().state() == PCM and
				k.algorithm() == key->algorithm())
			return true;
	}
	return false;
}

bool reliableRrsig(KeyDataList &key_list, KeyData *key) {
	if (key->keyStateRRSIG().state() == OMN) return true;
	if (key->keyStateRRSIG().state() != COM) return false;
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if  (k.keyStateRRSIG().state() == PCM and
				k.algorithm() == key->algorithm())
			return true;
	}
	return false;
}

bool updateDs(KeyDataList &key_list, KeyData &key, const time_t now, time_t &next_update_for_record) {
	bool record_changed = false;
	bool signer_needs_update = false;
	next_update_for_record = -1;
	int num_keys = key_list.numKeys();
	KeyData *k;
	time_t Tprop;

	bool exists_ds_postcomitted;
	bool forall;
	bool ds_omni_or_com;

	KeyState &record_state = key.keyStateDS();
	switch ( record_state.state() ) {

	case HID:
	if (key.introducing() and not key.standby()) {
		if (not record_state.minimize()) {
			for (int i = 0; i < num_keys; i++) {
				k = &key_list.key(i);
				if (k->algorithm() == key.algorithm() and
						reliableDs(key_list, k) and
						reliableDnskey(key_list, k)) {
					setState(record_state, RUM, now);
					record_changed = true;
					/* The DS record must be submit to the parent */
					key.setSubmitToParent(true);
					key.setDSSeen(false);
					/* The signer configuration does not change */
					break;
				}
			}
		} else if (key.keyStateDNSKEY().state() == OMN) {
			setState(record_state, COM, now);
			record_changed = true;
			/* The DS record must be submit to the parent */
			key.setSubmitToParent(true);
			key.setDSSeen(false);
			/* The signer configuration does not change */
		}
	}
	break;

	case RUM:
	if (not key.introducing()) {
		setState(record_state, UNR, now);
		record_changed = true;
		/* The DS record withdrawal must be submit to the parent */
		key.setSubmitToParent(true);
		key.setDSSeen(false);
		/* The signer configuration does not change */
	} else if (key.isDSSeen()) {
		Tprop = 0; /* some propagation time. TODO */
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
	if (key.isDSSeen()) {
		Tprop = 0; /* some propagation time. TODO */
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

	case OMN:
	if (key.introducing()) break; /* already there */

	if (key.keyStateDNSKEY().state() == OMN) {
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
		ds_omni_or_com |= k!=&key and (k->keyStateDS().state() == OMN or
				(k->keyStateDS().state() == COM and exists_ds_postcomitted));
		if (k->algorithm() != key.algorithm() ) continue;
		if (k->keyStateDS().state() == HID) continue;
		if (reliableDnskey(key_list, k)) continue;

		/* Leave innerloop as last check,
		 * for performance. */
		bool hasReplacement = false;
		KeyData *l;
		for (int j = 0; j < num_keys; j++) {
			l = &key_list.key(j);
			if (l->algorithm() == k->algorithm() and l != &key
					and reliableDs(key_list, l) and reliableDnskey(key_list, l)) {
				hasReplacement = true;
				break;
			}
		}
		if (not hasReplacement) {
			forall = false;
			break;
		}
	}

	if (ds_omni_or_com and forall) {
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
	Tprop = 0 /* TODO */;
	if (now >= Tprop) {
		setState(record_state, HID, now);
		record_changed = true;
	} else {
		next_update_for_record = Tprop;
	}
	break;

	case PCM:
	Tprop = 0 /* TODO */;
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

	/* check here for consistency. Signer never needs to know about
	 * DS changes. */
	if (signer_needs_update) {
	//zone->
	}
	return record_changed;
}

bool updateDnskey(KeyDataList &key_list, KeyData &key, const time_t now, time_t &next_update_for_record) {
	bool record_changed = false;
	bool signer_needs_update = false;
	next_update_for_record = -1;
	int num_keys = key_list.numKeys();
	KeyData *k, *l;
	time_t Tprop;
	
	KeyState &record_state = key.keyStateDNSKEY();
	switch ( record_state.state() ) {

	case HID:
	if (not key.introducing()) break;
	if (record_state.minimize() and (key.keyStateDS().state() == OMN or
		not key.role() & KSK) and
		(key.keyStateRRSIG().state() == OMN or 
		not key.role() & ZSK) ) {
		setState(record_state, COM, now);
		record_changed = true;
		/* The DNSKEY now needs to be published. */
		signer_needs_update = true;
		break;
	}
	if (record_state.minimize() and not key.standby()) {
		bool noneExist = true;
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if (not (key.algorithm() == k->algorithm() and
					reliableDnskey(key_list, k) and 
					key.role() & KSK)){
				noneExist = false;
				break;
			}
		}
		if (not noneExist) break;
	}
	if (not reliableDnskey(key_list, &key)) {
		bool oneExist = false;
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if (not (key.algorithm() == k->algorithm() and
					reliableDnskey(key_list, k) and 
					reliableRrsig(key_list, k))){
				oneExist = true;
				break;
			}
		}
		if (not oneExist) break;
	}
	setState(record_state, RUM, now);
	record_changed = true;
	/* The DNSKEY now needs to be published. */
	signer_needs_update = true;
	break;

	case RUM:
	if (not key.introducing()) {
		setState(record_state, UNR, now);
		record_changed = true;
		signer_needs_update = true;
		break;
	}
	Tprop = 0; /* TODO */
	if (now >= Tprop) {
		setState(record_state, OMN, now);
		record_changed = true;
		break;
	}
	next_update_for_record = Tprop;
	break;

	case COM:
	Tprop = 0; /* TODO */
	if (now >= Tprop) {
		setState(record_state, OMN, now);
		record_changed = true;
		break;
	}
	next_update_for_record = Tprop;
	break;

	case OMN:
	if (key.introducing() or key.keyStateDS().state() == PCM or
		key.keyStateRRSIG().state() == PCM ) break;
	if ( key.keyStateDS().state() == OMN and 
		key.keyStateRRSIG().state() == OMN and
		not key.revoke()) {
		bool hasReplacement = false;
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if ( k->keyStateDNSKEY().state() == COM and
					key.algorithm() == k->algorithm() and
					key.role() == k->role() ) {
				hasReplacement = true;
				break;
			}
		}
		if ( hasReplacement ) {
		/* withdraw stuff */
		record_state.setState( PCM );
		record_changed = true;
		break;
		}
	}
	if ( not key.keyStateDS().state() == PCM and
			not key.keyStateRRSIG().state() == PCM ) {
		bool all = true;
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if ( k->role() & KSK and k->keyStateDS().state() != HID and 
					(k == &key or not reliableDnskey(key_list, k)) ) {
				/* This key breaks the chain, see if there is a
				 * candidate that fixes this. */
				all = false;
				for ( int j = 0; j < num_keys; j++ ) {
					l = &key_list.key(j);
					if ( k != l and k->algorithm() == l->algorithm() and
							reliableDs( key_list, l ) and 
							reliableDnskey( key_list, l ) ) {
						all = true;
						break;
					}
				}
				if ( not all ) break;
			}
			/* Passed the first test */
			if ( k->keyStateDNSKEY().state() != HID and 
				not reliableRrsig( key_list, k ) ) {
				/* This key breaks the chain, see if there is a
				 * candidate that fixes this. */
				all = false;
				for ( int j = 0; j < num_keys; j++ ) {
					l = &key_list.key(j);
					if ( k != l and k->algorithm() == l->algorithm() and
							reliableRrsig( key_list, l ) and 
							reliableDnskey( key_list, l ) ) {
						all = true;
						break;
					}
				}
				if ( not all ) break;
			}
		}
		if ( not all ) break; /* from switch */
		key.keyStateDNSKEY().setState( key.revoke() ? REV : UNR );
		record_changed = true;
		/* submit or revoke stuff */
		break;
	}
	break;

	case REV:
	if (now >= /* some time */ 0) {
		key.keyStateDNSKEY().setState( UNR );
		record_changed = true;
	}
	break;

	case UNR:
	if (key.introducing()) {
		/* submit,
		 * key->dnskey_state = Key::ST_UNRETENTIVE;
		 * record_changed = true;
		 * */
	}
	else if (now >= /* some time */ 0) {
		key.keyStateDNSKEY().setState( HID );
		record_changed = true;
	}
	break;

	case PCM:
	break;

	}

	return record_changed;
}
bool updateRrsig(KeyDataList &key_list, KeyData &key, const time_t now, time_t &next_update_for_record) {
	bool record_changed = false;
	bool signer_needs_update = false;
	next_update_for_record = -1;
	int num_keys = key_list.numKeys();
	KeyData *k, *l;
	time_t Tprop;
	
	bool exists;
	bool safeToWithdraw;
	
	KeyState &record_state = key.keyStateRRSIG();
	switch ( record_state.state() ) {

	case HID:
	if ( not key.introducing() or key.standby() ) break;
	exists = false;
	if (not record_state.minimize()) {
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if ( key.algorithm() == k->algorithm() and 
					reliableRrsig(key_list, k) ) {
				exists = true;
				break;
			}
		}
	}
	if ( not exists ) {
		/* submit stuff */
		key.keyStateRRSIG().setState( RUM );
		record_changed = true;
		break;
	}
	if ( key.keyStateRRSIG().minimize() and 
			key.keyStateDNSKEY().state() == OMN) {
		/* submit stuff */
		key.keyStateRRSIG().setState( COM );
		record_changed = true;
		break;
	}
	break;
	
	case RUM:
	if ( not key.introducing() ) {
	    /* withdraw stuff */
	    key.keyStateRRSIG().setState( UNR );
	    record_changed = true;
	    break;
	}
	else if ( now >= /* some time */ 0 ) {
	    /* do stuff */
	    key.keyStateRRSIG().setState( OMN );
	    record_changed = true;
	    break;
	}
	break;
	
	case COM:
	if ( now >= /* some time */ 0 ) {
	    /* do stuff */
	    key.keyStateRRSIG().setState( OMN );
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
			if ( k->keyStateRRSIG().state() == COM and
					key.algorithm() == k->algorithm() ) {
				exist3 = true;
				break;
			}
		}
		if ( exist3 ) {
			key.keyStateRRSIG().setState( HID );
			record_changed = true;
			break;
		}
	}
	if ( key.keyStateDNSKEY().state() == PCM ) break;
	
	safeToWithdraw = ( key.keyStateDNSKEY().state() == HID );
	if ( not safeToWithdraw ) {
		for (int i = 0; i < num_keys; i++) {
			k = &key_list.key(i);
			if ( &key != k and key.algorithm() == k->algorithm() and
					reliableDnskey(key_list, k) and 
					reliableRrsig(key_list, k)) {
				safeToWithdraw = true;
				break;
			}
		}
	}
	if ( safeToWithdraw ) {
		/* submit stuff */
		key.keyStateRRSIG().setState( UNR );
		record_changed = true;
		break;
	}
	break;
	
	case REV:
	break;
	
	case UNR:
	if ( key.introducing()) {
	    /* submit
	     * state -> rumoured
	     break;*/
	}
	if ( now >= /* some time */ 0 ) {
		key.keyStateRRSIG().setState( HID );
		record_changed = true;
	    break;
	}
	break;
	
	case PCM:
	if ( now >= /* some time */ 0 ) {
		key.keyStateRRSIG().setState( HID );
		record_changed = true;
	    break;
	}
	break;
	
    }
    return record_changed;
}

/* updateKey
 * Updates all relevant (with respect to role) records of a key.
 *
 * @return: true on any changes within this key */
bool updateKey(KeyDataList &key_list, KeyData &key, const time_t now, time_t &next_update_for_key) {
	time_t next_update_for_record = -1;
	next_update_for_key = -1;
	bool key_changed = false;

	if (key.role() & KSK) { /* KSK and CSK */
		key_changed |= updateDs(key_list, key, now, next_update_for_record);
		minTime(next_update_for_record, next_update_for_key);
	}

	key_changed |= updateDnskey(key_list, key, now, next_update_for_record);
	minTime(next_update_for_record, next_update_for_key);

	if (key.role() & KSK) { /* ZSK and CSK */
		//~ key_changed |= updateRrsig(key_list, key, now, &next_update_for_record);
		minTime(next_update_for_record, next_update_for_key);
	}
	return key_changed;
}

/* TODO descr. */
time_t updateZone(EnforcerZone &zone, const time_t now) {
	time_t return_at = -1;
	time_t next_update_for_key;
	KeyData *key;
	KeyDataList &key_list = zone.keyDataList();

	/* Keep looping till there are no state changes.
	 * Find the soonest update time */
	bool a_key_changed = true;
	while (a_key_changed) {
		a_key_changed = false;
		/* Loop over all keys */
		for (int i = 0; i < key_list.numKeys(); i++) {
			key = &key_list.key(i);
			a_key_changed |= updateKey(key_list, *key, now, next_update_for_key);
			minTime(next_update_for_key, return_at);
		}
	}
	return return_at;
}

/* Abstraction to generalize different kind of keys. */
int numberOfKeys(const ::ods::kasp::Keys *policyKeys, const KeyRole role) {
	switch (role) {
		case KSK:
			return policyKeys->ksk_size();
		case ZSK:
			return policyKeys->zsk_size();
		case CSK:
			return policyKeys->csk_size();
		default:
			assert(0); /* report a bug! */
	}
}

/* Abstraction to generalize different kind of keys. */
void keyProperties(const ::ods::kasp::Keys *policyKeys, const KeyRole role,
		const int index, int *bits, int *algorithm, int *lifetime) {
	switch (role) {
		case KSK:
			assert(index < policyKeys->ksk_size());
			*bits	   = policyKeys->ksk(index).bits();
			*algorithm = policyKeys->ksk(index).algorithm();
			*lifetime  = policyKeys->ksk(index).lifetime();
			return;
		case ZSK:
			assert(index < policyKeys->zsk_size());
			*bits	   = policyKeys->zsk(index).bits();
			*algorithm = policyKeys->zsk(index).algorithm();
			*lifetime  = policyKeys->zsk(index).lifetime();
			return;
		case CSK:
			assert(index < policyKeys->csk_size());
			*bits	   = policyKeys->csk(index).bits();
			*algorithm = policyKeys->csk(index).algorithm();
			*lifetime  = policyKeys->csk(index).lifetime();
			return;
		default:
			assert(0); /* report a bug! */
	}
}

/* See what needs to be done for the policy*/
time_t updatePolicy(EnforcerZone &zone, const time_t now, HsmKeyFactory &keyfactory) {
	time_t return_at = -1;
	const ::ods::kasp::Policy *policy = zone.policy();

	/* first look at policy */
	::ods::kasp::Keys policyKeys = policy->keys();
	const std::string policyName = policy->name();

	int bits, algorithm, lifetime;
	time_t last_insert, next_insert;
	/* Visit every type of key-configuration, not pretty but we can't
	 * loop over enums. Include MAX in enum? */
	for ( int role = 1; role < 4; role++ ) {
		for ( int i = 0; i < numberOfKeys( &policyKeys, (KeyRole)role ); i++ ) {
			keyProperties(&policyKeys, (KeyRole)role, i, &bits, &algorithm, &lifetime);
			last_insert = 0; /* search all keys for this zone */
			next_insert = last_insert + lifetime;
			if ( now < next_insert and last_insert != -1 ) {
				/* No need to change key, come back at */
				minTime( next_insert, return_at );
				continue;
			}
			/* time for a new key */
			string locator;
			HsmKey *hsm_key;
			bool got_key;

			if ( policyKeys.zones_share_keys() )
				got_key = getLastReusableKey( 
					zone, policy, (KeyRole)role, bits, algorithm, now, 
					&hsm_key, keyfactory, lifetime)
				? 
					true
				: 
					keyfactory.CreateSharedKey(bits, policyName,
					algorithm, (KeyRole)role, zone.name(),&hsm_key );
			else
				got_key = keyfactory.CreateNewKey( bits, &hsm_key );
			if ( not got_key ) {
				/* The factory was not ready, return in 60s */
				minTime( NOKEY_TIMEOUT, return_at);
				continue;
			}
	
			KeyData &new_key = zone.keyDataList().addNewKey( algorithm, now,
				(KeyRole)role, false, false, false);
			new_key.setLocator( hsm_key->locator() );
			/* fill next_key */
			new_key.setDSSeen( false );
			new_key.setSubmitToParent( false );
			new_key.keyStateDS().setState(HID);
			new_key.keyStateDNSKEY().setState(HID);
			new_key.keyStateRRSIG().setState(HID);

			/* New key inserted, come back after its lifetime */
			minTime( now + lifetime, return_at );
		}
	} /* loop over KeyRole */
	return return_at;
}

/* Removes all keys from list that are no longer used. */
inline void removeDeadKeys(KeyDataList &key_list) {
	for (int i = key_list.numKeys()-1; i >= 0; i--) {
		KeyData &key = key_list.key(i);
		if (	key.keyStateDS().state() == HID and
				key.keyStateDNSKEY().state() == HID and
				key.keyStateRRSIG().state() == HID and
				not key.introducing())
			key_list.delKey(i);
	}
}

/* see header file */
time_t update(EnforcerZone &zone, const time_t now, HsmKeyFactory &keyfactory) {
	time_t policy_return_time, zone_return_time;
	KeyDataList &key_list = zone.keyDataList();

	policy_return_time = updatePolicy(zone, now, keyfactory);
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
			key->keyStateDNSKEY().state() == OMN or
			key->keyStateDNSKEY().state() == RUM or
			key->keyStateDNSKEY().state() == COM);
		key->setActive(
			key->keyStateRRSIG().state() == OMN or
			key->keyStateRRSIG().state() == RUM or
			key->keyStateRRSIG().state() == COM);
	}

	minTime(policy_return_time, zone_return_time);
	return zone_return_time;
}

#if 0
//~ #if 1
// TEST MAIN

/* This function is merely for testing purposes and should be removed.
 * call update() instead! */
int main() {
	/* data passed from upper layer */
	EnforcerZone *enfZone = NULL;
	HsmKeyFactory *keyfactory = NULL;

	/* small simulation */
	time_t t_now = time(NULL);
	for (int i = 0; i<10; i++) {
		cout << "Advancing time to " << ctime(&t_now);
		t_now = update(*enfZone, t_now, *keyfactory);
		if (t_now == -1) {
			/* This zone does not need an update. Ever. Unlikely
			 * this will ever happen, but it is possible with a silly
			 * policy. User action (policy change) can change this. */
			break;
		}
		cout << endl << "Next update scheduled at " << ctime(&t_now) << endl;
	}
	return 0;
}

#endif
