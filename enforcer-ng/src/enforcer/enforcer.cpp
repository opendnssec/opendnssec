#include <ctime>
#include <iostream>
#include <cassert>

#include "enforcer/enforcerdata.h"
#include "policy/kasp.pb.h"
#include "enforcer/enforcer.h"

// Interface of this cpp file is used by C code, we need to declare
// extern "C" to prevent linking errors.
extern "C" {
	/* YBS: I don't have this file yet */
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
 * must match and it must be a first generation key. */
bool getLastReusableKey( EnforcerZone &zone,
		const kasp::pb::Policy *policy, const KeyRole role,
		int bits, int algorithm, const time_t now, KeyData **ppKey,
		HsmKeyFactory &keyfactory, int lifetime) {
	//~ if (not keyfactory.FindSharedKeys(policy->name(), algorithm, bits,
			//~ role, zone.name(), ppKey))
	HsmKey **dummy = NULL;
	if (not keyfactory.FindSharedKeys(policy->name(), algorithm, bits,
			role, zone.name(), dummy))
		return false;
	assert(*ppKey != NULL); /* FindSharedKeys() promised us. */
	/* Key must (still) be in use */
	return (*ppKey)->introducing() and not (*ppKey)->revoke() and
		not (*ppKey)->standby() and now < (*ppKey)->inception() + lifetime;
}

void setState( KeyState &record_state, const RecordState new_state, const time_t now ) {
	record_state.setState(new_state);
	record_state.setLastChange(now);
}

bool reliableDs(KeyDataList &key_list, KeyData &key) {
	if (key.keyStateDS().state() == OMN) return true;
	if (key.keyStateDS().state() != COM) return false;
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if  (k.keyStateDS().state() == PCM and
				k.algorithm() == key.algorithm())
			return true;
	}
	return false;
}

bool reliableDnskey(KeyDataList &key_list, KeyData &key) {
	if (key.keyStateDNSKEY().state() == OMN) return true;
	if (key.keyStateDNSKEY().state() != COM) return false;
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if  (k.keyStateDNSKEY().state() == PCM and
				k.algorithm() == key.algorithm())
			return true;
	}
	return false;
}

bool reliableRrsig(KeyDataList &key_list, KeyData &key) {
	if (key.keyStateRRSIG().state() == OMN) return true;
	if (key.keyStateRRSIG().state() != COM) return false;
	for (int i = 0; i < key_list.numKeys(); i++) {
		KeyData &k = key_list.key(i);
		if  (k.keyStateRRSIG().state() == PCM and
				k.algorithm() == key.algorithm())
			return true;
	}
	return false;
}

//~ bool updateDs(KeyDataList *key_list, KeyData *key, const time_t now, time_t *next_update_for_record) {
	//~ bool record_changed = false;
	//~ bool signer_needs_update = false;
	//~ *next_update_for_record = -1;
	//~ int num_keys = key_list->numKeys();
	//~ KeyData *k;
	//~ time_t Tprop;
//~
	//~ KeyState *record_state = &key->keyStateDS();
	//~ switch ( record_state->state() ) {
//~
	//~ case HID:cc
	//~ if (key->introducing() and not key->standby()) {
		//~ if (not key->minimizeDS()) {
			//~ for (int i = 0; i < num_keys; i++) {
				//~ k = &key_list->key(i);
				//~ if (k->algorithm() == key->algorithm() and
						//~ reliableDs(k) and
						//~ reliableDnskey(k)) {
					//~ setState(record_state, RUM, now);
					//~ record_changed = true;
					//~ /* The DS record must be submit to the parent */
					//~ key->setSubmitToParent(true);
					//~ key->setDSSeen(false);
					//~ /* The signer configuration does not change */
					//~ break;
				//~ }
			//~ }
		//~ } else if (key->keyStateDNSKEY() == OMN) {
			//~ setState(record_state, COM, now);
			//~ record_changed = true;
			//~ /* The DS record must be submit to the parent */
			//~ key->setSubmitToParent(true);
			//~ key->setDSSeen(false);
			//~ /* The signer configuration does not change */
		//~ }
	//~ }
	//~ break;
//~
	//~ case RUM:
	//~ if (not key->introducing()) {
		//~ setState(record_state, UNR, now);
		//~ state_change = true;
		//~ /* The DS record withdrawal must be submit to the parent */
		//~ key->setSubmitToParent(true);
		//~ key->setDSSeen(false);
		//~ /* The signer configuration does not change */
	//~ } else if (key->isDSSeen()) {
		//~ Tprop = 0; /* some propagation time. TODO */
		//~ if (now >= Tprop) {
			//~ setState(record_state, OMN, now);
			//~ record_changed = true;
			//~ /* There is no next update scheduled for this record
			 //~ * since it is now omnipresent and introducing */
		//~ } else {
			//~ /* All requirements are met but not the propagation time
			 //~ * ask to come back at a later date. */
			//~ *next_update_for_record = Tprop;
		//~ }
	//~ }
	//~ break;
//~
	//~ case COM:
	//~ if (key->isDSSeen()) {
		//~ Tprop = 0; /* some propagation time. TODO */
		//~ if (now >= Tprop) {
			//~ setState(record_state, OMN, now);
			//~ record_changed = true;
			//~ /* There is no next update scheduled for this record
			 //~ * since it is now omnipresent and introducing */
		//~ } else {
			//~ /* All requirements are met but not the propagation time
			 //~ * ask to come back at a later date. */
			//~ *next_update_for_record = Tprop;
		//~ }
	//~ }
	//~ break;
//~
	//~ case OMN:
	//~ if (key->introducing()) break; /* already there */
//~
	//~ if (key->keyStateDNSKEY() == OMN) {
		//~ bool exists_ds_comitted = false;
		//~ for (int i = 0; i < num_keys; i++) {
			//~ k = &key_list->key(i);
			//~ if (k->keyStateDS() == COM) {
				//~ exists_ds_comitted = true;
				//~ break;
			//~ }
		//~ }
		//~ if (exists_ds_comitted) {
			//~ setState(record_state, PCM, now);
			//~ record_changed = true;
			//~ /* The DS record withdrawal must be submit to the parent */
			//~ key->setSubmitToParent(true);
			//~ key->setDSSeen(false);
			//~ /* The signer configuration does not change */
			//~ break; /* from switch */
		//~ }
	//~ }
//~
	//~ if (key->keyStateDNSKEY() == PCM) break;
//~
	//~ bool exists_ds_postcomitted = false;
	//~ for (int i = 0; i < num_keys; i++) {
		//~ k = &key_list->key(i);
		//~ if (k->keyStateDS() == PCM) {
			//~ exists_ds_postcomitted = true;
			//~ break;
		//~ }
	//~ }
	//~ bool forall = true;
	//~ bool ds_omni_or_com = false;
	//~ for (int i = 0; i < num_keys; i++) {
		//~ k = &key_list->key(i);
		//~ ds_omni_or_com |= k!=key and (k->keyStateDS() == OMN or
				//~ (k->keyStateDS() == COM and exists_ds_postcomitted));
		//~ if (k->algorithm != key->algorithm ) continue;
		//~ if (k->keyStateDS() == HID) continue;
		//~ if (reliableDnskey(k)) continue;
//~
		//~ /* Leave innerloop as last check,
		 //~ * for performance. */
		//~ bool hasReplacement = false;
		//~ KeyData *l;
		//~ for (int j = 0; j < num_keys; j++) {
			//~ l = &key_list->key(j);
			//~ if (l->algorithm == k->algorithm and l != key
					//~ and reliableDs(l) and reliableDnskey(l)) {
				//~ hasReplacement = true;
				//~ break;
			//~ }
		//~ }
		//~ if (not hasReplacement) {
			//~ forall = false;
			//~ break;
		//~ }
	//~ }
//~
	//~ if (ds_omni_or_com and forall) {
		//~ setState(record_state, UNR, now);
		//~ record_changed = true;
		//~ /* The DS record withdrawal must be submit to the parent */
		//~ key->setSubmitToParent(true);
		//~ key->setDSSeen(false);
		//~ /* The signer configuration does not change */
	//~ }
	//~ break;
//~
	//~ case UNR:
	//~ /* We might *not* allow this, for simplicity */
	//~ if (key->introducing()) {
		//~ setState(record_state, RUM, now);
		//~ record_changed = true;
		//~ /* The DS record withdrawal must be submit to the parent */
		//~ key->setSubmitToParent(true);
		//~ key->setDSSeen(false);
		//~ /* The signer configuration does not change */
		//~ break;
	//~ }
	//~ Tprop = 0 /* TODO */;
	//~ if (now >= Tprop) {
		//~ setState(record_state, HID, now);
		//~ record_changed = true;
	//~ } else {
		//~ *next_update_for_record = Tprop;
	//~ }
	//~ break;
//~
	//~ case PCM:
	//~ Tprop = 0 /* TODO */;
	//~ if (now >= Tprop) {
		//~ setState(record_state, HID, now);
		//~ record_changed = true;
		//~ /* no need to notify signer. Nothing changes in
		 //~ * its perspective. */
	//~ } else {
		//~ *next_update_for_record = Tprop;
	//~ }
	//~ break;
//~
	//~ case REV:
	//~ /* NOT IMPL */
	//~ break;
//~
	//~ default:
	//~ assert(0); /* Nonexistent state. */
	//~ }
//~
	//~ /* check here for consistency. Signer never needs to know about
	 //~ * DS changes. */
	//~ if (signer_needs_update) {
		//zone->
	//~ }
	//~ return record_changed;
//~ }
//~
//~ bool updateDnskey(KeyDataList *key_list, KeyData *key, const time_t now, time_t *next_update_for_record) {
	//~ bool record_changed = false;
	//~ bool signer_needs_update = false;
	//~ *next_update_for_record = -1;
	//~ int num_keys = key_list->numKeys();
	//~ KeyData *k;
	//~ time_t Tprop;
//~
	//~ KeyState *record_state = &key->keyStateDNSKEY();
	//~ switch ( record_state->state() ) {
//~
	//~ case HID:
	//~ if (not key->introducing()) break;
	//~ if (key->minimizeDNSKEY() and (key->keyStateDS() == OMN or
			//~ not key->keyRoles() & KSK) and
			//~ (key->keyStateRRSIG == OMN or not key->keyRoles() & ZSK) ) {
//~
		//~ setState(record_state, COM, now);
		//~ record_changed = true;
		//~ /* The DNSKEY now needs to be published. */
		//~ signer_needs_update = true;
		//~ break;
	//~ }
	//~ if (key->minimizeDNSKEY() and not key->standby()) {
		//~ bool noneExist = true;
		//~ for (int i = 0; i < num_keys; i++) {
			//~ k = &key_list->key(i);
			//~ if (not (key->algorithm() == k->algorithm() and
					//~ reliableDnskey(k) and key->keyRoles() & KSK)){
				//~ noneExist = false;
				//~ break;
			//~ }
		//~ }
		//~ if (not noneExist) break;
	//~ }
	//~ if (not reliableDnskey(key)) {
		//~ bool oneExist = false;
		//~ for (int i = 0; i < num_keys; i++) {
			//~ k = &key_list->key(i);
			//~ if (not (key->algorithm() == k->algorithm() and
					//~ reliableDnskey(k) and reliableRrsig(k))){
				//~ oneExist = true;
				//~ break;
			//~ }
		//~ }
		//~ if (not oneExist) break;
	//~ }
	//~ setState(record_state, RUM, now);
	//~ record_changed = true;
	//~ /* The DNSKEY now needs to be published. */
	//~ signer_needs_update = true;
	//~ break;
//~
	//~ case RUM:
	//~ if (not key->introducing()) {
		//~ setState(record_state, UNR, now);
		//~ state_change = true;
		//~ signer_needs_update = true;
		//~ break;
	//~ }
	//~ Tprop = 0; /* TODO */
	//~ if (now >= Tprop) {
		//~ setState(record_state, OMN, now);
		//~ state_change = true;
		//~ break;
	//~ }
	//~ *next_update_for_record = Tprop;
	//~ break;
//~
	//~ case COM:
	//~ Tprop = 0; /* TODO */
	//~ if (now >= Tprop) {
		//~ setState(record_state, OMN, now);
		//~ state_change = true;
		//~ break;
	//~ }
	//~ *next_update_for_record = Tprop;
	//~ break;
//~
	//~ case OMN:
	//~ if (key->introducing() or key->keyStateDS() == PCM or
			//~ key->keyStateRRSIG() == PCM )
		//~ break;
	//~ /* Yuri was 'ere */
	//~ if ( key->keyStateDS() == OMN and key->keyStateRRSIG() == OMN and
			//~ not key->revoke()) {
		//~ bool hasReplacement = false;
		//~ for (int i = 0; i < num_keys; i++) {
			//~ k = &key_list->key(i);
			//~ if ( k->keyStateDNSKEY() == COM and
				//~ key->algorithm() == k->algorithm() and
				//~ key->keyRole() == k->keyRole() ) {
			//~ hasReplacement = true;
			//~ break;
			//~ }
		//~ }
		//~ if ( hasReplacement ) {
			//~ /* withdraw stuff */
			//~ key->keyStateDNSKEY( PCM );
			//~ state_change = true;
			//~ break;
		//~ }
	//~ }
//~
	//~ if ( not key->keyStateDS() == Key::ST_POSTCOMITTED and
			//~ not key->keyStateRRSIG() == Key::ST_POSTCOMITTED ) {
		//~ bool all = true;
		//~ for (Key *k = keylist; k != NULL; k = k->next) {
			//~ bool check1 = not k->roles&Key::KSK or
				//~ k->ds_state == Key::ST_HIDDEN or
				//~ ( k != key and reliableDnskey(k));
			//~ if ( not check1 ) {
				//~ /*exists loop*/
				//~ bool exist1 = false;
				//~ for (Key *l = keylist; l != NULL; l = l->next) {
					//~ if ( k != l and k->algorithm == l->algorithm and
							//~ reliableDs(l) and reliableDnskey(l) ) {
						//~ exist1 = true;
						//~ break;
					//~ }
				//~ }
				//~ if ( not exist1 ) break;
			//~ }
			//~ bool check2 = k->dnskey_state == Key::ST_HIDDEN or
				//~ reliableRrsig(k);
			//~ if ( not check2 ) {
				//~ /*exists loop*/
				//~ bool exist2 = false;
				//~ for (Key *l = keylist; l != NULL; l = l->next) {
					//~ if ( k != l and k->algorithm == l->algorithm and
							//~ reliableRrsig(l) and reliableDnskey(l) ) {
						//~ exist2 = true;
						//~ break;
					//~ }
				//~ }
				//~ if ( not exist2 ) break;
			//~ }
//~
//~
		//~ }
		//~ if ( not all ) break;
		//~ key->dnskey_state = key->revoked?Key::ST_REVOKED
										//~ :Key::ST_UNRETENTIVE;
		//~ state_change = true;
		//~ /* submit or revoke stuff */
		//~ break;
	//~ }
	//~ break;
//~
	//~ case Key::ST_REVOKED:
	//~ if (now >= /* some time */ 0) {
		//~ key->dnskey_state = Key::ST_UNRETENTIVE;
		//~ state_change = true;
	//~ }
	//~ break;
//~
	//~ case Key::ST_UNRETENTIVE:
	//~ if (key->goal == Key::ST_OMNIPRESENT) {
		//~ /* submit,
		 //~ * key->dnskey_state = Key::ST_UNRETENTIVE;
		 //~ * state_change = true;
		 //~ * */
	//~ }
	//~ else if (now >= /* some time */ 0) {
		//~ key->dnskey_state = Key::ST_HIDDEN;
		//~ state_change = true;
	//~ }
	//~ break;
//~
	//~ case Key::ST_POSTCOMITTED:
	//~ break;
//~
	//~ }
//~
	//~ return record_changed;
//~ }
//~ bool updateRrsig(KeyDataList *key_list, KeyData *key, const time_t now, time_t *next_update_for_record) {
	//~ bool record_changed = false;
	//*next_update_for_record = -1;
	//time_t T_confirm = 0; /* some propagation time. TODO */
	//~ return record_changed;
//~ }

/* updateKey
 * Updates all relevant (with respect to role) records of a key.
 *
 * @return: true on any changes within this key */
bool updateKey(KeyDataList &key_list, KeyData &key, const time_t now, time_t &next_update_for_key) {
	time_t next_update_for_record = -1;
	next_update_for_key = -1;
	bool key_changed = false;

	if (key.role() & KSK) { /* KSK and CSK */
		//~ key_changed |= updateDs(key_list, key, now, &next_update_for_record);
		minTime(next_update_for_record, next_update_for_key);
	}

	//~ key_changed |= updateDnskey(key_list, key, now, &next_update_for_record);
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
int numberOfKeys(const kasp::pb::Keys *policyKeys, const KeyRole role) {
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
void keyProperties(const kasp::pb::Keys *policyKeys, const KeyRole role,
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
	const kasp::pb::Policy *policy = zone.policy();

	/* first look at policy */
	kasp::pb::Keys policyKeys = policy->keys();
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
			KeyData *next_key = NULL;
			bool shareable = true;
			if ( policyKeys.zones_share_keys() )
				getLastReusableKey(zone, policy, (KeyRole)role, bits,
						algorithm, now, &next_key, keyfactory, lifetime);
			if ( policyKeys.zones_share_keys() and next_key != NULL ) {
				/* Another usable key exists, copy location */
				locator = next_key->locator();
			} else {
				/* We don't have a usable key, ask for a new one */
				HsmKey *hsm_key;
				bool got_key;
				if ( policyKeys.zones_share_keys() ) {
					got_key = keyfactory.CreateSharedKey(
							policyName, algorithm,
							bits, (KeyRole)role, &hsm_key );
				} else {
					got_key = keyfactory.CreateNewKey(
							bits, &hsm_key );
					shareable = false;
				}
				if ( not got_key ) {
					/* The factory was not ready, return in 60s */
					minTime( NOKEY_TIMEOUT, return_at);
					continue;
				}
				/* Append a new hsmkey to the keyring */
				locator = hsm_key->locator();
			}
			KeyData &new_key = zone.keyDataList().addNewKey( algorithm, now,
				(KeyRole)role, false, false, false /*, shareable */);
			new_key.setLocator( locator );
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
		/* TODO */
		//~ key->setPublish(
				//~ key->keyStateDNSKEY() == OMN or
				//~ key->keyStateDNSKEY() == RUM or
				//~ key->keyStateDNSKEY() == COM);
		//~ key->setActive(
				//~ key->keyStateRRSIG() == OMN or
				//~ key->keyStateRRSIG() == RUM or
				//~ key->keyStateRRSIG() == COM);
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
