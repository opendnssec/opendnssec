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

/* Move this to enforcerdata at later time 
 * Hidden, rumoured, comitted, omnipresent, unretentive, postcomitted
 * revoked 
 * */
enum RecordState { HID, RUM, COM, OMN, UNR, PCM, REV };

using namespace std;

inline void minTime(const time_t t, time_t *min) {
    if (t < *min || *min == -1) *min = t;
}

/* Search for youngest key in use by any zone with this policy
 * with at least the roles requested. See if it isn't expired.
 * also, check if it isn't in zone already. Also length, algorithm
 * must match */
KeyData *getLastReusableKey( const EnforcerZone *zone, 
                            const kasp::pb::Policy *policy,
                            const KeyRole roles, const time_t now) {
    return NULL;
}

bool updateDs(KeyData *key, const time_t now, time_t *next_update_for_record) {
    bool record_changed = false;
    //~ *next_update = -1;
    //~ time_t T_confirm = 0; /* some propagation time. TODO */
    
    //~ KeyState key_state = key->keyStateDS();
    //~ switch ( key_state.state() ) {
	//~ 
    //~ }
    
    return record_changed;
}
bool updateDnskey(KeyData *key, const time_t now, time_t *next_update_for_record) {
    bool record_changed = false;
    //~ *next_update = -1;
    //~ time_t T_confirm = 0; /* some propagation time. TODO */
    return record_changed;
}
bool updateRrsig(KeyData *key, const time_t now, time_t *next_update_for_record) {
    bool record_changed = false;
    //~ *next_update = -1;
    //~ time_t T_confirm = 0; /* some propagation time. TODO */
    return record_changed;
}

/* updateKey
 * Updates all relevant (with respect to role) records of a key.
 * 
 * @return: true on any changes within this key */
bool updateKey(KeyData *key, const time_t now, time_t *next_update_for_key) {
    time_t next_update_for_record;
    *next_update_for_key = -1;
    bool key_changed = false;
    
    if (key->role() & KSK) { /* KSK and CSK */
        key_changed |= updateDs(key, now, &next_update_for_record);
        minTime(next_update_for_record, next_update_for_key);
    }
    
    key_changed |= updateDnskey(key, now, &next_update_for_record);
    minTime(next_update_for_record, next_update_for_key);
    
    if (key->role() & KSK) { /* ZSK and CSK */
        key_changed |= updateRrsig(key, now, &next_update_for_record);
        minTime(next_update_for_record, next_update_for_key);
    }
    return key_changed;
}

time_t updateZone(EnforcerZone *zone, const time_t now) {
    time_t return_at = -1;
    time_t next_update_for_key;
    KeyData *key;
    
    /* Keep looping till there are no state changes. 
     * Find the soonest update time*/
    bool a_key_changed = true;
    while (a_key_changed) {
        a_key_changed = false;
        /* Loop over all keys */
        for (int i = 0; i < zone->keyDataList().numKeys(); i++) {
            key = &zone->keyDataList().key(i);
            a_key_changed |= updateKey(key, now, &next_update_for_key);
            minTime(next_update_for_key, &return_at);
        }
    }
    return return_at;
}

int numberOfKeys(const kasp::pb::Keys *policyKeys, const KeyRole role) {
    switch (role) {
        case KSK: 
            return policyKeys->ksk_size();
        case ZSK:
            return policyKeys->zsk_size();
        case CSK:
            return policyKeys->csk_size();
    }
    assert(0); /* report a bug! */
    //~ return -1;
}

void keyProperties(const kasp::pb::Keys *policyKeys, const KeyRole role, 
                   const int index, int *bits, int *algorithm, int *lifetime) {
    switch (role) {
        case KSK:
            assert(index < policyKeys->ksk_size());
            *bits      = policyKeys->ksk(index).bits();
            *algorithm = policyKeys->ksk(index).algorithm();
            *lifetime  = policyKeys->ksk(index).lifetime();
            break;
        case ZSK:
            assert(index < policyKeys->zsk_size());
            *bits      = policyKeys->zsk(index).bits();
            *algorithm = policyKeys->zsk(index).algorithm();
            *lifetime  = policyKeys->zsk(index).lifetime();
            break;
        case CSK:
            assert(index < policyKeys->csk_size());
            *bits      = policyKeys->csk(index).bits();
            *algorithm = policyKeys->csk(index).algorithm();
            *lifetime  = policyKeys->csk(index).lifetime();
            break;
    }
}

/* See what needs to be done for the policy*/
time_t updatePolicy(EnforcerZone *zone, const time_t now, HsmKeyFactory *keyfactory) {
    time_t return_at = -1;
    const kasp::pb::Policy *policy = zone->policy();
    
    /* first look at policy */
    kasp::pb::Keys policyKeys = policy->keys();
    const std::string policyName = policy->name();
    
    int bits, algorithm, lifetime;
    time_t last_insert, next_insert;
    KeyData *next_key, *new_key;
    /* Visit every type of key-configuration, not pretty but we can't 
     * loop over enums. Include MAX in enum? */
    for (int role = 1; role < 4; role++) {
        for ( int i = 0; i < numberOfKeys( &policyKeys, (KeyRole)role ); i++ ) {
            keyProperties(&policyKeys, (KeyRole)role, i, &bits, &algorithm, &lifetime);
            last_insert = 0; /* search all keys for this zone */
            next_insert = last_insert + lifetime;
            if (now < next_insert and last_insert != -1) {
                /* No need to change key come back at */
                minTime( next_insert, &return_at );
                continue;
            }
            /* time for a new key */
            next_key = policyKeys.zones_share_keys()? 
            getLastReusableKey(zone, policy, (KeyRole)role, now) : NULL;
            if ( next_key == NULL ) {
                /* We don't have a usable key, ask for a new one */
                HsmKey *hsm_key;
                bool got_key_from_pool;
                if ( policyKeys.zones_share_keys() )
                    got_key_from_pool = keyfactory->CreateSharedKey(
                                                                    policyName, algorithm, 
                                                                    bits, (KeyRole)role, &hsm_key );
                else
                    got_key_from_pool = keyfactory->CreateNewKey( 
                                                                 bits, &hsm_key );
                if ( not got_key_from_pool ) {
                    /* The factory was not ready, return in 60s */
                    minTime( 60, &return_at);
                    continue;
                }
                /* Append a new key to the keyring */
                new_key = &zone->keyDataList().addNewKey(algorithm,now,
                                                         (KeyRole)role,
                                                         false,false,false);
                new_key->setLocator(hsm_key->locator());
            }
            else {
                /* Another usable key exists, copy location */
                new_key = &zone->keyDataList().addNewKey(algorithm,now,
                                                         (KeyRole)role,
                                                         false,false,false);
                new_key->setLocator(next_key->locator());
            }
            /* fill next_key */
//          new_key->setAlgorithm( algorithm );
//          new_key->setInception( now );
//          new_key->setKeyRole( (KeyRole)role );
//          new_key->setDSSeen( false );
            new_key->setSubmitToParent( false );
            new_key->keyStateDS().setState(0);     /* TODO HIDDEN */
            new_key->keyStateDNSKEY().setState(0); /* TODO HIDDEN */
            new_key->keyStateRRSIG().setState(0);  /* TODO HIDDEN */
            
            /* New key inserted, come back after its lifetime */
            minTime( now + lifetime, &return_at );
        }
    } // loop over KeyRole
    return return_at;
}

/* see header file */
time_t update(EnforcerZone *zone, const time_t now, HsmKeyFactory *keyfactory) {
    time_t policy_return_time, zone_return_time;
    
    policy_return_time = updatePolicy(zone, now, keyfactory);
    zone_return_time = updateZone(zone, now);
    
    //~ removeDeadKeys();
    
    minTime(policy_return_time, &zone_return_time);
    return zone_return_time;
}

#if 0
// TEST MAIN

#include "enforcer/enforcerdatadummy.h"

/* This function is merely for testing purposes and should be removed. 
 * call update() instead! */
int main() {
    /* data passed from upper layer */
    EnforcerZoneDummy enfZone("example.com");
    HsmKeyFactoryDummy keyfactory;
    
    /* small simulation */
    time_t t_now = time(NULL);
    for (int i = 0; i<10; i++) {
        cout << "Advancing time to " << ctime(&t_now);
        t_now = update(&enfZone, t_now, &keyfactory);
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
