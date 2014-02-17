/*
 * $Id$
 *
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
 * All rights reserved.
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

#include "enforcer/enforcerzone.h"

#include "shared/log.h"

static const char * const module_str = "enforcezone";

//////////////////////////////
// KeyStatePB
//////////////////////////////

KeyStatePB::KeyStatePB(::ods::keystate::KeyState *keystate)
: _keystate(keystate)
{
    
}

int KeyStatePB::state()
{
    return _keystate->state();
}

void KeyStatePB::setState(int value)
{
    if (::ods::keystate::rrstate_IsValid(value))
        _keystate->set_state( (::ods::keystate::rrstate)value );
    else {
        ods_log_error("[%s] %d is not a valid rrstate value",
                      module_str,value);
    }
}

int KeyStatePB::lastChange()
{
    return _keystate->last_change();
}

void KeyStatePB::setLastChange(int value)
{
    _keystate->set_last_change( value );
}

int KeyStatePB::ttl()
{
    return _keystate->ttl();
}

void KeyStatePB::setTtl(int value)
{
    _keystate->set_ttl( value );
}

bool KeyStatePB::minimize()
{
    return _keystate->minimize();
}

void KeyStatePB::setMinimize(bool value)
{
    _keystate->set_minimize(value);
}

//////////////////////////////
// KeyDataPB
//////////////////////////////

KeyDataPB::KeyDataPB( ::ods::keystate::KeyData *keydata )
:   _keydata(keydata),
    _keyStateDS( _keydata->mutable_ds() ),
    _keyStateRRSIG( _keydata->mutable_rrsig() ),
    _keyStateDNSKEY( _keydata->mutable_dnskey() ),
    _keyStateRRSIGDNSKEY( _keydata->mutable_rrsigdnskey() )
{
}

bool KeyDataPB::matches( const ::ods::keystate::KeyData *keydata )
{
    return _keydata == keydata;
}

const std::string &KeyDataPB::locator()
{
    return _keydata->locator();
}

void KeyDataPB::setLocator(const std::string &value)
{
    _keydata->set_locator( value );
}

int KeyDataPB::algorithm()
{
    return _keydata->algorithm();
}

void KeyDataPB::setAlgorithm(int value)
{
    _keydata->set_algorithm( value );
}

time_t KeyDataPB::inception()
{
    return _keydata->inception();
}

void KeyDataPB::setInception(time_t value)
{
    _keydata->set_inception( value );
}

KeyState &KeyDataPB::keyStateDS()
{
    return _keyStateDS;
}

KeyState &KeyDataPB::keyStateRRSIG()
{
    return _keyStateRRSIG;
}

KeyState &KeyDataPB::keyStateDNSKEY()
{
    return _keyStateDNSKEY;
}

KeyState &KeyDataPB::keyStateRRSIGDNSKEY()
{
    return _keyStateRRSIGDNSKEY;
}

KeyRole KeyDataPB::role()
{
    return (KeyRole)_keydata->role();
}

void KeyDataPB::setRole(KeyRole value)
{
    if (::ods::keystate::keyrole_IsValid(value))
        _keydata->set_role( (::ods::keystate::keyrole)value );
    else {
        ods_log_error("[%s] %d is not a valid keyrole value",
                      module_str,value);
    }
}

bool KeyDataPB::introducing()
{
    return _keydata->introducing();
}

void KeyDataPB::setIntroducing(bool value)
{
    _keydata->set_introducing(value);
}

bool KeyDataPB::revoke()
{
    return _keydata->revoke();
}

bool KeyDataPB::standby()
{
    return _keydata->standby();
}

void KeyDataPB::setPublish(bool value)
{
    _keydata->set_publish(value);
}

void KeyDataPB::setActiveZSK(bool value)
{
    _keydata->set_active_zsk(value);
}

void KeyDataPB::setActiveKSK(bool value)
{
    _keydata->set_active_ksk(value);
}

DsAtParent KeyDataPB::dsAtParent()
{
    return (DsAtParent)_keydata->ds_at_parent();
}

void KeyDataPB::setDsAtParent(DsAtParent value)
{
    if (::ods::keystate::dsatparent_IsValid(value))
        _keydata->set_ds_at_parent( (::ods::keystate::dsatparent)value );
    else {
        ods_log_error("[%s] %d is not a valid dsatparent value",
                      module_str,value);
    }
}

uint16_t KeyDataPB::keytag()
{
    return (uint16_t)_keydata->keytag();
}

void KeyDataPB::setKeytag(uint16_t value)
{
	_keydata->set_keytag( (uint32_t)value );
}

KeyDependencyPB::KeyDependencyPB( ::ods::keystate::KeyDependency *keydependency)
:   _keydependency(keydependency)
{
}

void KeyDependencyPB::setToKey(KeyData *key)
{
	_keydependency->set_to_key(key->locator());
}

void KeyDependencyPB::setFromKey(KeyData *key)
{
	_keydependency->set_from_key(key->locator());
}

void KeyDependencyPB::setRRType(RECORD record)
{
	_keydependency->set_rrtype(record);
}

const std::string &KeyDependencyPB::toKey()
{
	return _keydependency->to_key();
}
const std::string &KeyDependencyPB::fromKey()
{
	return _keydependency->from_key();
}
RECORD KeyDependencyPB::rrType()
{
	return (RECORD)_keydependency->rrtype();
}

KeyDependencyListPB::KeyDependencyListPB(::ods::keystate::EnforcerZone *zone)
: _zone(zone)
{
	//fill _deps
    for (int k=0; k<_zone->dependencies_size(); ++k) {
        ::ods::keystate::KeyDependency *keydep = _zone->mutable_dependencies(k);
        KeyDependencyPB dep( keydep );
        _deps.push_back(dep);
    }
}

int KeyDependencyListPB::numDeps()
{
	return _deps.size();
}
KeyDependency &KeyDependencyListPB::dep(int index)
{
	return _deps[index];
}

KeyDependency &KeyDependencyListPB::addNewDependency(
		KeyData *from_key, 
		KeyData *to_key, RECORD record)
{
	KeyDependencyPB dep( _zone->add_dependencies());
	dep.setFromKey(from_key);
	dep.setToKey(to_key);
	dep.setRRType(record);
	_deps.push_back(dep);
	return _deps.back();
}

void KeyDependencyListPB::delDependency( KeyData *key, RECORD record)
{
	for (int k=0; k<_zone->dependencies_size(); ++k) {
		if (_zone->mutable_dependencies(k)->rrtype() == record &&
				(_zone->mutable_dependencies(k)->to_key().compare(key->locator())||
				_zone->mutable_dependencies(k)->from_key().compare(key->locator())))
		{
			::google::protobuf::RepeatedPtrField< ::ods::keystate::KeyDependency > *
				pmutable_dependencies = _zone->mutable_dependencies();
			pmutable_dependencies->SwapElements(k,_zone->dependencies_size()-1);
			pmutable_dependencies->RemoveLast();
			break;
		}
	}
}

void KeyDependencyListPB::delDependency( KeyData *key)
{
	for (int k=0; k<_zone->dependencies_size(); ++k) {
		if ( (_zone->mutable_dependencies(k)->to_key().compare(key->locator())||
				_zone->mutable_dependencies(k)->from_key().compare(key->locator())))
		{
			::google::protobuf::RepeatedPtrField< ::ods::keystate::KeyDependency > *
				pmutable_dependencies = _zone->mutable_dependencies();
			pmutable_dependencies->SwapElements(k,_zone->dependencies_size()-1);
			pmutable_dependencies->RemoveLast();
		}
	}
}

// KeyDataListPB

KeyDataListPB::KeyDataListPB(::ods::keystate::EnforcerZone *zone)
: _zone(zone)
{
    for (int k=0; k<_zone->keys_size(); ++k) {
        ::ods::keystate::KeyData *keydata = _zone->mutable_keys(k);
        KeyDataPB key( keydata );
        _keys.push_back(key);
    }
}

KeyData &KeyDataListPB::addNewKey(int algorithm, time_t inception, KeyRole role,
                       int minimize)
{
    KeyDataPB key( _zone->add_keys() );
    key.setAlgorithm( algorithm );
    key.setInception( inception );
    key.setRole( role );
    ((KeyStatePB&)key.keyStateDS()).setMinimize( (minimize>>2)&1 );
    ((KeyStatePB&)key.keyStateDNSKEY()).setMinimize( (minimize>>1)&1 );
    ((KeyStatePB&)key.keyStateRRSIG()).setMinimize( minimize&1 );
    _keys.push_back(key);
    return _keys.back();
}


int KeyDataListPB::numKeys()
{
    return _keys.size();
}

KeyData &KeyDataListPB::key(int index)
{
    return _keys[index];
}

void KeyDataListPB::delKey(int index)
{
    std::vector<KeyDataPB>::iterator key = _keys.begin()+index;
    
    // remove the key from _zone->keys()
    for (int k=0; k<_zone->keys_size(); ++k) {
        if (key->matches( _zone->mutable_keys(k) )) {
            // Key at index k inside _zone->mutable_keys() matches the
            // key we are trying to delete.
            // Note that currently predicate 'k == index' should hold.
            // We don't enforce it however, to allow a future situation 
            // where the field _keys of this KeyDataListPB object contains 
            // a subset of the keys found in _zone->mutable_keys()
            ::google::protobuf::RepeatedPtrField< ::ods::keystate::KeyData > *
                pmutable_keys = _zone->mutable_keys();
            pmutable_keys->SwapElements(k,_zone->keys_size()-1);
            pmutable_keys->RemoveLast();
            break;
        }
    }

    _keys.erase( key );
}

// EnforcerZonePB

EnforcerZonePB::EnforcerZonePB(::ods::keystate::EnforcerZone *zone, 
                                     const ::ods::kasp::Policy &policy) 
: _zone(zone), _keyDataList(_zone), _keyDependencyList(_zone)
{
	_policy.CopyFrom(policy);
}

const std::string &EnforcerZonePB::name()
{
    return _zone->name();
}

const ::ods::kasp::Policy *EnforcerZonePB::policy()
{
    return &_policy;
}

int EnforcerZonePB::max_zone_ttl()
{
    int maxzonettl = _policy.signatures().max_zone_ttl();
    if (!_policy.denial().has_nsec3() || !_policy.denial().nsec3().has_ttl()) {
	return maxzonettl;
    }
    int nsec3paramttl = _policy.denial().nsec3().ttl();
    return (nsec3paramttl > maxzonettl)? nsec3paramttl : maxzonettl;
}

KeyDependencyList &EnforcerZonePB::keyDependencyList()
{
    return _keyDependencyList;
}

KeyDataList &EnforcerZonePB::keyDataList()
{
    return _keyDataList;
}

bool EnforcerZonePB::signerConfNeedsWriting()
{
    return _zone->signconf_needs_writing();
}

void EnforcerZonePB::setSignerConfNeedsWriting(bool value)
{
    _zone->set_signconf_needs_writing(value);
}

void EnforcerZonePB::setNextChange(time_t value)
{
    _zone->set_next_change(value);
}

time_t EnforcerZonePB::ttlEnddateDs()
{
    return _zone->has_ttl_end_ds() ? _zone->ttl_end_ds() : 0;
}

void EnforcerZonePB::setTtlEnddateDs(time_t value)
{
    _zone->set_ttl_end_ds(value);
}
time_t EnforcerZonePB::ttlEnddateDk()
{
    return _zone->has_ttl_end_dk() ? _zone->ttl_end_dk() : 0;
}

void EnforcerZonePB::setTtlEnddateDk(time_t value)
{
    _zone->set_ttl_end_dk(value);
}

time_t EnforcerZonePB::ttlEnddateRs()
{
    return _zone->has_ttl_end_rs() ? _zone->ttl_end_rs() : 0;
}

void EnforcerZonePB::setTtlEnddateRs(time_t value)
{
    _zone->set_ttl_end_rs(value);
}

bool EnforcerZonePB::rollKskNow()
{
    return _zone->roll_ksk_now();
}

void EnforcerZonePB::setRollKskNow(bool value)
{
    _zone->set_roll_ksk_now(value);
}

bool EnforcerZonePB::rollZskNow()
{
    return _zone->roll_zsk_now();
}

void EnforcerZonePB::setRollZskNow(bool value)
{
    _zone->set_roll_zsk_now(value);
}

bool EnforcerZonePB::rollCskNow()
{
    return _zone->roll_csk_now();
}

void EnforcerZonePB::setRollCskNow(bool value)
{
    _zone->set_roll_csk_now(value);
}
/* Only used to show the user */
time_t EnforcerZonePB::nextKskRoll() {return _zone->next_ksk_roll();}
time_t EnforcerZonePB::nextZskRoll() {return _zone->next_zsk_roll();}
time_t EnforcerZonePB::nextCskRoll() {return _zone->next_csk_roll();}
void EnforcerZonePB::setNextKskRoll(time_t value) {_zone->set_next_ksk_roll(value);}
void EnforcerZonePB::setNextZskRoll(time_t value) {_zone->set_next_zsk_roll(value);}
void EnforcerZonePB::setNextCskRoll(time_t value) {_zone->set_next_csk_roll(value);}

