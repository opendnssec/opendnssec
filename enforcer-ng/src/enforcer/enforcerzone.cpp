#include "enforcer/enforcerzone.h"

extern "C" {
#include "shared/log.h"
}

static const char *enforcezone_str = "enforcezone";

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
                      enforcezone_str,value);
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
    _keyStateDNSKEY( _keydata->mutable_dnskey() )
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
                      enforcezone_str,value);
    }
}

bool KeyDataPB::isDSSeen()
{
    return _keydata->ds_seen();
}

void KeyDataPB::setDSSeen(bool value)
{
    _keydata->set_ds_seen( value );
}

bool KeyDataPB::submitToParent()
{
    return _keydata->submit_to_parent();
}

void KeyDataPB::setSubmitToParent(bool value)
{
    _keydata->set_submit_to_parent( value );
}

bool KeyDataPB::introducing()
{
    return _keydata->introducing();
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

void KeyDataPB::setActive(bool value)
{
    _keydata->set_active(value);
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
                       bool minimizeDS, bool minimizeRRSIG, 
                       bool minimizeDNSKEY)
{
    KeyDataPB key( _zone->add_keys() );
    key.setAlgorithm( algorithm );
    key.setInception( inception );
    key.setRole( role );
    ((KeyStatePB&)key.keyStateDS()).setMinimize( minimizeDS );
    ((KeyStatePB&)key.keyStateRRSIG()).setMinimize( minimizeRRSIG );
    ((KeyStatePB&)key.keyStateDNSKEY()).setMinimize( minimizeDNSKEY );
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
                                     const ::ods::kasp::Policy *policy) 
: _zone(zone), _policy(policy), _keyDataList(_zone)
{
}

const std::string &EnforcerZonePB::name()
{
    return _zone->name();
}

const ::ods::kasp::Policy *EnforcerZonePB::policy()
{
    return _policy;
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

void EnforcerZonePB::beginTransaction()
{
    
}

void EnforcerZonePB::commitTransaction()
{
    
}

void EnforcerZonePB::cancelTransaction()
{
    
}
