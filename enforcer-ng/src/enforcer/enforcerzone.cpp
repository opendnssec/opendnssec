#include "enforcer/enforcerzone.h"

//////////////////////////////
// KeyStatePB
//////////////////////////////

KeyStatePB::KeyStatePB(::keystate::pb::KeyState *keystate)
: _keystate(keystate)
{
    
}

int KeyStatePB::state()
{
    return _keystate->state();
}

void KeyStatePB::setState(int value)
{
    _keystate->set_state( value );
}

int KeyStatePB::lastChange()
{
    return _keystate->lastchange();
}

void KeyStatePB::setLastChange(int value)
{
    _keystate->set_lastchange( value );
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

KeyDataPB::KeyDataPB( ::keystate::pb::KeyData *keydata )
:   _keydata(keydata),
    _keyStateDS( _keydata->mutable_ds() ),
    _keyStateRRSIG( _keydata->mutable_rrsig() ),
    _keyStateDNSKEY( _keydata->mutable_dnskey() )
{
}

bool KeyDataPB::deleted()
{
    return _keydata->_deleted();
}

void KeyDataPB::setDeleted(bool value)
{
    _keydata->set__deleted(value);
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

int KeyDataPB::inception()
{
    return _keydata->inception();
}

void KeyDataPB::setInception(int value)
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
    _keydata->set_role( (::keystate::pb::keyrole)value );
}

bool KeyDataPB::isDSSeen()
{
    return _keydata->dsseen();
}

void KeyDataPB::setDSSeen(bool value)
{
    _keydata->set_dsseen( value );
}

bool KeyDataPB::submitToParent()
{
    return _keydata->submittoparent();
}

void KeyDataPB::setSubmitToParent(bool value)
{
    _keydata->set_submittoparent( value );
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

KeyDataListPB::KeyDataListPB(::keystate::pb::EnforcerZone *zone)
: _zone(zone)
{
    for (int k=0; k<_zone->keys_size(); ++k) {
        ::keystate::pb::KeyData *keydata = _zone->mutable_keys(k);
        if (keydata->_deleted()) 
            continue;
        KeyDataPB key( keydata );
        _keys.push_back(key);
    }
}

KeyData &KeyDataListPB::addNewKey(int algorithm, int inception, KeyRole role,
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
    std::vector<KeyDataPB>::iterator it = _keys.begin()+index;
    it->setDeleted(true);
    _keys.erase( it );
}

// EnforcerZonePB

EnforcerZonePB::EnforcerZonePB(::keystate::pb::EnforcerZone *zone, 
                                     const kasp::pb::Policy *policy) 
: _zone(zone), _policy(policy), _keyDataList(_zone)
{
}

const std::string &EnforcerZonePB::name()
{
    return _zone->name();
}

const kasp::pb::Policy *EnforcerZonePB::policy()
{
    return _policy;
}

KeyDataList &EnforcerZonePB::keyDataList()
{
    return _keyDataList;
}

bool EnforcerZonePB::signerConfNeedsWriting()
{
    return _zone->signconfneedswriting();
}

void EnforcerZonePB::setSignerConfNeedsWriting(bool value)
{
    _zone->set_signconfneedswriting(value);
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
