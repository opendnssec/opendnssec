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


//////////////////////////////
// KeyDataPB
//////////////////////////////

KeyDataPB::KeyDataPB( ::keystate::pb::KeyData *keydata )
: _keydata(keydata)
{
    _keyStateDS = new KeyStatePB( _keydata->mutable_ds() );
    _keyStateRRSIG = new KeyStatePB( _keydata->mutable_rrsig() );
    _keyStateDNSKEY = new KeyStatePB( _keydata->mutable_dnskey() );
}

KeyDataPB::~KeyDataPB()
{
    delete _keyStateDS;
    delete _keyStateRRSIG;
    delete _keyStateDNSKEY;
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
    return *_keyStateDS;
}

KeyState &KeyDataPB::keyStateRRSIG()
{
    return *_keyStateRRSIG;
}

KeyState &KeyDataPB::keyStateDNSKEY()
{
    return *_keyStateDNSKEY;
}

KeyRole KeyDataPB::keyRole()
{
    return (KeyRole)_keydata->role();
}

void KeyDataPB::setKeyRole(KeyRole value)
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

KeyData &KeyDataListPB::addNewKey()
{
    KeyDataPB key( _zone->add_keys() );
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
: _zone(zone), _policy(policy)
{
    _keyDataList = new KeyDataListPB(_zone);
}

EnforcerZonePB::~EnforcerZonePB()
{
    delete _keyDataList;
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
    return *_keyDataList;
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
