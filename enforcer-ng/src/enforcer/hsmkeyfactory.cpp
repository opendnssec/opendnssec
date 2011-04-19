#include "enforcer/hsmkeyfactory.h"

//////////////////////////////
// HsmKeyPB
//////////////////////////////


HsmKeyPB::HsmKeyPB(const std::string &locator) : _locator(locator) 
{
}

const std::string &HsmKeyPB::locator()
{ 
    return _locator;
}

bool HsmKeyPB::candidateForSharing()
{
    return _candidateForSharing;
}

void HsmKeyPB::setCandidateForSharing(bool value)
{
    _candidateForSharing = value;
}

int HsmKeyPB::bits()
{
    return _bits;
}

void HsmKeyPB::setBits(int value)
{
    _bits = value;
}

const std::string &HsmKeyPB::policy()
{
    return _policy;
}

void HsmKeyPB::setPolicy(const std::string &value) 
{
    _policy = value;
}

int HsmKeyPB::algorithm()
{
    return _algorithm;
}

void HsmKeyPB::setAlgorithm(int value)
{
    _algorithm  = value;
}


KeyRole HsmKeyPB::keyRole()
{
    return _keyRole;
}

void HsmKeyPB::setKeyRole(KeyRole value)
{
    _keyRole = value;
}

bool HsmKeyPB::usedByZone(const std::string &zone)
{
    return _usedByZones.count(zone) > 0;
}

void HsmKeyPB::setUsedByZone(const std::string &zone, bool bValue)
{
    if (bValue)
        _usedByZones.insert(zone);
    else
        _usedByZones.erase(zone);
}

int HsmKeyPB::inception()
{
    return _inception;
}

void HsmKeyPB::setInception(int value)
{
    _inception = value;
}

bool HsmKeyPB::revoke()
{
    return _revoke;
}

void HsmKeyPB::setRevoke(bool value)
{
    _revoke = value;
}

//////////////////////////////
// HsmKeyFactoryPB
//////////////////////////////

/* Create a new key with the specified number of bits (or retrieve it 
 from a pre-generated keypool)  */
bool HsmKeyFactoryPB::CreateNewKey(int bits, HsmKey **ppKey)
{
    // Create a dummy key with the given locator
    
    static const char *dummyLocators[] = {
        "008be1241707c55f7c4bc35743151e71",
        "108be1241707c55f7c4bc35743151e71",
        "208be1241707c55f7c4bc35743151e71",
        "308be1241707c55f7c4bc35743151e71",
        "408be1241707c55f7c4bc35743151e71",
        "508be1241707c55f7c4bc35743151e71",
        "608be1241707c55f7c4bc35743151e71",
        "708be1241707c55f7c4bc35743151e71",
        "808be1241707c55f7c4bc35743151e71",
        "908be1241707c55f7c4bc35743151e71",
        "a08be1241707c55f7c4bc35743151e71",
        "b08be1241707c55f7c4bc35743151e71",
        "c08be1241707c55f7c4bc35743151e71",
        "d08be1241707c55f7c4bc35743151e71",
        "e08be1241707c55f7c4bc35743151e71",
        "f08be1241707c55f7c4bc35743151e71",
    };
  
    // Out of dummy locators, then return false
    if (_keys.size() >= sizeof(dummyLocators)/sizeof(const char *))
        return false;
    
    HsmKeyPB dummyKey(dummyLocators[_keys.size()]);
    dummyKey.setBits(bits);
    
    _keys.push_back(dummyKey);
    *ppKey = &_keys.back();
    return true;
}

bool HsmKeyFactoryPB::CreateSharedKey(int bits, 
                                      const std::string &policy, int algorithm, 
                                      KeyRole role, const std::string &zone,
                                      HsmKey **ppKey)
{
    if (CreateNewKey(bits, ppKey)) {
        
        (*ppKey)->setPolicy(policy);
        (*ppKey)->setAlgorithm(algorithm);
        (*ppKey)->setKeyRole(role);
        (*ppKey)->usedByZone(zone);
        
        return true;
    }
    return false;
}

bool HsmKeyFactoryPB::UseSharedKey(int bits, 
                                   const std::string &policy, int algorithm, 
                                   KeyRole role, const std::string &zone, 
                                   HsmKey **ppKey)
{
    std::vector<HsmKeyPB>::iterator k;
    for (k = _keys.begin(); k != _keys.end(); ++k) {
        if (k->bits() == bits 
            && k->policy() == policy 
            && k->algorithm() == algorithm
            && k->keyRole() == role
            && !k->usedByZone(zone)
            )
        {
            *ppKey = &(*k);
            (*ppKey)->usedByZone(zone);
            return true;
        }
    }
    return false;
}
