#include "enforcer/hsmkeyfactory.h"

//////////////////////////////
// HsmKeyPB
//////////////////////////////


HsmKeyPB::HsmKeyPB(const std::string &locator) : _locator(locator) 
{
}

std::string HsmKeyPB::locator()
{ 
    return _locator;
    // return std::string();
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
    
int HsmKeyPB::algorithm()
{
    return _algorithm;
}

void HsmKeyPB::setAlgorithm(int value)
{
    _algorithm  = value;
}

std::string HsmKeyPB::policyName()
{
    // return std::string("Default");
    return _policyName;
}

void HsmKeyPB::setPolicyName(const std::string &value)
{
    _policyName = value;
}

int HsmKeyPB::bits()
{
    //return 2048;
    return _bits;
}

void HsmKeyPB::setBits(int value)
{
    _bits = value;
}

KeyRole HsmKeyPB::keyRole()
{
    return _keyRole;
}

void HsmKeyPB::setKeyRole(KeyRole value)
{
    _keyRole = value;
}

//////////////////////////////
// HsmKeyFactoryPB
//////////////////////////////

/* Create a new key with the specified number of bits (or retrieve it 
 from a pre-generated keypool)  */
bool HsmKeyFactoryPB::CreateNewKey(int bits, HsmKey **ppKey)
{
    // Create a dummy key with the given locator
    
    const char *dummyLocators[] = {
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
    dummyKey.setAlgorithm(8);
    dummyKey.setPolicyName("Default");
    dummyKey.setBits(bits);
    
    _keys.push_back(dummyKey);
    *ppKey = &_keys.back();
    return true;
}

bool HsmKeyFactoryPB::CreateSharedKey(const std::string &policyName, 
                                         int algorithm, int bits, 
                                         KeyRole role, HsmKey **ppKey)
{
    std::vector<HsmKeyPB>::iterator k;
    for (k = _keys.begin(); k != _keys.end(); ++k) {
        if (k->policyName() == policyName && k->algorithm() == algorithm && k->bits() == bits) {
            *ppKey = &(*k);
            return true;
        }
    }
    
    if (CreateNewKey(bits, ppKey)) {
        
        (*ppKey)->setAlgorithm(algorithm);
        (*ppKey)->setPolicyName(policyName);
        
        return true;
    }
    return false;
}

bool HsmKeyFactoryPB::FindSharedKeys(const std::string &policyName,
                                        int algorithm, int bits, 
                                        KeyRole role,
                                        const std::string &notZone, 
                                        HsmKey **ppKey)
{
    return false;
}
