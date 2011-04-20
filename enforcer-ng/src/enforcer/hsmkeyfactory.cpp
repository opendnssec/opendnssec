#include "enforcer/hsmkeyfactory.h"

extern "C" {
#include "shared/duration.h"
    
}

//////////////////////////////
// HsmKeyPB
//////////////////////////////


HsmKeyPB::HsmKeyPB(::ods::hsmkey::HsmKey *key)
: _key(key)
{
    
}

const std::string &HsmKeyPB::locator()
{ 
    return _key->locator();
}

bool HsmKeyPB::candidateForSharing()
{
    return _key->candidate_for_sharing();
}

void HsmKeyPB::setCandidateForSharing(bool value)
{
    _key->set_candidate_for_sharing(value);
}

int HsmKeyPB::bits()
{
    return _key->bits();
}

void HsmKeyPB::setBits(int value)
{
    _key->set_bits(value);
}

const std::string &HsmKeyPB::policy()
{
    return _key->policy();
}

void HsmKeyPB::setPolicy(const std::string &value) 
{
    _key->set_policy(value);
}

int HsmKeyPB::algorithm()
{
    return _key->algorithm();
}

void HsmKeyPB::setAlgorithm(int value)
{
    _key->set_algorithm(value);
}


KeyRole HsmKeyPB::keyRole()
{
    return (KeyRole)_key->role();
}

void HsmKeyPB::setKeyRole(KeyRole value)
{
    _key->set_role((::ods::hsmkey::keyrole)value);
}

bool HsmKeyPB::usedByZone(const std::string &zone)
{
    ::google::protobuf::RepeatedPtrField< ::std::string>::iterator it;
    ::google::protobuf::RepeatedPtrField< ::std::string>*ubz = 
        _key->mutable_used_by_zones();
    for (it = ubz->begin(); it!=ubz->end(); ++it) {
        if (*it == zone) {
            return true;
        }
    }
    return false;
}

void HsmKeyPB::setUsedByZone(const std::string &zone, bool bValue)
{
    ::google::protobuf::RepeatedPtrField< ::std::string>*ubz = 
        _key->mutable_used_by_zones();
    for (int z=0; z<_key->used_by_zones_size(); ++z) {
        if (_key->used_by_zones(z) == zone) {
            if (!bValue) {
                ubz->SwapElements(z,_key->used_by_zones_size()-1);
                ubz->RemoveLast();
            }
            return;
        }
    }
    if (bValue)
        _key->add_used_by_zones(zone);
}

time_t HsmKeyPB::inception()
{
    return _key->inception();
}

void HsmKeyPB::setInception(time_t value)
{
    _key->set_inception(value);
}

bool HsmKeyPB::revoke()
{
    return _key->revoke();
}

void HsmKeyPB::setRevoke(bool value)
{
    _key->set_revoke(value);
}

//////////////////////////////
// HsmKeyFactoryPB
//////////////////////////////

HsmKeyFactoryPB::HsmKeyFactoryPB(::ods::hsmkey::HsmKeyDocument *doc)
: _doc(doc)
{
}


/* Create a new key with the specified number of bits (or retrieve it 
 from a pre-generated keypool)  */
bool HsmKeyFactoryPB::CreateNewKey(int bits, HsmKey **ppKey)
{
    for (int k=0; k<_doc->keys_size(); ++k) {
        ::ods::hsmkey::HsmKey *pbkey = _doc->mutable_keys(k);
        if (pbkey->bits() == bits && !pbkey->has_inception()) {
            pbkey->set_inception(time_now());
            _keys.push_back(HsmKeyPB(pbkey));
            *ppKey = &_keys.back();
            return true;
        }
    }
    return false;
}

bool HsmKeyFactoryPB::CreateSharedKey(int bits, 
                                      const std::string &policy, int algorithm, 
                                      KeyRole role, const std::string &zone,
                                      HsmKey **ppKey)
{
    if (CreateNewKey(bits, ppKey)) {
        
        (*ppKey)->setCandidateForSharing(true);
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
