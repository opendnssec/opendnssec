#include "enforcer/hsmkeyfactory.h"

extern "C" {
#include "shared/duration.h"
#include "shared/log.h"
}

static const char * const module_str = "hsmkeyfactory";

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
    if (::ods::hsmkey::keyrole_IsValid(value))
        _key->set_role( (::ods::hsmkey::keyrole)value );
    else {
        ods_log_error("[%s] %d is not a valid keyrole value",
                      module_str,value);
    }
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

const std::string &HsmKeyPB::repository()
{
    return _key->repository();
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
bool HsmKeyFactoryPB::CreateNewKey(int bits, const std::string &repository,
                                   const std::string &policy, int algorithm,
                                   KeyRole role,
                                   HsmKey **ppKey)
{
    // First go through the keys and try to find a key that matches the
    // parameters exactly.
    for (int k=0; k<_doc->keys_size(); ++k) {
        ::ods::hsmkey::HsmKey *pbkey = _doc->mutable_keys(k);
        if (!pbkey->has_inception() 
            && pbkey->bits() == bits
            && pbkey->repository() == repository
            && pbkey->policy() == policy
            && pbkey->algorithm() == algorithm
            && pbkey->role() == (::ods::hsmkey::keyrole)role
            )
        {
            pbkey->set_inception(time_now());
            std::pair<std::map<std::string,HsmKeyPB>::iterator,bool> ret;
            ret = _keys.insert(std::pair<std::string,HsmKeyPB>(
                                            pbkey->locator(),HsmKeyPB(pbkey)));
            *ppKey = &ret.first->second;

            // Fixate unset attributes that returned their default value.
            // Otherwise when we list the keys those values will show 
            // up as 'not set'
            if (!pbkey->has_policy())
                (*ppKey)->setPolicy(policy);
            if (!pbkey->has_algorithm())
                (*ppKey)->setAlgorithm(algorithm);
            if (!pbkey->has_role())
                (*ppKey)->setKeyRole(role);
            return true;
        }
    }

    // If that fails go through the list of keys again and try to find
    // a key that has some of the attributes not assigned.
    for (int k=0; k<_doc->keys_size(); ++k) {
        ::ods::hsmkey::HsmKey *pbkey = _doc->mutable_keys(k);
        if (!pbkey->has_inception()
            && pbkey->bits() == bits
            && pbkey->repository() == repository
            && (!pbkey->has_policy() || pbkey->policy() == policy)
            && (!pbkey->has_algorithm() || pbkey->algorithm() == algorithm)
            && (!pbkey->has_role()||pbkey->role()==(::ods::hsmkey::keyrole)role)
            ) 
        {
            pbkey->set_inception(time_now());
            std::pair<std::map<std::string,HsmKeyPB>::iterator,bool> ret;
            ret = _keys.insert(std::pair<std::string,HsmKeyPB>(
                                            pbkey->locator(),HsmKeyPB(pbkey)));
            *ppKey = &ret.first->second;
            if (!pbkey->has_policy())
                (*ppKey)->setPolicy(policy);
            if (!pbkey->has_algorithm())
                (*ppKey)->setAlgorithm(algorithm);
            if (!pbkey->has_role())
                (*ppKey)->setKeyRole(role);
            return true;
        }
    }
    
    // We were not able to find any suitable key, give up.
    return false;
}

bool HsmKeyFactoryPB::CreateSharedKey(int bits, const std::string &repository,
                                      const std::string &policy, int algorithm, 
                                      KeyRole role, const std::string &zone,
                                      HsmKey **ppKey)
{
    if (CreateNewKey(bits, repository, policy, algorithm, role, ppKey)) {
        
        (*ppKey)->setCandidateForSharing(true);
        (*ppKey)->setUsedByZone(zone,true);
        
        return true;
    }
    return false;
}

bool HsmKeyFactoryPB::GetHsmKeyByLocator(const std::string loc, HsmKey **ppKey)
{
    // First try to match one of the existing HsmKeyPB objects
    std::map<std::string,HsmKeyPB>::iterator lk = _keys.find(loc);
    if (lk != _keys.end()) {
        *ppKey = &lk->second;
        return true;
    }
    
    // Now enumerate keys in the document try to find a key that matches the
    // parameters exactly and is not yet present in the _keys vector field.
    for (int k=0; k<_doc->keys_size(); ++k) {
        ::ods::hsmkey::HsmKey *pbkey = _doc->mutable_keys(k);
        if (pbkey->locator() == loc) {
            std::pair<std::map<std::string,HsmKeyPB>::iterator,bool> ret;
            ret = _keys.insert(std::pair<std::string,HsmKeyPB>(
                                            pbkey->locator(),HsmKeyPB(pbkey)));
            *ppKey = &ret.first->second;
            return true;
        }
    }
    return false;
}

bool HsmKeyFactoryPB::UseSharedKey(int bits, const std::string &repository,
                                   const std::string &policy, int algorithm, 
                                   KeyRole role, const std::string &zone, 
                                   HsmKey **ppKey)
{
    // First try to match one of the existing HsmKeyPB objects
    std::map<std::string,HsmKeyPB>::iterator k;
    for (k = _keys.begin(); k != _keys.end(); ++k) {
        if (k->second.bits() == bits 
            && k->second.policy() == policy 
            && k->second.algorithm() == algorithm
            && k->second.keyRole() == role
            && !k->second.usedByZone(zone)
            )
        {
            *ppKey = &k->second;
            (*ppKey)->setUsedByZone(zone,true);
            return true;
        }
    }

    // Now enumerate keys in the document try to find a key that matches the
    // parameters exactly and is not yet present in the _keys vector field.
    for (int k=0; k<_doc->keys_size(); ++k) {
        ::ods::hsmkey::HsmKey *pbkey = _doc->mutable_keys(k);
        if (pbkey->has_inception()
            && pbkey->bits() == bits
            && pbkey->repository() == repository
            && pbkey->policy() == policy
            && pbkey->algorithm() == algorithm
            && pbkey->role() == (::ods::hsmkey::keyrole)role
            )
        {
            pbkey->set_inception(time_now());
            std::pair<std::map<std::string,HsmKeyPB>::iterator,bool> ret;
            ret = _keys.insert(std::pair<std::string,HsmKeyPB>(
                                            pbkey->locator(),HsmKeyPB(pbkey)));
            *ppKey = &ret.first->second;
            (*ppKey)->setUsedByZone(zone,true);
            
            // Fixate unset attributes that returned their default value.
            // Otherwise when we list the keys those values will show 
            // up as 'not set'
            if (!pbkey->has_policy())
                (*ppKey)->setPolicy(policy);
            if (!pbkey->has_algorithm())
                (*ppKey)->setAlgorithm(algorithm);
            if (!pbkey->has_role())
                (*ppKey)->setKeyRole(role);
            return true;
        }
    }

    return false;
}
