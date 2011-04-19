#ifndef _ENFORCER_HSMKEYFACTORY_H_
#define _ENFORCER_HSMKEYFACTORY_H_

/*
 * Dummy implemenation of enforcer data to be used as test fixture 
 * and to establish whether the interface is actually complete.
 */

#include <set>
#include "enforcer/enforcerdata.h"
#include "hsmkey/hsmkey.pb.h"


class HsmKeyPB : public HsmKey {
private:
    ::hsmkey::pb::HsmKey *_key;
public:
    HsmKeyPB(::hsmkey::pb::HsmKey *key);
    
    virtual const std::string &locator();
    
    virtual bool candidateForSharing();
    virtual void setCandidateForSharing(bool value);

    virtual int bits();
    virtual void setBits(int value);
    
    virtual const std::string &policy();
    virtual void setPolicy(const std::string &value);
    
    virtual int algorithm();
    virtual void setAlgorithm(int value);
    
    virtual KeyRole keyRole();
    virtual void setKeyRole(KeyRole value);

    virtual bool usedByZone(const std::string &zone);
    virtual void setUsedByZone(const std::string &zone, bool bValue);

    virtual time_t inception();
    virtual void setInception(time_t value);
    
    virtual bool revoke();
    virtual void setRevoke(bool value);
    
};

class HsmKeyFactoryPB : public HsmKeyFactory {
private:
    ::hsmkey::pb::HsmKeyDocument *_doc;
    std::vector<HsmKeyPB> _keys;
public:
    HsmKeyFactoryPB(::hsmkey::pb::HsmKeyDocument *doc);
    
    virtual bool CreateNewKey(int bits, HsmKey **ppKey);
    
    virtual bool CreateSharedKey(int bits,
                                 const std::string &policy, int algorithm,
                                 KeyRole role, const std::string &zone,
                                 HsmKey **ppKey);

    virtual bool UseSharedKey(int bits, 
                              const std::string &policy, int algorithm,
                              KeyRole role, const std::string &zone,
                              HsmKey **ppKey);
};

#endif
