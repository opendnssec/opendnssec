#ifndef _ENFORCER_HSMKEYFACTORY_H_
#define _ENFORCER_HSMKEYFACTORY_H_

/*
 * Dummy implemenation of enforcer data to be used as test fixture 
 * and to establish whether the interface is actually complete.
 */

#include <set>
#include "enforcer/enforcerdata.h"

class HsmKeyPB : public HsmKey {
private:
    std::string _locator;
    int _algorithm;
    std::string _policyName;
    int _bits;
    KeyRole _keyRole;
    std::set<std::string> _usedByZones;
public:
    HsmKeyPB(const std::string &locator);
    
    virtual std::string locator();
    
    virtual bool usedByZone(const std::string &zone);
    virtual void setUsedByZone(const std::string &zone, bool bValue);

    virtual int algorithm();
    virtual void setAlgorithm(int value);
    
    virtual std::string policyName();
    virtual void setPolicyName(const std::string &value);
    
    virtual int bits();
    virtual void setBits(int value);

    virtual KeyRole keyRole();
    virtual void setKeyRole(KeyRole value);
};

class HsmKeyFactoryPB : public HsmKeyFactory {
private:
    std::vector<HsmKeyPB> _keys;
public:
    virtual bool CreateNewKey(int bits, HsmKey **ppKey);
    
    virtual bool CreateSharedKey(const std::string &policyName, int algorithm,
                                 int bits, KeyRole role, HsmKey **ppKey);


    virtual bool FindSharedKeys(const std::string &policyName, int algorithm,
                                int bits, KeyRole role, 
                                const std::string &notZone, HsmKey **ppKey);
};

#endif
