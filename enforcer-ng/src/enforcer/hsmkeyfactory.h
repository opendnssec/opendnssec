#ifndef _ENFORCER_HSMKEYFACTORY_H_
#define _ENFORCER_HSMKEYFACTORY_H_

/*
 * Dummy implemenation of enforcer data to be used as test fixture 
 * and to establish whether the interface is actually complete.
 */

#include <map>
#include "enforcer/enforcerdata.h"
#include "hsmkey/hsmkey.pb.h"

class HsmKeyPB : public HsmKey {
private:
    ::ods::hsmkey::HsmKey *_key;
public:
    HsmKeyPB(::ods::hsmkey::HsmKey *key);
    
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
    
    virtual const std::string &repository();    
};

class HsmKeyFactoryDelegatePB {
public:

    /**
     * Called when a key was created.
     * The implementer of the delegate can then decide whether it should
     * create additional keys to replace the one that was consumed.
     */
    virtual void OnKeyCreated(int bits, const std::string &repository,
                              const std::string &policy, int algorithm,
                              KeyRole role) = 0;

    /**
     * Called when a key could not be created because there are
     * not enough available. The implementer of the delegate should
     * start the key generation process to create keys for the enforcer.
     */
    virtual void OnKeyShortage(int bits, const std::string &repository,
                               const std::string &policy, int algorithm,
                               KeyRole role) = 0;
};

class HsmKeyFactoryPB : public HsmKeyFactory {
private:
    ::ods::hsmkey::HsmKeyDocument *_doc;
    std::map<std::string,HsmKeyPB> _keys;
    HsmKeyFactoryDelegatePB *_delegate;
    
public:
    HsmKeyFactoryPB(::ods::hsmkey::HsmKeyDocument *doc,
                    HsmKeyFactoryDelegatePB *delegate);
    
    virtual bool CreateNewKey(int bits, const std::string &repository,
                              const std::string &policy, int algorithm,
                              KeyRole role,
                              HsmKey **ppKey);
    
    virtual bool CreateSharedKey(int bits, const std::string &repository,
                                 const std::string &policy, int algorithm,
                                 KeyRole role, const std::string &zone,
                                 HsmKey **ppKey);

    virtual bool UseSharedKey(int bits, const std::string &repository,
                              const std::string &policy, int algorithm,
                              KeyRole role, const std::string &zone,
                              HsmKey **ppKey);
                              
    virtual bool GetHsmKeyByLocator(const std::string loc, HsmKey **ppKey);
};

#endif
