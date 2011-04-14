#ifndef _ENFORCER_ENFORCERDATA_H_
#define _ENFORCER_ENFORCERDATA_H_

#include "policy/kasp.pb.h"

enum KeyRole { KSK=1, ZSK, CSK };

class HsmKey {
public:
    virtual std::string locator() = 0;

    virtual bool usedByZone(const std::string &zone) = 0;
    virtual void setUsedByZone(const std::string &zone, bool bValue) = 0;
    
    virtual int algorithm() = 0;
    virtual void setAlgorithm(int value) = 0;

    virtual std::string policyName() = 0;
    virtual void setPolicyName(const std::string &value) = 0;

    virtual int bits() = 0;
    virtual void setBits(int value) = 0;
    
    virtual KeyRole keyRole() = 0;
    virtual void setKeyRole(KeyRole value) = 0;
};


/**
 * Get access to the pool of keys (pre-)generated and stored in a HSM 
 * The enforcer uses this factory to get fresh keys to be used as KSK 
 * or ZSK in the zone.
 */

class HsmKeyFactory {
public:
    /* Create a new key with the specified number of bits (or retrieve it 
     from a pre-generated keypool)  */
    virtual bool CreateNewKey(int bits, HsmKey **ppKey) = 0;
    
    /* Create a key shared by all the zones with the given policy name, 
     * algorithm and bits
     * \param[in] policyName name of the policy
     * \param[in] algorithm algorithm
     * \param[in] bits number of bits in the key
     * \param[in] role role of the key
     * \return HsmKeyEnumerator * key enumerator for accessing the search result
     *      or NULL when §the search did not match any known keys.
     */
    virtual bool CreateSharedKey(const std::string &policyName, int algorithm,
                                 int bits, KeyRole role, HsmKey **ppKey) = 0;

    /* Find existing keys based on the arguments passed in.
     * Additionally the following sanity checks will be performed on 
     * viable candidates

     - niet Zone Z (niet 2x in dezelfde zone gebruiken)
     - daarvan de gene met de grootste inception date. (de nieuwste)

     * \param[in] policyName name of the policy to match
     * \param[in] algorithm algorithm to match
     * \param[in] bits number of bits to match
     * \param[in] role role of the key to match
     * \param[in] notZone zone name in which the key should not yet be used
     * \param[out] ppKey key that matches the search criteria
     * \return bool returns true when a match was found.
     */
    virtual bool FindSharedKeys(const std::string &policyName, int algorithm,
                                int bits, KeyRole role, 
                                const std::string &notZone, HsmKey **ppKey) = 0;
};

class KeyState {
public:
    virtual int state() = 0;
    virtual void setState(int value) = 0;
    
    virtual int lastChange() = 0;
    virtual void setLastChange(int value) = 0;
    
    virtual bool minimize() = 0;
};

class KeyData {
public:
    virtual const std::string &locator() = 0;
    virtual void setLocator(const std::string &value) = 0;
    
    virtual int algorithm() = 0;

    virtual int inception() = 0;
    
    virtual KeyState &keyStateDS() = 0;
    virtual KeyState &keyStateRRSIG() = 0;
    virtual KeyState &keyStateDNSKEY() = 0;

    virtual KeyRole role() = 0;

    virtual bool isDSSeen() = 0;
    virtual void setDSSeen(bool value) = 0;
    
    virtual bool submitToParent() = 0;
    virtual void setSubmitToParent(bool value) = 0;

    /* Movement direction */
    virtual bool introducing() = 0; /* goal */
    
    /* alternative path */
    virtual bool revoke() = 0;
    
    /* selective brakes */
    virtual bool standby() = 0;
};

class KeyDataList {
public:
    virtual KeyData &addNewKey(int algorithm, int inception, KeyRole role,
                               bool minimizeDS, bool minimizeRRSIG, 
                               bool minimizeDNSKEY) = 0;
    virtual int numKeys() = 0;
    virtual KeyData &key(int index) = 0;
    virtual void delKey(int index) = 0;
};

class EnforcerZone {
public:
    virtual const std::string &name() = 0;
    
    /* Get access to the policy for associated with this zone */
    virtual const kasp::pb::Policy *policy() = 0;

    /* Get access to the list of KeyData entries for this zone. */
    virtual KeyDataList &keyDataList() = 0;

    /* returns true when the signer configuration for the signer should be updated */
    virtual bool signerConfNeedsWriting() = 0;
    
    /* set to true when the signer configuration for the signer needs to  be updated. */
    virtual void setSignerConfNeedsWriting(bool value) = 0;

    /* Called to indicate the zone is going to be modified in the persistent data store. */
    virtual void beginTransaction() = 0;
    
    /* Called to commit any changes made to the zone to the persistent data store. */
    virtual void commitTransaction() = 0;
    
    /* Called to cancel the changes made to the persisten data store. */
    virtual void cancelTransaction() = 0;
    
};

typedef time_t (*update_func_type)(EnforcerZone *zone, time_t now, HsmKeyFactory *keyfactory);

#endif
