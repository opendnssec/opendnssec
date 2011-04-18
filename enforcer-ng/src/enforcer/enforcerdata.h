#ifndef _ENFORCER_ENFORCERDATA_H_
#define _ENFORCER_ENFORCERDATA_H_

#include "policy/kasp.pb.h"

enum KeyRole { KSK=1, ZSK, CSK };

class HsmKey {
public:
    virtual const std::string &locator() = 0;

    /* When looking for a shared key, this flag determines whether the 
     * key is a suitable candidate for being used as a shared key.
     */
    virtual bool candidateForSharing() = 0;
    
    /* Set this flag to false to indicate that this key should no longer 
     * be considered when looking for a uitable candidate for a shared key.
     * Note that setting this flag does not prevent the key from being shared 
     * it only influences the search for a shared key.
     */
    virtual void setCandidateForSharing(bool value) = 0;
    

    virtual int bits() = 0;
    virtual void setBits(int value) = 0;
    
    virtual const std::string &policy() = 0;
    virtual void setPolicy(const std::string &value) = 0;
    
    virtual int algorithm() = 0;
    virtual void setAlgorithm(int value) = 0;

    virtual KeyRole keyRole() = 0;
    virtual void setKeyRole(KeyRole value) = 0;
    
    virtual bool usedByZone(const std::string &zone) = 0;
    virtual void setUsedByZone(const std::string &zone, bool bValue) = 0;

    virtual int inception() = 0;
    virtual void setInception(int value) = 0;
    
    virtual bool revoke() = 0;
    virtual void setRevoke(bool value) = 0;

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
     *
     * The HsmKey will have setUsedByZone(zone,true) called for the zone that 
     * is passed in. Also setInception(now) will be called for the HsmKey 
     * before it is returned
     *
     * \param[in] bits number of bits in the key
     * \param[in] policy name of the policy
     * \param[in] algorithm algorithm
     * \param[in] role role of the key
     * \param[in] zone zone the key is going to be used in.
     * \return bool true when the key was created or false when it failed.
     */
    virtual bool CreateSharedKey(int bits,
                                 const std::string &policy, int algorithm,
                                 KeyRole role, const std::string &zone,
                                 HsmKey **ppKey) = 0;

    /* Find and re-use an existing HsmKey based on the arguments passed in.
     *
     * The HsmKeys that will be considered for sharing need to have 
     * the candidateForSharing flag set. 
     * For the zone that is passed in, a HsmKey that is already being used 
     * by that zone will not be considered.
     *
     * When this member function finds a shared key this method will 
     * automatically call setUsedByZone(zone,true) on the HsmKey that 
     * is returned.
     *
     * \param[in] bits number of bits to match
     * \param[in] policy name of the policy to match
     * \param[in] algorithm algorithm to match
     * \param[in] role role of the key to match
     * \param[in] zone zone the key is going to be used in.
     * \param[out] ppKey key that matches the search criteria
     * \return bool returns true when a match was found or false when no
     *              match was found.
     */
    virtual bool UseSharedKey(int bits,
                              const std::string &policy, int algorithm,
                              KeyRole role, const std::string &zone,
                              HsmKey **ppKey) = 0;
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
    
    /* identical to algorithm property on associated HsmKey */
    virtual int algorithm() = 0;
    
    virtual KeyRole role() = 0;
    
    /* alternative path */
    virtual bool revoke() = 0;
    
    /* KeyData inception indicates the moment of first use in this 
     * zone of the HsmKey. The inception found on the HsmKey associated
     * with this KeyData via the locator will be the same as this inception
     * on a non-shared key. However on a shared key the inception on the
     * HsmKey may be earlier as it may have been used previously in 
     * a different zone.
     */
    virtual int inception() = 0;
    
    virtual KeyState &keyStateDS() = 0;
    virtual KeyState &keyStateRRSIG() = 0;
    virtual KeyState &keyStateDNSKEY() = 0;

    virtual bool isDSSeen() = 0;
    virtual void setDSSeen(bool value) = 0;
    
    virtual bool submitToParent() = 0;
    virtual void setSubmitToParent(bool value) = 0;

    /* Movement direction */
    virtual bool introducing() = 0; /* goal */
    
    /* selective brakes */
    virtual bool standby() = 0;
    
    virtual void setPublish(bool value) = 0;
    virtual void setActive(bool value) = 0;
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
