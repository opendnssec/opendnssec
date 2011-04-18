#ifndef _ENFORCER_ENFORCERZONE_H_
#define _ENFORCER_ENFORCERZONE_H_

/*
 * PB implemenation of enforcer data to be used as test fixture 
 * and to establish whether the interface is actually complete.
 */

#include <set>
#include "policy/kasp.pb.h"
#include "enforcer/enforcerdata.h"
#include "keystate/keystate.pb.h"

class KeyStatePB : public KeyState {
private:
    ::keystate::pb::KeyState *_keystate;
public:
    KeyStatePB(::keystate::pb::KeyState *keystate);
    
    virtual int state();
    virtual void setState(int value);
    
    virtual int lastChange();
    virtual void setLastChange(int value);

    virtual bool minimize();
    void setMinimize(bool value);
};

class KeyDataPB : public KeyData {
private:
    ::keystate::pb::KeyData *_keydata;
    
    KeyStatePB _keyStateDS;
    KeyStatePB _keyStateRRSIG;
    KeyStatePB _keyStateDNSKEY;
public:
    KeyDataPB( ::keystate::pb::KeyData *keydata );

    bool deleted();
    void setDeleted(bool value);
    
    virtual const std::string &locator();
    virtual void setLocator(const std::string &value);
    
    virtual int algorithm();
    void setAlgorithm(int value);
    
    virtual int inception();
    void setInception(int value);
    
    virtual KeyState &keyStateDS();
    virtual KeyState &keyStateRRSIG();
    virtual KeyState &keyStateDNSKEY();
    
    virtual KeyRole role();
    void setRole(KeyRole value);
    
    virtual bool isDSSeen();
    virtual void setDSSeen(bool value);
    
    virtual bool submitToParent();
    virtual void setSubmitToParent(bool value);

    virtual bool introducing(); /* goal */
    
    /* alternative path */
    virtual bool revoke();
    
    /* selective brakes */
    virtual bool standby();

    virtual void setPublish(bool value);
    virtual void setActive(bool value);
};

class KeyDataListPB : public KeyDataList {
private:
    std::vector<KeyDataPB> _keys;
    ::keystate::pb::EnforcerZone *_zone;
public:
    KeyDataListPB( ::keystate::pb::EnforcerZone *zone);

    virtual KeyData &addNewKey(int algorithm, int inception, KeyRole role,
                               bool minimizeDS, bool minimizeRRSIG, 
                               bool minimizeDNSKEY);
    virtual int numKeys();
    virtual KeyData &key(int index);
    virtual void delKey(int index);
};

class EnforcerZonePB : public EnforcerZone {
private:
    ::keystate::pb::EnforcerZone *_zone;
    const kasp::pb::Policy *_policy;

    KeyDataListPB _keyDataList;
public:
    EnforcerZonePB(::keystate::pb::EnforcerZone *zone, const kasp::pb::Policy *policy);

    /* Get access to the policy for associated with this zone */
    virtual const std::string &name();
    
    /* Get access to the policy for associated with this zone */
    virtual const kasp::pb::Policy *policy();
    
    /* Get access to the list of KeyData entries for this zone. */
    virtual KeyDataList &keyDataList();
    
    /* returns true when the signer configuration for the signer should be updated */
    virtual bool signerConfNeedsWriting();
    
    /* set to true when the signer configuration for the signer needs to  be updated. */
    virtual void setSignerConfNeedsWriting(bool value);

    /* Called to indicate the zone is going to be modified in the persistent data store. */
    virtual void beginTransaction();
    
    /* Called to commit any changes made to the zone to the persistent data store. */
    virtual void commitTransaction();
    
    /* Called to cancel the changes made to the persisten data store. */
    virtual void cancelTransaction();
};

#endif
