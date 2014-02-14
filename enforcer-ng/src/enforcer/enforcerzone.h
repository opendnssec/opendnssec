/*
 * $Id$
 *
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

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
    ::ods::keystate::KeyState *_keystate;
public:
    KeyStatePB(::ods::keystate::KeyState *keystate);
    
    virtual int state();
    virtual void setState(int value);
    
    virtual int lastChange();
    virtual void setLastChange(int value);

    virtual int ttl();
    virtual void setTtl(int value);

    virtual bool minimize();
    void setMinimize(bool value);
};

class KeyDataPB : public KeyData {
private:
    ::ods::keystate::KeyData *_keydata;
    
    KeyStatePB _keyStateDS;
    KeyStatePB _keyStateRRSIG;
    KeyStatePB _keyStateDNSKEY;
    KeyStatePB _keyStateRRSIGDNSKEY;
public:
    KeyDataPB( ::ods::keystate::KeyData *keydata );
    bool matches( const ::ods::keystate::KeyData *keydata );

    virtual const std::string &locator();
    virtual void setLocator(const std::string &value);
    
    virtual int algorithm();
    void setAlgorithm(int value);
    
    virtual time_t inception();
    void setInception(time_t value);
    
    virtual KeyState &keyStateDS();
    virtual KeyState &keyStateRRSIG();
    virtual KeyState &keyStateDNSKEY();
    virtual KeyState &keyStateRRSIGDNSKEY();
    
    virtual KeyRole role();
    void setRole(KeyRole value);
    
    virtual bool introducing(); /* goal */
    virtual void setIntroducing(bool value);
    
    /* alternative path */
    virtual bool revoke();
    
    /* selective brakes */
    virtual bool standby();

    virtual void setPublish(bool value);
    virtual void setActiveZSK(bool value);
    virtual void setActiveKSK(bool value);
    
    /* Current state of the DS record at the parent */
    virtual DsAtParent dsAtParent();
    virtual void setDsAtParent(DsAtParent value);
    
    virtual uint16_t keytag();
    virtual void setKeytag(uint16_t value);
};

class KeyDataListPB : public KeyDataList {
private:
    std::vector<KeyDataPB> _keys;
    ::ods::keystate::EnforcerZone *_zone;
public:
    KeyDataListPB( ::ods::keystate::EnforcerZone *zone);

    virtual KeyData &addNewKey(int algorithm, time_t inception, KeyRole role,
                               int minimize);
    virtual int numKeys();
    virtual KeyData &key(int index);
    virtual void delKey(int index);
};

class KeyDependencyPB : public KeyDependency {
private:
    ::ods::keystate::KeyDependency *_keydependency;
public:
    KeyDependencyPB( ::ods::keystate::KeyDependency *keydependency);
    
    virtual void setToKey(KeyData *key);
    virtual void setFromKey(KeyData *key);
    virtual void setRRType(RECORD record);
    virtual const std::string &toKey();
    virtual const std::string &fromKey();
    virtual RECORD rrType();
};

class KeyDependencyListPB : public KeyDependencyList {
private:
    std::vector<KeyDependencyPB> _deps;
    ::ods::keystate::EnforcerZone *_zone;
public:
    virtual int numDeps();
    virtual KeyDependency &dep(int index);
	/** List of all key dependencies in this zone */
    KeyDependencyListPB( ::ods::keystate::EnforcerZone *zone );
    
    virtual KeyDependency &addNewDependency(
			KeyData *from_key, 
			KeyData *to_key, RECORD record);
    virtual void delDependency( KeyData *key, RECORD record);
    virtual void delDependency( KeyData *key);
};

class EnforcerZonePB : public EnforcerZone {
private:
    ::ods::keystate::EnforcerZone *_zone;
    ::ods::kasp::Policy _policy;

    KeyDataListPB _keyDataList;
    KeyDependencyListPB _keyDependencyList;
public:
    EnforcerZonePB(::ods::keystate::EnforcerZone *zone, const ::ods::kasp::Policy &policy);

    /* Get access to the policy for associated with this zone */
    virtual const std::string &name();
    
    /* Get access to the policy for associated with this zone */
    virtual const ::ods::kasp::Policy *policy();
    /* TTL we must take in to account when rolling wrt signatures. 
     * defined as max( MaxZoneTTL, Nsec3ParamTTL ) */
    virtual int max_zone_ttl();
    
    /* Get access to the list of KeyDependency entries for this zone. */
    virtual KeyDependencyList &keyDependencyList();
    
    /* Get access to the list of KeyData entries for this zone. */
    virtual KeyDataList &keyDataList();
    
    /* returns true when the signer configuration for the signer should be updated */
    virtual bool signerConfNeedsWriting();
    
    /* set to true when the signer configuration for the signer needs to  be updated. */
    virtual void setSignerConfNeedsWriting(bool value);
    
    /* When the key states in this zone are expected to change state. */
    void setNextChange(time_t value);

    /* Moment at which current TTL becomes effective */
    virtual time_t ttlEnddateDs();
    virtual void setTtlEnddateDs(time_t value);
    virtual time_t ttlEnddateDk();
    virtual void setTtlEnddateDk(time_t value);
    virtual time_t ttlEnddateRs();
    virtual void setTtlEnddateRs(time_t value);
    
    virtual bool rollKskNow();
    virtual void setRollKskNow(bool value);
    virtual bool rollZskNow();
    virtual void setRollZskNow(bool value);
    virtual bool rollCskNow();
    virtual void setRollCskNow(bool value);
    
    /* Only used to show the user */
    virtual time_t nextKskRoll();
    virtual time_t nextZskRoll();
    virtual time_t nextCskRoll();
    virtual void setNextKskRoll(time_t value);
    virtual void setNextZskRoll(time_t value);
    virtual void setNextCskRoll(time_t value);
};

#endif
