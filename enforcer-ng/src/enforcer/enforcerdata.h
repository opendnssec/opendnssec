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

#ifndef _ENFORCER_ENFORCERDATA_H_
#define _ENFORCER_ENFORCERDATA_H_

#include <ctime>

#include "policy/kasp.pb.h"

enum KeyRole { KSK=1, ZSK, CSK };
#undef DS /* DS is defined somewhere on SunOS 5.10 and breaks this enum */
enum RECORD {REC_MIN, DS = REC_MIN, DK, RD, RS, REC_MAX};
enum DsAtParent { 
    DS_UNSUBMITTED = 0,
    DS_SUBMIT,
    DS_SUBMITTED,
    DS_SEEN,
    DS_RETRACT,
    DS_RETRACTED
};

class HsmKey {
public:
	HsmKey() {}
	virtual ~HsmKey() {}
	
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

    virtual time_t inception() = 0;
    virtual void setInception(time_t value) = 0;
    
    virtual bool revoke() = 0;
    virtual void setRevoke(bool value) = 0;
    
    virtual const std::string &repository() = 0;
    
    virtual bool backedup() = 0;
    virtual bool requirebackup() = 0;
	
private:
	HsmKey(const HsmKey &);
	void operator=(const HsmKey &);
};


/**
 * Get access to the pool of keys (pre-)generated and stored in a HSM 
 * The enforcer uses this factory to get fresh keys to be used as KSK 
 * or ZSK in the zone.
 */

class HsmKeyFactory {
public:
    /* Create a new key with the specified number of bits (or retrieve it 
     from a pre-generated keypool)
    * \param[in] bits number of bits in the key
    * \param[in] repository name of the HSM where the key should reside
    * \param[in] policy name of the policy
    * \param[in] algorithm algorithm
    * \param[in] role role of the key
    * \return bool true when the key was created or false when it failed.
    */
    virtual bool CreateNewKey(int bits, const std::string &repository,
                              const std::string &policy, int algorithm,
                              KeyRole role,
                              HsmKey **ppKey) = 0;
    
    /* Create a key shared by all the zones with the given policy name, 
     * algorithm and bits
     *
     * The HsmKey will have setUsedByZone(zone,true) called for the zone that 
     * is passed in. Also setInception(now) will be called for the HsmKey 
     * before it is returned
     *
     * \param[in] bits number of bits in the key
     * \param[in] repository name of the HSM where the key should reside
     * \param[in] policy name of the policy
     * \param[in] algorithm algorithm
     * \param[in] role role of the key
     * \param[in] zone zone the key is going to be used in.
     * \return bool true when the key was created or false when it failed.
     */
    virtual bool CreateSharedKey(int bits, const std::string &repository,
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
     * \param[in] repository name of the HSM where the key should reside
     * \param[in] policy name of the policy to match
     * \param[in] algorithm algorithm to match
     * \param[in] role role of the key to match
     * \param[in] zone zone the key is going to be used in.
     * \param[out] ppKey key that matches the search criteria
     * \return bool returns true when a match was found or false when no
     *              match was found.
     */
    virtual bool UseSharedKey(int bits, const std::string &repository,
                              const std::string &policy, int algorithm,
                              KeyRole role, const std::string &zone,
                              HsmKey **ppKey) = 0;

    /* Find existing HsmKey based on locator.
     * 
     * \param[in] loc locator to search for
     * \param[out] ppKey key that matches the search criteria
     * \return bool returns true when a match was found or false when no
     *              match was found.
     */
    virtual bool GetHsmKeyByLocator(const std::string loc, 
                                    HsmKey **ppKey) = 0;
};

class KeyState {
public:
    virtual int state() = 0;
    virtual void setState(int value) = 0;

    virtual int lastChange() = 0;
    virtual void setLastChange(int value) = 0;

    virtual int ttl() = 0;
    virtual void setTtl(int value) = 0;
    
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
    virtual time_t inception() = 0;
    
    virtual KeyState &keyStateDS() = 0;
    virtual KeyState &keyStateRRSIG() = 0;
    virtual KeyState &keyStateDNSKEY() = 0;
    virtual KeyState &keyStateRRSIGDNSKEY() = 0;

    /* Movement direction, efault true */
    virtual bool introducing() = 0; /* goal */
    virtual void setIntroducing(bool value) = 0;
    
    /* selective brakes */
    virtual bool standby() = 0;
    
    virtual void setPublish(bool value) = 0;
    virtual void setActiveZSK(bool value) = 0;
    virtual void setActiveKSK(bool value) = 0;
    
    virtual void setDsAtParent(DsAtParent value) = 0;
    virtual DsAtParent dsAtParent() = 0;
};

class KeyDataList {
public:
    virtual KeyData &addNewKey(int algorithm, time_t inception, KeyRole role,
                               int minimize) = 0;
    virtual int numKeys() = 0;
    virtual KeyData &key(int index) = 0;
    virtual void delKey(int index) = 0;
};

class KeyDependency {
public:
    virtual const std::string &toKey() = 0;
    virtual const std::string &fromKey() = 0;
    virtual RECORD rrType() = 0;
};

class KeyDependencyList {
public:
    virtual int numDeps() = 0;
    virtual KeyDependency &dep(int index) = 0;
	virtual KeyDependency &addNewDependency(
			KeyData *from_key, 
			KeyData *to_key, RECORD record) = 0;
	/* Delete all dependencies to and from this key for recordtype */
	virtual void delDependency( KeyData *key, RECORD record) = 0;
	virtual void delDependency( KeyData *key) = 0;
};

class EnforcerZone {
public:
    virtual const std::string &name() = 0;
    
    /* Get access to the policy for associated with this zone */
    virtual const ::ods::kasp::Policy *policy() = 0;

    /* Get access to the list of KeyDependency entries for this zone. */
    virtual KeyDependencyList &keyDependencyList() = 0;
    
    /* Get access to the list of KeyData entries for this zone. */
    virtual KeyDataList &keyDataList() = 0;

    /* returns true when the signer configuration for the signer should be updated */
    virtual bool signerConfNeedsWriting() = 0;
    
    /* set to true when the signer configuration for the signer needs to  be updated. */
    virtual void setSignerConfNeedsWriting(bool value) = 0;
    
    /* Moment at which current TTL becomes effective */
    virtual time_t ttlEnddateDs() = 0;
    virtual void setTtlEnddateDs(time_t value) = 0;
    virtual time_t ttlEnddateDk() = 0;
    virtual void setTtlEnddateDk(time_t value) = 0;
    virtual time_t ttlEnddateRs() = 0;
    virtual void setTtlEnddateRs(time_t value) = 0;
    
    /* True if user indicated role must be rolled, only applicable
     * if policy states we must do manual rollover for that role. */
    virtual bool rollKskNow() = 0;
    virtual void setRollKskNow(bool value) = 0;
    virtual bool rollZskNow() = 0;
    virtual void setRollZskNow(bool value) = 0;
    virtual bool rollCskNow() = 0;
    virtual void setRollCskNow(bool value) = 0;
};

typedef time_t (*update_func_type)(EnforcerZone *zone, time_t now, HsmKeyFactory *keyfactory);

#endif
