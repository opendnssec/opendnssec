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

#include "enforcer/hsmkeyfactory.h"

#include "shared/duration.h"
#include "shared/log.h"

static const char * const module_str = "hsmkeyfactory";

//////////////////////////////
// HsmKeyPB
//////////////////////////////

class KeyRef {
public:
	int _refcount;
	::ods::hsmkey::HsmKey *_key;
	KeyRef(::ods::hsmkey::HsmKey *key) : _refcount(1), _key(key) {
	}
	~KeyRef() {
		release();
	}
	KeyRef *retain() {
		_refcount++;
		return this;
	}
	void release() {
		if (this != NULL && _refcount > 0 && --_refcount == 0)
			delete this;
	}
private:
	KeyRef(const KeyRef &);
	void operator=(const KeyRef &);
};


HsmKeyPB::HsmKeyPB(::ods::hsmkey::HsmKey *key)
{
	_keyref = new KeyRef(key);
	_keyref->_refcount = 1;
	_keyref->_key = key;
}

HsmKeyPB::HsmKeyPB(const HsmKeyPB &value) : _keyref(NULL)
{
	if (value._keyref != _keyref) {
		if (_keyref)
			_keyref->release();
		_keyref = value._keyref->retain();
	}
}

HsmKeyPB::~HsmKeyPB()
{
	_keyref->release();
	_keyref = NULL;
}

const std::string &HsmKeyPB::locator()
{ 
    return _keyref->_key->locator();
}

bool HsmKeyPB::candidateForSharing()
{
    return _keyref->_key->candidate_for_sharing();
}

void HsmKeyPB::setCandidateForSharing(bool value)
{
    _keyref->_key->set_candidate_for_sharing(value);
}

int HsmKeyPB::bits()
{
    return _keyref->_key->bits();
}

void HsmKeyPB::setBits(int value)
{
    _keyref->_key->set_bits(value);
}

const std::string &HsmKeyPB::policy()
{
    return _keyref->_key->policy();
}

void HsmKeyPB::setPolicy(const std::string &value) 
{
    _keyref->_key->set_policy(value);
}

int HsmKeyPB::algorithm()
{
    return _keyref->_key->algorithm();
}

void HsmKeyPB::setAlgorithm(int value)
{
    _keyref->_key->set_algorithm(value);
}


KeyRole HsmKeyPB::keyRole()
{
    return (KeyRole)_keyref->_key->role();
}

void HsmKeyPB::setKeyRole(KeyRole value)
{
    if (::ods::hsmkey::keyrole_IsValid(value))
        _keyref->_key->set_role( (::ods::hsmkey::keyrole)value );
    else {
        ods_log_error("[%s] %d is not a valid keyrole value",
                      module_str,value);
    }
}

bool HsmKeyPB::usedByZone(const std::string &zone)
{
    ::google::protobuf::RepeatedPtrField< ::std::string>::iterator it;
    ::google::protobuf::RepeatedPtrField< ::std::string>*ubz = 
        _keyref->_key->mutable_used_by_zones();
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
        _keyref->_key->mutable_used_by_zones();
    for (int z=0; z<_keyref->_key->used_by_zones_size(); ++z) {
        if (_keyref->_key->used_by_zones(z) == zone) {
            if (!bValue) {
                ubz->SwapElements(z,_keyref->_key->used_by_zones_size()-1);
                ubz->RemoveLast();
            }
            return;
        }
    }
    if (bValue)
        _keyref->_key->add_used_by_zones(zone);
}

time_t HsmKeyPB::inception()
{
    return _keyref->_key->inception();
}

void HsmKeyPB::setInception(time_t value)
{
    _keyref->_key->set_inception(value);
}

bool HsmKeyPB::revoke()
{
    return _keyref->_key->revoke();
}

void HsmKeyPB::setRevoke(bool value)
{
    _keyref->_key->set_revoke(value);
}

const std::string &HsmKeyPB::repository()
{
    return _keyref->_key->repository();
}

bool HsmKeyPB::backedup()
{
    return _keyref->_key->backedup();
}

bool HsmKeyPB::requirebackup()
{
    return _keyref->_key->requirebackup();
}

//////////////////////////////
// HsmKeyFactoryPB
//////////////////////////////

HsmKeyFactoryPB::HsmKeyFactoryPB(OrmConn conn,
                                 HsmKeyFactoryDelegatePB *delegate)
: _conn(conn), _delegate(delegate)
{
}

/* Create a new key with the specified number of bits (or retrieve it 
 from a pre-generated keypool)  */
bool HsmKeyFactoryPB::CreateNewKey(int bits, const std::string &repository,
                                   const std::string &policy, int algorithm,
                                   KeyRole role,
                                   HsmKey **ppKey)
{
#if 0
	// perform retrieval and update of a hsm key inside a single transaction.
	OrmTransactionRW transaction(_conn);
	if (!transaction.started())
		return false;
#endif
	
    // Find keys that are available and match exactly with the given parameters.
	{	OrmResultRef rows;
		if (!OrmMessageEnumWhere(_conn, ::ods::hsmkey::HsmKey::descriptor(),
								 rows, "inception IS NULL"))
			return false;

		::ods::hsmkey::HsmKey *pbkey = new ::ods::hsmkey::HsmKey;
		
		for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
			OrmContextRef context;
			if (OrmGetMessage(rows, *pbkey, true, context)) {
				if (!pbkey->has_inception() 
					&& pbkey->bits() == bits
					&& pbkey->repository() == repository
					&& pbkey->policy() == policy
					&& pbkey->algorithm() == algorithm
					&& pbkey->role() == (::ods::hsmkey::keyrole)role
					)
				{
					// found a candidate, so we no longer need the rows
					rows.release();

					pbkey->set_inception(time_now());
					HsmKeyPB pbkey_ref(pbkey);
					
					// Fixate unset attributes that returned their default value.
					// Otherwise when we list the keys those values will show 
					// up as 'not set'
					if (!pbkey->has_policy())
						pbkey_ref.setPolicy(policy);
					if (!pbkey->has_algorithm())
						pbkey_ref.setAlgorithm(algorithm);
					if (!pbkey->has_role())
						pbkey_ref.setKeyRole(role);
					
					pbkey = NULL;

					// We have modified the key and need to update it.
					if (!OrmMessageUpdate(context)) 
						return false;
#if 0
					if (!transaction.commit())
						return false;
#endif
					std::pair<std::map<std::string,HsmKeyPB>::iterator,bool> ret;
					ret = _keys.insert(std::pair<std::string,HsmKeyPB>(
										pbkey_ref.locator(),pbkey_ref));
					*ppKey = &ret.first->second;
					return true;
				}
			}
		}

		delete pbkey;
    }

#if 0
	// explicit rollback not strictly needed as it's the default action.
	// but we want to be sure to leave the transaction before we start calling 
	// callbacks on our delegate.
	transaction.rollback(); 
#endif
	
    // We were not able to find any suitable key, give up.
    if (_delegate)
        _delegate->OnKeyShortage(bits,repository,policy,algorithm,role);
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
	OrmResultRef rows;
	if (OrmMessageEnum(_conn, ::ods::hsmkey::HsmKey::descriptor(), rows)) {

		::ods::hsmkey::HsmKey *pbkey = NULL;

		for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
			
			if (!pbkey)
				pbkey = new ::ods::hsmkey::HsmKey;
			
			if (OrmGetMessage(rows, *pbkey, true)) {
				if (pbkey->locator() == loc) {
					std::pair<std::map<std::string,HsmKeyPB>::iterator,bool> ret;
					ret = _keys.insert(
						std::pair<std::string,HsmKeyPB>(loc,HsmKeyPB(pbkey)) );
					pbkey = NULL;
					*ppKey = &ret.first->second;
					return true;
				}
			}
		}

		if (pbkey)
			delete pbkey;
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


#if 0
	// All the database access has to be done within a single transaction
	OrmTransactionRW trans(_conn);
#endif
	
    // Now enumerate keys in the document try to find a key that matches the
    // parameters exactly and is not yet present in the _keys vector field.
	OrmResultRef rows;
	if (OrmMessageEnum(_conn, ::ods::hsmkey::HsmKey::descriptor(), rows)) {

		::ods::hsmkey::HsmKey *pbkey = NULL;
		
		for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {

			if (!pbkey)
				pbkey = new ::ods::hsmkey::HsmKey;
			
			OrmContextRef context;
			if (OrmGetMessage(rows, *pbkey, true, context)) {
				if (pbkey->has_inception()
					&& pbkey->bits() == bits
					&& pbkey->repository() == repository
					&& pbkey->policy() == policy
					&& pbkey->algorithm() == algorithm
					&& pbkey->role() == (::ods::hsmkey::keyrole)role
					)
				{
					pbkey->set_inception(time_now());
					HsmKeyPB pbkey_ref(pbkey);
					
					
					// Fixate unset attributes that returned their default value.
					// Otherwise when we list the keys those values will show 
					// up as 'not set'
					if (!pbkey->has_policy())
						pbkey_ref.setPolicy(policy);
					if (!pbkey->has_algorithm())
						pbkey_ref.setAlgorithm(algorithm);
					if (!pbkey->has_role())
						pbkey_ref.setKeyRole(role);

					pbkey = NULL;
					
					// We have modified the key and need to update it.
					if (OrmMessageUpdate(context)) {
						
						// we won't be needing the result anymore, so release it
						rows.release();
#if 0
						// now more active queries, so commit should work.
						if (trans.commit()) {
#endif
							std::pair<std::map<std::string,HsmKeyPB>::iterator,bool> ret;
							ret = _keys.insert(std::pair<std::string,HsmKeyPB>(
												pbkey_ref.locator(),pbkey_ref));
							*ppKey = &ret.first->second;
							(*ppKey)->setUsedByZone(zone,true);
							return true;
#if 0
						}
#endif
					}
				}
			}
		}

		if (pbkey)
			delete pbkey;

		rows.release();
		
    }

#if 0	
	// transaction rolback is default, but we make it explicit here.
	trans.rollback();
#endif
	
    return false;
}
