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

#ifndef _ENFORCER_HSMKEYFACTORY_H_
#define _ENFORCER_HSMKEYFACTORY_H_

/*
 * Dummy implemenation of enforcer data to be used as test fixture 
 * and to establish whether the interface is actually complete.
 */

#include <map>
#include "shared/log.h"
#include "enforcer/enforcerdata.h"
#include "hsmkey/hsmkey.pb.h"
#include "protobuf-orm/pb-orm.h"

class KeyRef;

class HsmKeyPB : public HsmKey {
private:
	KeyRef *_keyref;
	
public:
    HsmKeyPB(::ods::hsmkey::HsmKey *key);
	HsmKeyPB(const HsmKeyPB &value);
    virtual ~HsmKeyPB();
	
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
    
    virtual bool backedup();
    virtual bool requirebackup();

private:
	void operator=(const HsmKeyPB &);
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
    OrmConn _conn;
    std::map<std::string,HsmKeyPB> _keys;
    HsmKeyFactoryDelegatePB *_delegate;
    
public:
    HsmKeyFactoryPB(OrmConn conn,
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
