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

#include "hsmkey/hsmkey_list_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "shared/str.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include <fcntl.h>

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

static const char *module_str = "hsmkey_list_task";

void 
perform_hsmkey_list(int sockfd, engineconfig_type *config, int bVerbose)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    // Load the current list of pre-generated keys

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // errors have already been reported.
	
    if (!bVerbose){
        ods_printf(sockfd,
                       "HSM keys:\n"
                       "Id:                                      "
                       "Key type:  "
                       "Bits:   "
                       "Repository:  "
                       "First use:                 "
                       "\n"
                       );
    } else {
        ods_printf(sockfd,
                       "HSM keys:\n"
                       "Id:                                      "
                       "Key type:  "
                       "Bits:   "
                       "Repository:  "
                       "First use:                 "
                       "Key role:   "
                       "Algorithm : "
                       "Policy :                        "
                       "\n"
                       );
    }

	{	OrmTransaction transaction(conn);
		
		if (!transaction.started()) {
			ods_printf(sockfd,"error: database transaction failed\n");
			return;
		}
			
		{	OrmResultRef rows;

			if (!OrmMessageEnum(conn, ::ods::hsmkey::HsmKey::descriptor(), rows)) {
				ods_printf(sockfd,"error: database hsm key enumeration failed\n");
				return;
			}
			
			// Enumerate the hsm keys referenced in the database
			for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
				::ods::hsmkey::HsmKey key;
				if (OrmGetMessage(rows, key, true)) {
					std::string ktype  = key.key_type();
					uint32_t bits = key.bits();
					std::string loca = key.locator();
					std::string repo = key.repository();
					char incep[32];
					if (key.inception() != 0) {
						if (!ods_ctime_r(incep,sizeof(incep),key.inception())) {
							strncpy(incep,"invalid date/time",sizeof(incep));
							incep[sizeof(incep)-1] = '\0';
						}
					} else {
						strncpy(incep,"never",sizeof(incep));
						incep[sizeof(incep)-1] = '\0';
					}
					
					char keyalgo[32];
					if (key.has_algorithm()) {
						snprintf(keyalgo,sizeof(keyalgo),"%d",key.algorithm());
					} else {
						strncpy(keyalgo,"not set",sizeof(keyalgo));
					}
					keyalgo[sizeof(keyalgo)-1] = '\0';
					
					std::string role;
					if ( key.has_role() )
						role.assign( ::ods::hsmkey::keyrole_Name(key.role()) );
					else
						role.assign("not set");
					
					
					std::string polic;
					if ( key.has_policy() )
						polic.assign( key.policy() );
					else
						polic.assign("not set");
					
					if (!bVerbose) {
						ods_printf(sockfd,
									   "%-40s %-10s %-7u %-12s %-26s\n",
									   loca.c_str(),ktype.c_str(),bits,repo.c_str(),incep);
					} else {
						ods_printf(sockfd,
									   "%-40s %-10s %-7u %-12s %-26s %-11s %-11s %-31s\n",
									   loca.c_str(),ktype.c_str(),bits,repo.c_str(),incep,
									   role.c_str(),keyalgo,polic.c_str());
					}
				}
			}
		}
	}
}
