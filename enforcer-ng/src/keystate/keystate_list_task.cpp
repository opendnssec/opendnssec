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

#include "keystate/keystate_list_task.h"
#include "shared/file.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <fcntl.h>

static const char *module_str = "keystate_list_task";

void 
perform_keystate_list(int sockfd, engineconfig_type *config, int bverbose)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // error already reported.
	
	{	OrmTransaction transaction(conn);
		if (!transaction.started()) {
			ods_log_error("[%s] Could not start database transaction", module_str);
			ods_printf(sockfd, "error: Could not start database transaction\n");
			return;
		}
		
		::ods::keystate::EnforcerZone zone;
		
		{	OrmResultRef rows;
			if (!OrmMessageEnum(conn, zone.descriptor(),rows)) {
				ods_log_error("[%s] error enumerating zones", module_str);
				ods_printf(sockfd, "error enumerating zones\n");
				return;
			}
			
			ods_printf(sockfd,
					   "Database set to: %s\n"
					   "Keys:\n"
					   "Zone:                           "
					   "Key role:     "
					   "DS:          "
					   "DNSKEY:      "
					   "RRSIGDNSKEY: "
					   "RRSIG:       "
					   "Pub: "
					   "Act: "
					   "Id:"
					   "\n"
					   ,config->datastore
					   );

			for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
				
				if (!OrmGetMessage(rows, zone, true)) {
					ods_log_error("[%s] error reading zone", module_str);
					ods_printf(sockfd, "error reading zone\n");
					return;
				}
					
				for (int k=0; k<zone.keys_size(); ++k) {
					const ::ods::keystate::KeyData &key = zone.keys(k);
					std::string keyrole = keyrole_Name(key.role());
					std::string ds_rrstate = rrstate_Name(key.ds().state());
					std::string dnskey_rrstate = rrstate_Name(key.dnskey().state());
					std::string rrsigdnskey_rrstate = rrstate_Name(key.rrsigdnskey().state());
					std::string rrsig_rrstate = rrstate_Name(key.rrsig().state());
					ods_printf(sockfd, 
							   "%-31s %-13s %-12s %-12s %-12s %-12s %d %4d    %s\n",
							   zone.name().c_str(),
							   keyrole.c_str(),
							   ds_rrstate.c_str(),
							   dnskey_rrstate.c_str(),
							   rrsigdnskey_rrstate.c_str(),
							   rrsig_rrstate.c_str(),
							   key.publish(),
							   key.active_ksk()||key.active_zsk(),
							   key.locator().c_str()
							   );
				}
			}
		}
    }
}

