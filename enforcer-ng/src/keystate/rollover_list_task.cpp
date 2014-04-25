/*
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

#include "keystate/rollover_list_task.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "daemon/clientpipe.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <fcntl.h>

static const char *module_str = "keystate_list_task";
using ::ods::keystate::EnforcerZone;
using ::ods::keystate::KeyData;

/** Time of next transition. Caller responsible for freeing ret
 * @param zone: zone key belongs to
 * @param key: key to evaluate
 * @return: human readable transition time/event */
static char*
map_keytime(const EnforcerZone zone, const KeyData key)
{
	enum {DS_NSUB = 0, DS_SUBM, DS_SBMD, DS_SEEN, DS_RETR, DS_RTRD};
	switch(key.ds_at_parent()) {
		case DS_SUBM: return strdup("waiting for ds-submit");
		case DS_SBMD: return strdup("waiting for ds-seen");
		case DS_RETR: return strdup("waiting for ds-retract");
		case DS_RTRD: return strdup("waiting for ds-gone");
	}

	enum {KSK = 1, ZSK, CSK};
	time_t t;
	switch (key.role()) {
		case KSK: t = zone.next_ksk_roll(); break;
		case ZSK: t = zone.next_zsk_roll(); break;
		case CSK: t = zone.next_csk_roll(); break;
	}
	if (!t) return strdup("No roll scheduled");
	
	char ct[26];
	struct tm srtm;
	localtime_r(&t, &srtm);
	strftime(ct, 26, "%Y-%m-%d %H:%M:%S", &srtm);
	return strdup(ct);
}

int 
perform_rollover_list(int sockfd, engineconfig_type *config, const char *listed_zone)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	EnforcerZone zone;
	OrmResultRef rows;
	const char* fmt = "%-31s %-8s %-30s\n";

	if (!ods_orm_connect(sockfd, config, conn)) return 1;
	OrmTransaction transaction(conn);
	if (!OrmMessageEnum(conn, zone.descriptor(), rows)) {
		ods_log_error("[%s] error enumerating zones", module_str);
		client_printf(sockfd, "error enumerating zones\n");
		return 1;
	}
	
    if (NULL == listed_zone || 0 == strlen(listed_zone)) {
        if (!OrmMessageEnum(conn, zone.descriptor(), rows)) {
            ods_log_error("[%s] error enumerating zones", module_str);
            client_printf(sockfd, "error enumerating zones\n");
            return 1;
        }
    }
    else {
        std::string qzone;
        if (!OrmQuoteStringValue(conn, std::string(listed_zone), qzone)) {
            const char *emsg = "quoting zone value failed";
            ods_log_error_and_printf(sockfd,module_str,emsg);
            return 1;
        }

        if (!OrmMessageEnumWhere(conn, 
                    zone.descriptor(),
                    rows,
                    "name = %s",
                    qzone.c_str())) {
            ods_log_error("[%s] unable to find zone:%s", 
                    module_str, qzone.c_str());
            client_printf(sockfd, "unable to find zone:%s\n", qzone.c_str());
            return 1;
        }

        if (!OrmFirst(rows)) {
            ods_log_error("[%s] zone:%s not found", 
                    module_str, qzone.c_str());
            client_printf(sockfd, "zone:%s not found\n", qzone.c_str());
            return 1;
        }
    }	
	
	
	client_printf(sockfd, "Keys:\n");
	client_printf(sockfd, fmt, "Zone:", "Keytype:", "Rollover expected:");
	for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
		if (!OrmGetMessage(rows, zone, true)) {
			ods_log_error("[%s] error reading zone", module_str);
			client_printf(sockfd, "error reading zone\n");
			return 1;
		}
		for (int k=0; k<zone.keys_size(); ++k) {
			const KeyData &key = zone.keys(k);
			char* tchange = map_keytime(zone, key);
			client_printf(sockfd, fmt, zone.name().c_str(),
				keyrole_Name(key.role()).c_str(), tchange);
			free(tchange);
		}
	}
	return 0;
}
