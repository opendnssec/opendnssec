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

#include "keystate/zone_export_task.h"
#include "shared/file.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "xmlext-pb/xmlext-wr.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <memory>

#include <fcntl.h>

static const char *module_str = "zone_export_task";

#define ODS_LOG_AND_RETURN(errmsg) do { \
	ods_log_error_and_printf(sockfd,module_str,errmsg); return; } while (0)
#define ODS_LOG_AND_CONTINUE(errmsg) do { \
	ods_log_error_and_printf(sockfd,module_str,errmsg); continue; } while (0)

void 
perform_zone_export(int sockfd, engineconfig_type *config, const char *zone)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // error already reported.
	
	{	OrmTransaction transaction(conn);
		if (!transaction.started())
			ODS_LOG_AND_RETURN("transaction not started");
		
		{	OrmResultRef rows;
			ods::keystate::KeyStateExport kexport;
			
			std::string qzone;
			if (!OrmQuoteStringValue(conn, std::string(zone), qzone))
				ODS_LOG_AND_RETURN("quoting string value failed");
			
			if (!OrmMessageEnumWhere(conn,kexport.zone().descriptor(),
									 rows,"name = %s",qzone.c_str()))
				ODS_LOG_AND_RETURN("message enumeration failed");

			for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
				
				if (!OrmGetMessage(rows, *kexport.mutable_zone(), true))
					ODS_LOG_AND_CONTINUE("reading zone from database failed");

				if (!write_pb_message_to_xml_fd(kexport.mutable_zone(),sockfd))
					ODS_LOG_AND_CONTINUE("writing message to xml file failed");
			}
		}
    }
}
