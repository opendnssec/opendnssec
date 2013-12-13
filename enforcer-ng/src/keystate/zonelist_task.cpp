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

#include <memory>

#include "protobuf-orm/pb-orm.h"
#include "xmlext-pb/xmlext-wr.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/orm.h"
#include "keystate/keystate.pb.h"
#include "keystate/zonelist_task.h"

static const char *module_str = "zonelist_task";

int
perform_zonelist_export(int sockfd, engineconfig_type *config)
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    OrmConnRef conn;
    if (!ods_orm_connect(sockfd, config, conn)) {
        ods_log_error("[%s] connect database failed", module_str);
        return 0; // error already reported.
    }
    
    {   OrmTransaction transaction(conn);
        if (!transaction.started()) {
            ods_log_error("[%s] begin transaction failed", module_str);
            return 0;
        }
    
        {   OrmResultRef rows;
            ::ods::keystate::EnforcerZone enfzone;
            std::auto_ptr< ::ods::keystate::ZoneListDocument > zonelistdoc(
                    new ::ods::keystate::ZoneListDocument );

            bool ok = OrmMessageEnum(conn, enfzone.descriptor(), rows);
            if (!ok) {
                transaction.rollback();
                ods_log_error("[%s] enum enforcer zone failed", module_str);
                return 0;
            }

            for (bool next=OrmFirst(rows); next; next = OrmNext(rows)) {
                 OrmContextRef context;
                 if (!OrmGetMessage(rows, enfzone, true, context)) {
                     rows.release();
                     transaction.rollback();
                     ods_log_error("[%s] retrieving zone from database failed");
                     return 0;
                 }
            
                 std::auto_ptr< ::ods::keystate::ZoneData > zonedata(
                         new ::ods::keystate::ZoneData);
                 zonedata->set_name(enfzone.name());
                 zonedata->set_policy(enfzone.policy());
                 zonedata->set_signer_configuration(
                         enfzone.signconf_path());
                 zonedata->mutable_adapters()->CopyFrom(enfzone.adapters());
                 ::ods::keystate::ZoneData *added_zonedata = zonelistdoc->mutable_zonelist()->add_zones();
                 added_zonedata->CopyFrom(*zonedata);
             }
            
             rows.release();
            
             if (!write_pb_message_to_xml_fd(zonelistdoc.get(), sockfd)) {
                 transaction.rollback();
                 ods_log_error("[%s] writing enforcer zone to xml file failed");
                 return 0;
             }
        }

        if (!transaction.commit()) {
            ods_log_error("[%s] commit transaction failed", module_str);
            return 0;
        }
    }

    return 1;
}
