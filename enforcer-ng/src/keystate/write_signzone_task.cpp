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
#include <string>

#include "protobuf-orm/pb-orm.h"
#include "xmlext-pb/xmlext-wr.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/orm.h"
//#include "config.h"
#include "keystate/keystate.pb.h"
#include "keystate/write_signzone_task.h"

static const char *module_str = "write_signzone_task";

static int write_empty_signzones_file(const std::string &file_name);

int
perform_write_signzone_file(int sockfd, engineconfig_type *config)
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    OrmConnRef conn;
    if (!ods_orm_connect(sockfd, config, conn)) {
        ods_log_error("[%s] connect database failed", module_str);
        return 0; // error already reported.
    }

    std::auto_ptr< ::ods::keystate::ZoneListDocument > zonelistdoc(
                new ::ods::keystate::ZoneListDocument );
    
    {   OrmTransaction transaction(conn);
        if (!transaction.started()) {
            ods_log_error("[%s] begin transaction failed", module_str);
            return 0;
        }
    
        {   OrmResultRef rows;
            ::ods::keystate::EnforcerZone enfzone;

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
                 ::ods::keystate::ZoneData *added_zonedata = 
                     zonelistdoc->mutable_zonelist()->add_zones();
                 added_zonedata->CopyFrom(*zonedata);
             }
            
             rows.release();

        }

        if (!transaction.commit()) {
            ods_log_error("[%s] commit transaction failed", module_str);
            return 0;
        }
    }

    //write signzone file
    std::string signzone_file(OPENDNSSEC_STATE_DIR);
    signzone_file.append("/signconf/signzones.xml");
    std::string tmp_signzone_file(signzone_file);
    tmp_signzone_file.append(".bak");
    if (zonelistdoc.get()->has_zonelist() && 
            (zonelistdoc.get()->mutable_zonelist()->zones_size() > 0)) {
        if (!write_pb_message_to_xml_file(zonelistdoc.get(), tmp_signzone_file.c_str())) {
            ods_log_error("[%s] failed to write signzones.xml.bak", module_str);
            return 0;
        }
    }
    else {
        //write empty zonelistdoc
        if (!write_empty_signzones_file(tmp_signzone_file)) {
            ods_log_error("[%s] failed to write empty signzones.xml.bak", module_str);
            return 0;
        }
    }

    if (rename(tmp_signzone_file.c_str(), signzone_file.c_str())) {
        ods_log_error("[%s] failed to rename signzones.xml", module_str);
        return 0;
    }

    return 1;
}

static int
write_empty_signzones_file(const std::string &file_name)
{
    FILE *fw = ods_fopen(file_name.c_str(), NULL, "w");
    if (!fw) return 0;

    fprintf(fw, "<ZoneList>\n</ZoneList>\n");
    ods_fclose(fw);

    return 1;
}
