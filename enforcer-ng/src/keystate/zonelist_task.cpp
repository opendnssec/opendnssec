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

#include <memory>

#include "protobuf-orm/pb-orm.h"
#include "xmlext-pb/xmlext-wr.h"
#include "daemon/clientpipe.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/orm.h"
#include "keystate/keystate.pb.h"
#include "keystate/zonelist_task.h"

static const char *module_str = "zonelist_task";

bool
write_zonelist_file_to_disk(::ods::keystate::ZoneListDocument &zone_list_doc, const std::string &filename, int sockfd) {

	// TODO: As in 1.4, do some permissions checking here first
	// TODO: As in 1.4, create a backup file. Need to implement a
	// a copy function that doesn't use a system call! (unlike ods_file_copy)

	// Do the write as an atomic operation i.e. write to a .tmp then rename it...
	std::string filename_tmp(filename);
	filename_tmp.append(".tmp");								
    if (!write_pb_message_to_xml_file(&zone_list_doc, filename_tmp.c_str())) {
         ods_log_error("[%s] writing zonelist xml to output failed", module_str);
         return false;
    }	
    if (rename(filename_tmp.c_str(), filename.c_str()) != 0) {
        ods_log_error("[%s] failed to rename %s to %s", module_str, filename_tmp.c_str(), filename.c_str());
        return false;
    }	
	return true;
}


int
perform_zonelist_export_to_file(const std::string& filename, engineconfig_type *config)
{
	return perform_zonelist_export(&filename, 0, config);
}

int
perform_zonelist_export_to_fd(int sockfd, engineconfig_type *config)
{
	return perform_zonelist_export(NULL, sockfd, config);
}

int
perform_zonelist_export(const std::string* filename, int sockfd, engineconfig_type *config)
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
			// This is a dummy variable so that empty zonelists will be exported
			// It does not appear in the output file
			zonelistdoc->mutable_zonelist()->set_export_empty(true);

            bool ok = OrmMessageEnum(conn, enfzone.descriptor(), rows);
            if (!ok) {
                ods_log_error("[%s] enum enforcer zone failed", module_str);
                return 0;
            }

            for (bool next=OrmFirst(rows); next; next = OrmNext(rows)) {
                 OrmContextRef context;
                 if (!OrmGetMessage(rows, enfzone, true, context)) {
                     rows.release();
                     ods_log_error("[%s] retrieving zone from database failed", module_str);
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

			// Where should we write the output?
            if (filename != NULL) {
	             if (!write_zonelist_file_to_disk(*(zonelistdoc.get()), *filename, sockfd)) {
	                 ods_log_error("[%s] writing zonelist xml to output failed", module_str);
	                 return 0;
	             }				
			} else {
				char *buf = NULL;
				size_t bufc;
				FILE *fw = open_memstream(&buf, &bufc);
				if (!fw) {
					client_printf_err(sockfd, "Failed to allocate buffer.\n");
					ods_log_error("[%s] Failed to allocate buffer while writing zonelist. (%s)", 
						module_str, strerror(errno));
					return 0;
				}
				if (!write_pb_message_to_xml_file(zonelistdoc.get(), fw, 0)) {
					ods_log_error("[%s] writing zonelist xml to output failed", module_str);
					free(buf);
					return 0;
				}
				fclose(fw);
				for (int i = 0; i < bufc; i++) {
					/* todo: optimize this loop to read upto ODS_SE_MAXLINE */
					client_printf(sockfd, "%c", buf[i]);
				}
				free(buf);
			}
        }
    }

    return 1;
}
