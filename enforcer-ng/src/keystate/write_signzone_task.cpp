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

#include "config.h"

#include <memory>
#include <errno.h>
#include <string>
#include <sys/stat.h>

#include "protobuf-orm/pb-orm.h"
#include "xmlext-pb/xmlext-wr.h"
#include "xmlext-pb/xmlext-rd.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "daemon/orm.h"
#include "keystate/keystate.pb.h"
#include "keystate/write_signzone_task.h"

static const char *module_str = "write_signzone_task";



static void
get_zones_file_name(std::string& filename, engineconfig_type *config) {
	filename.assign(config->working_dir);
    filename.append("/");
    filename.append(OPENDNSSEC_ENFORCER_ZONELIST);
}


bool
load_zones_file(::ods::keystate::ZoneListDocument &zonelistDoc, bool &file_not_found, engineconfig_type *config, int sockfd) {

	// Find out if the zones.xml file exists
	// This may be the first ever export, or something could have happened to the file...
	file_not_found = false;
    std::string zones_file;
	get_zones_file_name(zones_file, config);

	struct stat stat_ret;
	if (stat(zones_file.c_str(), &stat_ret) != 0) {
		if (errno != ENOENT) {
			ods_log_error_and_printf(sockfd, module_str, "ERROR: cannot stat file %s: %s",
					zones_file.c_str(), strerror(errno));
			return false;
		}
		// This is a case where the file simply doesn't exist
		file_not_found = true;
		return false;
	}
	if (!S_ISREG(stat_ret.st_mode)) {
		ods_log_error_and_printf(sockfd, module_str, "ERROR: %s is not a regular file \n", zones_file.c_str());
		return false;
	}

	// The file exists, so lets load it 
	if (!read_pb_message_from_xml_file(&zonelistDoc, zones_file.c_str())) {
		ods_log_error_and_printf(sockfd,module_str,
								 "Unable to read the %s file", zones_file.c_str());
		return false;
	}

	// Note we don't do any validation or checking on this file as since it is an 'internal' file
	return true;
}

bool
dump_zones_file(::ods::keystate::ZoneListDocument &zonelistDoc, engineconfig_type *config, int sockfd) {

    std::string zones_file;
	get_zones_file_name(zones_file, config);
/*	return write_zonelist_file_to_disk(zonelistDoc, zones_file, sockfd);*/
return false;
}

int
perform_write_zones_file(int sockfd, engineconfig_type *config)
{

    //write signzone file
    std::string signzone_file;
	get_zones_file_name(signzone_file, config);
/*
	if (!perform_zonelist_export_to_file(signzone_file,config)) {
    	ods_log_error_and_printf(sockfd, module_str, 
            	"failed to write %s", signzone_file.c_str());
	}
*/
	ods_log_debug("[%s] Exported internal zone list ", module_str);
    return 1;
}
