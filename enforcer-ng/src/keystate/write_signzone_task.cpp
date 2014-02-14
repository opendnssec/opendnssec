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
#include "keystate/keystate.pb.h"
#include "keystate/write_signzone_task.h"
#include "keystate/zonelist_task.h"

static const char *module_str = "write_signzone_task";



int
perform_write_signzone_file(int sockfd, engineconfig_type *config)
{

    //write signzone file
    std::string signzone_file(config->working_dir);
    signzone_file.append("/");
    signzone_file.append(OPENDNSSEC_ENFORCER_ZONELIST);

	if (!perform_zonelist_export_to_file(signzone_file,config)) {
    	ods_log_error_and_printf(sockfd, module_str, 
            	"failed to write %s", signzone_file.c_str());
	}

    return 1;
}