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

#ifndef _KEYSTATE_WRITE_SIGNZONE_TASK_H_
#define _KEYSTATE_WRITE_SIGNZONE_TASK_H_

#include "daemon/cfg.h"

namespace ods {
	namespace keystate {
		class ZoneListDocument;
	}
}

// This method performs a bulk export of the file be retriving the 
// entire zone list from the database
int perform_write_zones_file(int sockfd, engineconfig_type *config);

// These methods load/dump from the zones file into the zonelistDoc structures
// They are used in the cases where incremental updates to the zones file are needed
bool load_zones_file(::ods::keystate::ZoneListDocument &zonelistDoc, bool &file_not_found, engineconfig_type *config, int sockfd);
bool dump_zones_file(::ods::keystate::ZoneListDocument &zonelistDoc, engineconfig_type *config, int sockfd);

#endif /* _KEYSTATE_WRITE_SIGNZONE_TASK_H_ */
