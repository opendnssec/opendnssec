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
#include "protobuf.h"
#include "shared/log.h"
#include "shared/file.h"
#include <google/protobuf/stubs/common.h>

static const char *module_str = "protobuf";

static void 
ods_protobuf_loghandler(::google::protobuf::LogLevel level,
						const char *filename,
						int line,
						const std::string &message)
{
	const char * const fmt = "[%s] %s %s:%d] %s";
	switch (level) {
		case ::google::protobuf::LOGLEVEL_INFO:
			ods_log_info(fmt,module_str,"INFO",filename,line,message.c_str());
			break;
		case ::google::protobuf::LOGLEVEL_WARNING:
			ods_log_warning(fmt,module_str,"WARNING",filename,line,message.c_str());
			break;
		case ::google::protobuf::LOGLEVEL_ERROR:
			ods_log_crit(fmt,module_str,"ERROR",filename,line,message.c_str());
			break;
		case ::google::protobuf::LOGLEVEL_FATAL:
			ods_fatal_exit(fmt,module_str,"FATAL",filename,line,message.c_str());
			break;
		default:
			ods_log_assert(false);
			break;
	}
}

static ::google::protobuf::LogHandler *static_loghandler = NULL;

void
ods_protobuf_initialize()
{
	static_loghandler = ::google::protobuf::SetLogHandler(ods_protobuf_loghandler);
}

void
ods_protobuf_shutdown()
{
	::google::protobuf::SetLogHandler(static_loghandler);
	static_loghandler = NULL;
	google::protobuf::ShutdownProtobufLibrary();
}
