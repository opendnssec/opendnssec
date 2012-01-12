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
}
