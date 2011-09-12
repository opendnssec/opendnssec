extern "C" {
#include "keystate/keystate_rollover_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"
#include "libhsmdns.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"


#include <fcntl.h>

static const char *module_str = "keystate_rollover_task";

void 
perform_keystate_rollover(int sockfd, engineconfig_type *config,
                          const char *zone, const char *keytype)
{

}
