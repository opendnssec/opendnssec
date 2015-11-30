#ifndef _KEYSTATE_KEY_PURGE_H_
#define _KEYSTATE_KEY_PURGE_H_

#include "daemon/engine.h"
#include "db/db_connection.h"
#include "db/zone.h"
#include "db/policy.h"

int removeDeadKeysNow(int sockfd, db_connection_t *dbconn, policy_t *policy, zone_t *rzone);

#endif

