#ifndef _KEYSTATE_KEY_PURGE_H_
#define _KEYSTATE_KEY_PURGE_H_

#include "daemon/engine.h"
#include "db/db_connection.h"
#include "db/zone_db.h"
#include "db/policy.h"

extern int removeDeadKeysNow(int sockfd, db_connection_t *dbconn, policy_t *policy, zone_db_t *rzone);

#endif

