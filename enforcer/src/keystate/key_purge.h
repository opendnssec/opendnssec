#ifndef _KEYSTATE_KEY_PURGE_H_
#define _KEYSTATE_KEY_PURGE_H_

#include "db/dbw.h"

extern int removeDeadKeysNow(int sockfd, db_connection_t *dbconn, policy_t *policy, zone_db_t *rzone, int purge);

#endif
