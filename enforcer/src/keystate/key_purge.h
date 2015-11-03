#ifndef _KEYSTATE_KEY_PURGE_H_
#define _KEYSTATE_KEY_PURGE_H_

#include "daemon/engine.h"
#include "db/db_connection.h"
#include "db/zone.h"
#include "db/policy.h"

void free_all(key_data_list_t *key_list, key_data_t** keylist, key_dependency_list_t *deplist, key_dependency_t **deplist2, zone_t *zone);

int removeDeadKeysNow(int sockfd, db_connection_t *dbconn, policy_t *policy, zone_t *rzone);

#endif

