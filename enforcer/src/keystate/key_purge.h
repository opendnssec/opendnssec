#ifndef _KEYSTATE_KEY_PURGE_H_
#define _KEYSTATE_KEY_PURGE_H_

#include "db/dbw.h"

int removeDeadKeysNow_zone(int sockfd, struct dbw_db *db, struct dbw_zone *zone);
int removeDeadKeysNow_policy(int sockfd, struct dbw_db *db, struct dbw_policy *policy);

#endif

