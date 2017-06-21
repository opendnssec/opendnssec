/* TODO COPYRIGHT */

#include "key_purge.h"
#include "clientpipe.h"
#include "log.h"
#include "db/dbw.h"
#include "hsmkey/hsm_key_factory.h"

int
removeDeadKeysNow_zone(int sockfd, struct dbw_db *db, struct dbw_zone *zone)
{
    static const char *scmd = "removeDeadKeysNow";

    int purged = 0;
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (key->introducing) continue;
        int purgeable = 1;
        for (size_t s = 0; s < key->keystate_count; s++) {
            struct dbw_keystate *keystate = key->keystate[s];
            if (keystate->state == DBW_NA) continue;
            purgeable &= (keystate->state == DBW_HIDDEN);
        }
        if (!purgeable) continue;
        ods_log_info("[%s] deleting key: %s", scmd, key->hsmkey->locator);
        client_printf (sockfd, "deleting key: %s\n", key->hsmkey->locator);
        for (size_t s = 0; s < key->keystate_count; s++) {
            key->keystate[s]->dirty = DBW_DELETE;
        }
        key->dirty = DBW_DELETE;
        hsm_key_factory_release_key(key->hsmkey, key);
        for (size_t d = 0; d < key->from_keydependency_count; d++) {
            key->from_keydependency[d]->dirty = DBW_DELETE;
        }
        purged++;
    }

    if (!purged)
        client_printf (sockfd, "No keys to purge for %s \n", zone->name);
    return purged;
}

int
removeDeadKeysNow_policy(int sockfd, struct dbw_db *db, struct dbw_policy *policy)
{
    int r = 0;
    for (size_t z = 0; z < policy->zone_count; z++) {
        r |= removeDeadKeysNow_zone(sockfd, db, policy->zone[z]);
    }
    return r;
}
