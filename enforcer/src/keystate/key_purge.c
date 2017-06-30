/*
 * Copyright (c) 2017 NLNet Labs. All rights reserved.
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
