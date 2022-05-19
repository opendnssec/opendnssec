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
#include "hsmkey/hsm_key_factory.h"

static void free_all(key_data_list_t *key_list, key_data_t** keylist,
	key_dependency_list_t *deplist, key_dependency_t **deplist2,
	zone_db_t *zone)
{
	int i;

	key_dependency_list_free(deplist);
	deplist = NULL;

	key_data_list_free(key_list);
	key_list = NULL;

	if (keylist) {
		int keylist_size = key_data_list_size(key_list);
		for (i = 0; i < keylist_size; i++) {
			key_data_free(keylist[i]);
		}
		free(keylist);
		keylist = NULL;
	}

	if (deplist2) {
		int deplist2_size = key_dependency_list_size(deplist);
		for (i = 0; i < deplist2_size; i++){
			key_dependency_free(deplist2[i]);
		}
		free(deplist2);
		deplist2 = NULL;
	}

	zone_db_free(zone);
}


int removeDeadKeysNow(int sockfd, db_connection_t *dbconn,
	policy_t *policy, zone_db_t *rzone, int purge)
{
    static const char *scmd = "removeDeadKeysNow";
    size_t i, deplist2_size = 0;
    int key_purgable, cmp;
    int zone_key_purgable;
    unsigned int j;
    const key_state_t* state = NULL;
    key_data_list_t *key_list = NULL;
    key_data_t** keylist = NULL;
    key_dependency_list_t *deplist = NULL;
    key_dependency_t **deplist2 = NULL;
    size_t keylist_size;
    zone_list_db_t *zonelist = NULL;
    zone_db_t *zone = NULL;
    int listsize = 0;


    if (!dbconn) {
        ods_log_error("[%s] no dbconn", scmd);
        client_printf_err(sockfd, "[%s] no dbconn", scmd);
        return 1;
    }

    if (policy) {
        if (policy_retrieve_zone_list(policy)) {
            ods_log_error("[%s] Error fetching zones", scmd);
            client_printf_err(sockfd, "[%s] Error fetching zones", scmd);
            return 1;
        }
        zonelist = policy_zone_list(policy);
        listsize = zone_list_db_size(zonelist);
        if (listsize == 0) {
            client_printf (sockfd, "No zones on policy %s\n", policy_name(policy));
            client_printf (sockfd, "No keys to purge\n");
            return 0;
        }
        zone = zone_list_db_get_next(zonelist);
    } else if (rzone) {
        listsize = 1;
        zone = zone_db_new_copy(rzone);
    }


    while (listsize > 0 ) {
        zone_key_purgable = 0;
        if (!(deplist = zone_db_get_key_dependencies(zone))) {
            /* TODO: better log error */
            ods_log_error("[%s] error zone_db_get_key_dependencies()", scmd);
            client_printf_err(sockfd, "%s: error zone_db_get_key_dependencies()", scmd);
            free_all(key_list, keylist, deplist, deplist2, zone);
            return 1;
        }

        if (!(key_list = zone_db_get_keys(zone))) {
            /* TODO: better log error */
            ods_log_error("[%s] error zone_db_get_keys()", scmd);
            client_printf_err(sockfd, "%s: error zone_db_get_keys()", scmd);
            free_all(key_list, keylist, deplist, deplist2, zone);
            return 1;
        }
        keylist_size = key_data_list_size(key_list);

        if (keylist_size) {
            if (!(keylist = (key_data_t**)calloc(keylist_size, sizeof(key_data_t*)))) {
                /* TODO: better log error */
                ods_log_error("[%s] error calloc(keylist_size)", scmd);
                client_printf_err(sockfd, "[%s] error calloc(keylist_size)", scmd);
                free_all(key_list, keylist, deplist, deplist2, zone);
                return 1;
            }
            for (i = 0; i < keylist_size; i++) {
                if (!i)
                    keylist[i] = key_data_list_get_begin(key_list);
                else
                    keylist[i] = key_data_list_get_next(key_list);
                if (!keylist[i]
                        || key_data_cache_hsm_key(keylist[i])
                        || key_data_cache_key_states(keylist[i])) {
                    ods_log_error("[%s] error key_data_list cache", scmd);
                    client_printf_err(sockfd, "[%s] error key_data_list cache", scmd);
                    free_all(key_list, keylist, deplist, deplist2, zone);
                    return 1;
                }
            }
        }
        key_data_list_free(key_list);
        key_list = NULL;

        deplist2_size = key_dependency_list_size(deplist);
        deplist2 = (key_dependency_t**)calloc(deplist2_size, sizeof(key_dependency_t*));
        /* deplist might be NULL but is always freeable */
        if (deplist2_size > 0)
            deplist2[0] = key_dependency_list_get_begin(deplist);
        for (i = 1; i < deplist2_size; i++)
            deplist2[i] = key_dependency_list_get_next(deplist);
        key_dependency_list_free(deplist);
        deplist = NULL;

        for (i = 0; i < keylist_size; i++) {
            if (key_data_introducing(keylist[i])) continue;
            key_purgable = 1;
            for (j = 0; j<4; j++) {
                switch(j){
                    case 0: state = key_data_cached_ds(keylist[i]); break;
                    case 1: state = key_data_cached_dnskey(keylist[i]); break;
                    case 2: state = key_data_cached_rrsigdnskey(keylist[i]); break;
                    case 3: state = key_data_cached_rrsig(keylist[i]); break;
                    default: state = NULL;
                }
                if (key_state_state(state) == KEY_STATE_STATE_NA) continue;
                if (key_state_state(state) != KEY_STATE_STATE_HIDDEN) {
                    key_purgable = 0;
                    break;
                }
            }
            if (key_purgable) {
                zone_key_purgable = 1;
                /* key is purgable  */
                ods_log_info("[%s] deleting key: %s", scmd,
                        hsm_key_locator(key_data_cached_hsm_key(keylist[i])));
                client_printf (sockfd, "deleting key: %s\n",
                        hsm_key_locator(key_data_cached_hsm_key(keylist[i])));

                /* FIXME: key_data_cached_ds spits out const
                 * key_state_delete discards that. */
                if (key_state_delete(key_data_cached_ds(keylist[i]))
                        || key_state_delete(key_data_cached_dnskey(keylist[i]))
                        || key_state_delete(key_data_cached_rrsigdnskey(keylist[i]))
                        || key_state_delete(key_data_cached_rrsig(keylist[i]))
                        || key_data_delete(keylist[i])
                        || hsm_key_factory_release_key_id(hsm_key_id(key_data_cached_hsm_key(keylist[i])), dbconn)) {
                    /* TODO: better log error */
                    ods_log_error("[%s] key_state_delete() || key_data_delete() || hsm_key_factory_release_key() failed", scmd);
                    client_printf_err(sockfd, "[%s] key_state_delete() || key_data_delete() || hsm_key_factory_release_key() failed", scmd);
                    free_all(key_list, keylist, deplist, deplist2, zone);
                    return 1;
                }
                /* we can clean up dependency because key is purgable */

                for (j = 0; j < deplist2_size; j++) {
                    if (!deplist2[j]) continue;
                    if (db_value_cmp(key_data_id(keylist[i]), key_dependency_from_key_data_id(deplist2[j]), &cmp)) {
                        /* TODO: better log error */
                        ods_log_error("[%s] cmp deplist from failed", scmd);
                        client_printf_err(sockfd, "[%s] cmp deplist from failed", scmd);
                        break;
                    }
                    if(cmp) continue;

                    if (key_dependency_delete(deplist2[j])) {
                        /* TODO: better log error */
                        ods_log_error("[%s] key_dependency_delete() failed", scmd);
                        client_printf_err(sockfd, "[%s] key_dependency_delete() failed", scmd);
                        break;
                    }
                }
            }

        }
        if (zone_key_purgable == 0)
            client_printf (sockfd, "No keys to purge for %s \n", zone_db_name(zone));

        free_all(key_list, keylist, deplist, deplist2, zone);

        listsize--;
        if (listsize > 0) {
            zone = zone_list_db_get_next(zonelist);
        }
    }

    if(purge) {
        int deleteCount = hsm_key_factory_delete_key(dbconn);
        if(deleteCount > 0)
            client_printf (sockfd, "Number of keys deleted from HSM is %d\n", deleteCount);
        else
            client_printf (sockfd, "Found no keys to delete from HSM\n");
    } else
        client_printf (sockfd, "Refrained from deleting keys from HSM\n");

    return 0;
}
