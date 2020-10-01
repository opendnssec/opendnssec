/*
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
 * All rights reserved.
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

#include "config.h"
#include <getopt.h>

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "file.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "duration.h"
#include "libhsm.h"
#include "libhsmdns.h"
#include "db/key_data.h"
#include "db/db_error.h"

#include "keystate/keystate_export_cmd.h"
#include "keystate/keystate_list_cmd.h"

static const char *module_str = "keystate_export_cmd";

/** Retrieve KEY from HSM, should only be called for DNSKEYs
 * @param id, locator of DNSKEY on HSM
 * @param zone, name of zone key belongs to
 * @param algorithm, alg of DNSKEY
 * @param ttl, ttl DS should get. if 0 DNSKEY_TTL is used.
 * @return RR on succes, NULL on error */
static ldns_rr *
get_dnskey(const char *id, const char *zone, const char *keytype, int alg, uint32_t ttl)
{
    libhsm_key_t *key;
    hsm_sign_params_t *sign_params;
    ldns_rr *dnskey_rr;
    /* Code to output the DNSKEY record  (stolen from hsmutil) */
    hsm_ctx_t *hsm_ctx = hsm_create_context();
    if (!hsm_ctx) {
        ods_log_error("[%s] Could not connect to HSM", module_str);
        return NULL;
    }
    if (!(key = hsm_find_key_by_id(hsm_ctx, id))) {
        hsm_destroy_context(hsm_ctx);
        return NULL;
    }

    /* Sign params only need to be kept around
     * for the hsm_get_dnskey() call. */
    sign_params = hsm_sign_params_new();
    sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone);
    sign_params->algorithm = (ldns_algorithm) alg;
    sign_params->flags = LDNS_KEY_ZONE_KEY;

    if (keytype && (!strcasecmp(keytype, "KSK") || !strcasecmp(keytype, "CSK")))
        sign_params->flags = sign_params->flags | LDNS_KEY_SEP_KEY;
		
    /* Get the DNSKEY record */
    dnskey_rr = hsm_get_dnskey(hsm_ctx, key, sign_params);

    libhsm_key_free(key);
    hsm_sign_params_free(sign_params);
    hsm_destroy_context(hsm_ctx);
	
    /* Override the TTL in the dnskey rr */
    if (ttl)
        ldns_rr_set_ttl(dnskey_rr, ttl);
	
    return dnskey_rr;
}

/**
 * Print DNSKEY record or SHA1 and SHA256 DS records, should only be
 * called for DNSKEYs.
 *
 * @param sockfd, Where to print to
 * @param key, Key to be printed. Must not be NULL.
 * @param zone, name of zone key belongs to. Must not be NULL.
 * @param bind_style, bool. print DS rather than DNSKEY rr.
 * @return 1 on succes 0 on error
 */
static int 
print_ds_from_id(int sockfd, key_data_t *key, const char *zone,
	const char* state, int bind_style, int print_sha1)
{
    ldns_rr *dnskey_rr;
    ldns_rr *ds_sha_rr;
    int ttl = 0;
    const char *locator;
    char *rrstr;

    assert(key);
    assert(zone);

    locator = hsm_key_locator(key_data_hsm_key(key));
    if (!locator)
        return 1;
    /* This fetches the states from the DB, I'm only assuming they get
     * cleaned up when 'key' is cleaned(?) */
    if (key_data_cache_key_states(key) != DB_OK)
        return 1;

    ttl = key_state_ttl(key_data_cached_dnskey(key));

    dnskey_rr = get_dnskey(locator, zone, key_data_role_text(key), key_data_algorithm(key), ttl);
    if (!dnskey_rr)
        return 1;

    if (bind_style) {
        ldns_rr_set_ttl(dnskey_rr, key_state_ttl (key_data_cached_ds(key)));
        if (print_sha1) {
            ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA1);
            rrstr = ldns_rr2str(ds_sha_rr);
            ldns_rr_free(ds_sha_rr);
            /* TODO log error on failure */
            (void)client_printf(sockfd, ";%s %s DS record (SHA1):\n%s", state, key_data_role_text(key), rrstr);
            LDNS_FREE(rrstr);
        } else {
            ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA256);
            rrstr = ldns_rr2str(ds_sha_rr);
            ldns_rr_free(ds_sha_rr);
            /* TODO log error on failure */
            (void)client_printf(sockfd, ";%s %s DS record (SHA256):\n%s", state, key_data_role_text(key), rrstr);
            LDNS_FREE(rrstr);
        }
    } else {
        rrstr = ldns_rr2str_fmt(ldns_output_format_nocomments, dnskey_rr);
        /* TODO log error on failure */
        (void)client_printf(sockfd, "%s", rrstr);
        LDNS_FREE(rrstr);
    }
	
    ldns_rr_free(dnskey_rr);
    return 0;
}

static int
perform_keystate_export(int sockfd, db_connection_t *dbconn,
	const char *zonename, const char *keytype, const char *keystate,
        const hsm_key_t *hsmkey, int all, int bind_style, int print_sha1)
{
    key_data_list_t *key_list = NULL;
    key_data_t *key;
    zone_db_t *zone = NULL;
    db_clause_list_t* clause_list = NULL;
    const char *azonename = NULL;

    /* Find all keys related to zonename */
    if (all == 0) {
        if (!(key_list = key_data_list_new(dbconn)) ||
              !(clause_list = db_clause_list_new()) ||
              !(zone = zone_db_new_get_by_name(dbconn, zonename)) ||
              !key_data_zone_id_clause(clause_list, zone_db_id(zone)) ||
              (hsmkey && !key_data_hsm_key_id_clause(clause_list, hsm_key_id(hsmkey))) ||
              key_data_list_get_by_clauses(key_list, clause_list))
        {
            key_data_list_free(key_list);
            db_clause_list_free(clause_list);
            zone_db_free(zone);
            ods_log_error("[%s] Error fetching from database", module_str);
            return 1;
        }
        db_clause_list_free(clause_list);
        zone_db_free(zone);
    } else {
        if (!(key_list = key_data_list_new_get(dbconn)) ||
                !(clause_list = db_clause_list_new()) ||
                (hsmkey && !key_data_hsm_key_id_clause(clause_list, hsm_key_id(hsmkey))) ||
                key_data_list_get_by_clauses(key_list, clause_list))
        {
            key_data_list_free(key_list);
            db_clause_list_free(clause_list);
            ods_log_error("[%s] Error fetching from database", module_str);
            return 1;
        }
        db_clause_list_free(clause_list);
    }
	
    /* Print data*/
    while ((key = key_data_list_get_next(key_list))) {
        if (keytype && strcasecmp(key_data_role_text(key), keytype)) {
            key_data_free(key);
            continue;
        }
        if (keystate && strcasecmp(map_keystate(key), keystate)) {
            key_data_free(key);
            continue;
        }
        if (!keytype && !keystate && !hsmkey &&
              key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_SUBMIT &&
              key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_SUBMITTED &&
              key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_RETRACT   &&
              key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_RETRACTED)
        {
            key_data_free(key);
            continue;
        }

        if (all && (!(zone = zone_db_new (dbconn)) || (zone_db_get_by_id(zone, key_data_zone_id(key))) || !(azonename = zone_db_name(zone)))) {
            ods_log_error("[%s] Error fetching from database", module_str);
            client_printf_err(sockfd, "Error fetching from database \n");
        }

        /* check return code TODO */
        if (key_data_cache_hsm_key(key) == DB_OK) {
            if (print_ds_from_id(sockfd, key, (const char*)azonename?azonename:zonename, (const char*)map_keystate(key), bind_style, print_sha1)) {
                ods_log_error("[%s] Error in print_ds_from_id", module_str);
                client_printf_err(sockfd, "Error in print_ds_from_id \n");
            }
        } else {
            ods_log_error("[%s] Error fetching from database", module_str);
            client_printf_err(sockfd, "Error fetching from database \n");
        }
        key_data_free(key);

        if (all)
            zone_db_free(zone);
    }
    key_data_list_free(key_list);
    return 0;
}

static void
usage(int sockfd)
{
    client_printf(sockfd,
         "key export\n"
         "	--zone <zone> | --all			aka -z | -a \n"
         "	--keystate <state>			aka -e\n"
         "	--keytype <type>			aka -t \n"
         "	--cka_id <CKA_ID>			aka -k \n"
         "	[--ds [--sha1]]				aka -d [-s]\n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
         "Export DNSKEY(s) for a given zone or all of them from the database.\n"
         "If keytype and keystate are not specified, KSKs which are waiting for command ds-submit, ds-seen, ds-retract and ds-gone are shown. Otherwise both keystate and keytype must be given.\n"
         "If cka_id is specified then that key is output for the specified zones.\n"

         "\nOptions:\n"
         "zone|all	specify a zone or all of them\n"
         "keystate	limit the output to a given state\n"
         "keytype		limit the output to a given type, can be ZSK, KSK, or CSK\n"
         "cka_id		limit the output to the given key locator\n"
         "ds		export DS in BIND format which can be used for upload to a registry\n"
         "sha1		When outputting DS print sha1 instead of sha256\n");
}

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
    #define NARGV 11
    char buf[ODS_SE_MAXLINE];
    const char *argv[NARGV];
    int argc = 0;
    const char *zonename = NULL;
    const char* keytype = NULL;
    const char* keystate = NULL;
    const char* cka_id = NULL;
    zone_db_t * zone = NULL;
    hsm_key_t *hsmkey = NULL;
    int all = 0;
    int ds = 0;
    int bsha1 = 0;
    int long_index = 0, opt = 0;
    db_connection_t* dbconn = getconnectioncontext(context);

    static struct option long_options[] = {
        {"zone", required_argument, 0, 'z'},
        {"keytype", required_argument, 0, 't'},
        {"keystate", required_argument, 0, 'e'},
        {"cka_id", required_argument, 0, 'k'},
        {"all", no_argument, 0, 'a'},
        {"ds", no_argument, 0, 'd'},
        {"sha1", no_argument, 0, 's'},
        {0, 0, 0, 0}
    };
	
    ods_log_debug("[%s] %s command", module_str, key_export_funcblock.cmdname);

    /* Use buf as an intermediate buffer for the command.*/
    strncpy(buf, cmd, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';

    /* separate the arguments*/
    argc = ods_str_explode(buf, NARGV, argv);
    if (argc == -1) {
        client_printf_err(sockfd, "too many arguments\n");
        ods_log_error("[%s] too many arguments for %s command",
                      module_str, key_export_funcblock.cmdname);
        return -1;
    }

    optind = 0;
    while ((opt = getopt_long(argc, (char* const*)argv, "z:t:e:k:ads", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'z':
                zonename = optarg;
                break;
            case 't':
                keytype = optarg;
                break;
            case 'e':
                keystate = optarg;
                break;
            case 'k':
                cka_id = optarg;
                break;
            case 'a':
                all = 1;
                break;
            case 'd':
                ds = 1;
                break;
            case 's':
                bsha1 = 1;
                break; 
            default:
                client_printf_err(sockfd, "unknown arguments\n");
                ods_log_error("[%s] unknown arguments for %s command",
                                module_str, key_export_funcblock.cmdname);
                return -1;
        }
    }

    if (keytype) {
        if (strcasecmp(keytype, "KSK") && strcasecmp(keytype, "ZSK") && strcasecmp(keytype, "CSK")) {
            ods_log_error("[%s] unknown keytype, should be one of KSK, ZSK, or CSK", module_str);
            client_printf_err(sockfd, "unknown keytype, should be one of KSK, ZSK, or CSK\n");
            return -1;
        }
    }

    if (keystate) {
        if (strcasecmp(keystate, "generate") && strcasecmp(keystate, "publish") && strcasecmp(keystate, "ready") && strcasecmp(keystate, "active") && strcasecmp(keystate, "retire") && strcasecmp(keystate, "unknown") && strcasecmp(keystate, "mixed")) {
            ods_log_error("[%s] unknown keystate", module_str);
            client_printf_err(sockfd, "unknown keystate\n");
            return -1;
        }
    }


    if ((!zonename && !all) || (zonename && all)) {
        ods_log_error("[%s] expected either --zone or --all for %s command", module_str, key_export_funcblock.cmdname);
        client_printf_err(sockfd, "expected either --zone or --all \n");
        return -1;
    }
    if (zonename && !(zone = zone_db_new_get_by_name(dbconn, zonename))) {
        ods_log_error("[%s] Unknown zone: %s", module_str, zonename);
        client_printf_err(sockfd, "Unknown zone: %s\n", zonename);
        return -1;
    }
    free(zone);
    zone = NULL;

    /* if no keystate and keytype are given, default values are used.
     * Default type is KSK, default states are waiting for ds-submit, ds-seen, ds-retract and ds-gone.
     * Otherwise both keystate and keytype must be specified.
     */
    if ((keytype && !keystate) || (!keytype && keystate)) {
        ods_log_error("[%s] expected both --keystate and --keytype together or none of them", module_str);
        client_printf_err(sockfd, "expected both --keystate and --keytype together or none of them\n");
        return -1;
    }

    if (cka_id && !(hsmkey = hsm_key_new_get_by_locator(dbconn, cka_id))) {
        client_printf_err(sockfd, "CKA_ID %s can not be found!\n", cka_id);
        return -1;
    }

    /* perform task immediately */
    return perform_keystate_export(sockfd, dbconn, zonename, (const char*) keytype, (const char*) keystate, hsmkey, all, ds, bsha1);
}

struct cmd_func_block key_export_funcblock = {
    "key export", &usage, &help, NULL, &run
};
