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
#include "db/dbw.h"

#include "keystate/keystate_list_cmd.h"
#include "keystate/keystate_export_cmd.h"

static const char *module_str = "keystate_export_cmd";

/** Retrieve KEY from HSM, should only be called for DNSKEYs
 * @param id, locator of DNSKEY on HSM
 * @param zone, name of zone key belongs to
 * @param algorithm, alg of DNSKEY
 * @param ttl, ttl DS should get. if 0 DNSKEY_TTL is used.
 * @return RR on succes, NULL on error */
static ldns_rr *
get_dnskey(const char *locator, const char *zonename, int is_ksk, int alg,
    uint32_t ttl)
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
    if (!(key = hsm_find_key_by_id(hsm_ctx, locator))) {
        hsm_destroy_context(hsm_ctx);
        return NULL;
    }

    /* Sign params only need to be kept around
     * for the hsm_get_dnskey() call. */
    sign_params = hsm_sign_params_new();
    sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zonename);
    sign_params->algorithm = (ldns_algorithm) alg;
    sign_params->flags = LDNS_KEY_ZONE_KEY;
    if (is_ksk)
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
 * @param bind_style, bool. print DS rather than DNSKEY rr.
 * @return 1 on succes 0 on error
 */
static int
print_ds_from_id(int sockfd, struct dbw_key *key, int bind_style, int print_sha1)
{
    ldns_rr *dnskey_rr;
    ldns_rr *ds_sha_rr;
    char *rrstr;
    
    struct dbw_keystate *dnskey = dbw_get_keystate(key, DBW_DNSKEY);
    if (!dnskey) return 1;
    dnskey_rr = get_dnskey(key->hsmkey->locator, key->zone->name,
        key->role & DBW_KSK, key->algorithm, dnskey->ttl);
    if (!dnskey_rr) return 1;

    if (bind_style) {
        struct dbw_keystate *ds = dbw_get_keystate(key, DBW_DS);
        if (!ds) return 1;
        ldns_rr_set_ttl(dnskey_rr, ds->ttl);
        if (print_sha1) {
            ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA1);
            rrstr = ldns_rr2str(ds_sha_rr);
            ldns_rr_free(ds_sha_rr);
            /* TODO log error on failure */
            (void)client_printf(sockfd, ";%s %s DS record (SHA1):\n%s",
                map_keystate(key), dbw_key_role_txt[key->role], rrstr);
            LDNS_FREE(rrstr);
        } else {
            ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA256);
            rrstr = ldns_rr2str(ds_sha_rr);
            ldns_rr_free(ds_sha_rr);
            /* TODO log error on failure */
            (void)client_printf(sockfd, ";%s %s DS record (SHA256):\n%s",
                map_keystate(key), dbw_key_role_txt[key->role], rrstr);
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
perform_keystate_export(int sockfd, struct dbw_zone *zone, int role,
    const char *keystate, int bind_style, int print_sha1)
{
    int keys_exported = 0;
    for (size_t k = 0; k < zone->key_count; k++) {
        struct dbw_key *key = zone->key[k];
        if (role != -1 && key->role != role) continue;
        if (keystate && strcasecmp(map_keystate(key), keystate)) continue;
        /* Don't export keys in stable DS states unless explicitly asked. */
        if (role == -1 && !keystate &&
              key->ds_at_parent != DBW_DS_AT_PARENT_SUBMIT &&
              key->ds_at_parent != DBW_DS_AT_PARENT_SUBMITTED &&
              key->ds_at_parent != DBW_DS_AT_PARENT_RETRACT   &&
              key->ds_at_parent != DBW_DS_AT_PARENT_RETRACTED)
        {
            continue;
        }
        if (print_ds_from_id(sockfd, key, bind_style, print_sha1)) {
            ods_log_error("[%s] Error in print_ds_from_id", module_str);
            client_printf_err(sockfd, "Error in print_ds_from_id \n");
            return 1;
        }
        keys_exported++;
    }
    return !keys_exported;
}

static void
usage(int sockfd)
{
    client_printf(sockfd,
         "key export\n"
         "	--zone <zone> | --all			aka -z | -a \n"
         "	--keystate <state>			aka -e\n"
         "	--keytype <type>			aka -t \n"
         "	[--ds [--sha1]]				aka -d [-s]\n"
    );
}

static void
help(int sockfd)
{
    client_printf(sockfd,
         "Export DNSKEY(s) for a given zone or all of them from the database.\n"
         "If keytype and keystate are not specified, KSKs which are waiting for command ds-submit, ds-seen, ds-retract and ds-gone are shown. Otherwise both keystate and keytype must be given.\n"

         "\nOptions:\n"
         "zone|all	specify a zone or all of them\n"
         "keystate	limit the output to a given state\n"
         "keytype		limit the output to a given type, can be ZSK, KSK, or CSK\n"
         "ds		export DS in BIND format which can be used for upload to a registry\n"
         "sha1		When outputting DS print sha1 instead of sha256\n");
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
    #define NARGV 11
    const char *argv[NARGV];
    int argc = 0;
    const char *zonename = NULL;
    const char* keytype = NULL;
    const char* keystate = NULL;
    int all = 0;
    int ds = 0;
    int bsha1 = 0;
    int long_index = 0, opt = 0;
    db_connection_t* dbconn = getconnectioncontext(context);

    static struct option long_options[] = {
        {"zone", required_argument, 0, 'z'},
        {"keytype", required_argument, 0, 't'},
        {"keystate", required_argument, 0, 'e'},
        {"all", no_argument, 0, 'a'},
        {"ds", no_argument, 0, 'd'},
        {"sha1", no_argument, 0, 's'},
        {0, 0, 0, 0}
    };
	
    ods_log_debug("[%s] %s command", module_str, key_export_funcblock.cmdname);

    /* separate the arguments*/
    argc = ods_str_explode(cmd, NARGV, argv);
    if (argc == -1) {
        client_printf_err(sockfd, "too many arguments\n");
        ods_log_error("[%s] too many arguments for %s command",
                      module_str, key_export_funcblock.cmdname);
        return -1;
    }

    optind = 0;
    while ((opt = getopt_long(argc, (char* const*)argv, "z:t:e:ads", long_options, &long_index)) != -1) {
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

    int keytype_int = -1;
    if (keytype && (keytype_int = dbw_txt2enum(dbw_key_role_txt, keytype)) == -1) {
        ods_log_error("[%s] unknown keytype, should be one of KSK, ZSK, or CSK", module_str);
        client_printf_err(sockfd, "unknown keytype, should be one of KSK, ZSK, or CSK\n");
        return -1;
    }
    if (keystate && strcasecmp(keystate, "generate") &&
        strcasecmp(keystate, "publish") && strcasecmp(keystate, "ready") &&
        strcasecmp(keystate, "active")  && strcasecmp(keystate, "retire") &&
        strcasecmp(keystate, "unknown") && strcasecmp(keystate, "mixed"))
    {
        ods_log_error("[%s] unknown keystate", module_str);
        client_printf_err(sockfd, "unknown keystate\n");
        return -1;
    }

    if ((!zonename && !all) || (zonename && all)) {
        ods_log_error("[%s] expected either --zone or --all for %s command", module_str, key_export_funcblock.cmdname);
        client_printf_err(sockfd, "expected either --zone or --all \n");
        return -1;
    }
    /* if no keystate and keytype are given, default values are used.
     * Default type is KSK, default states are waiting for ds-submit, ds-seen, ds-retract and ds-gone.
     * Otherwise both keystate and keytype must be specified.
     */
    if ((keytype && !keystate) || (!keytype && keystate)) {
        ods_log_error("[%s] expected both --keystate and --keytype together or none of them", module_str);
        client_printf_err(sockfd, "expected both --keystate and --keytype together or none of them\n");
        return -1;
    }

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return -1;
    int r = 0;
    int exports = 0;
    for (size_t z = 0; z < db->zones->n; z++) {
        struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
        if (zonename && strcmp(zonename, zone->name)) continue;
        r |= perform_keystate_export(sockfd, zone, keytype_int, keystate, ds, bsha1);
        exports++;
    }
    dbw_free(db);
    if (zonename && !exports) {
        ods_log_error("[%s] Unknown zone: %s", module_str, zonename);
        client_printf_err(sockfd, "Unknown zone: %s\n", zonename);
        return 1;
    }
    return 0;
}

struct cmd_func_block key_export_funcblock = {
    "key export", &usage, &help, NULL, &run
};
