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

#include <getopt.h>
#include "config.h"

#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "daemon/engine.h"
#include "file.h"
#include "duration.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "longgetopt.h"

#include "db/key_state.h"
#include "db/hsm_key.h"
#include "db/zone_db.h"

#include "keystate/keystate_list_cmd.h"

static const char *module_str = "keystate_list_task";

/* shorter defines to keep keystate table more readable */
#define HID KEY_STATE_STATE_HIDDEN
#define RUM KEY_STATE_STATE_RUMOURED
#define OMN KEY_STATE_STATE_OMNIPRESENT
#define UNR KEY_STATE_STATE_UNRETENTIVE
#define NAV KEY_STATE_STATE_NA

enum {KS_GEN = 0, KS_PUB, KS_RDY, KS_ACT, KS_RET, KS_UNK, KS_MIX, KS_DEAD};
const char* statenames[] = {"generate", "publish", "ready",
		"active", "retire", "unknown", "mixed", "dead"};

/** Map 2.0 states to 1.x states
 * @param p: state of RR higher in the chain (e.g. DS)
 * @param c: state of RR lower in the chain (e.g. DNSKEY)
 * @param introducing: key goal
 * @return: state in 1.x speak
 **/
static int
keystate(int p, int c, int introducing, key_data_ds_at_parent_t dsstate)
{
	int dsseen    = (dsstate == KEY_DATA_DS_AT_PARENT_SEEN);
	int dsretract = (dsstate == KEY_DATA_DS_AT_PARENT_RETRACT);

	if (p == OMN && c == OMN) return KS_ACT;
	if (p == RUM && dsseen && c == OMN) return KS_ACT;
	if (introducing) {
		if (p == HID && c == HID) return KS_GEN;
		if (p == HID || c == HID) return KS_PUB;
		if (p == OMN || c == OMN) return KS_RDY;
		if (p == RUM || c == RUM) return KS_RDY;
		return KS_UNK;
	} else {
		/* retire conforms better to 1.4 terminology than dead. */
		if (p == HID && c == HID) return KS_RET; /* dead */
		if (p == UNR || c == UNR) return KS_RET;
		if (p == OMN || c == OMN) return KS_RDY;
		if (p == RUM || c == RUM) return KS_RDY;
		return KS_RET;
	}
}

static int
zskstate(key_data_t *key)
{
	return keystate(key_state_state(key_data_cached_dnskey(key)),
		key_state_state(key_data_cached_rrsig(key)),
		key_data_introducing(key), KEY_DATA_DS_AT_PARENT_INVALID);
}

static int
kskstate(key_data_t *key)
{
	return keystate(key_state_state(key_data_cached_ds(key)),
		key_state_state(key_data_cached_dnskey(key)),
		key_data_introducing(key),
		key_data_ds_at_parent(key));
}

/** Human readable keystate in 1.x speak
 * @param key: key to evaluate
 * @return: state as string
 **/
const char*
map_keystate(key_data_t *key)
{
	int z,k;
	switch(key_data_role(key)) {
		case KEY_DATA_ROLE_KSK:
			return statenames[kskstate(key)];
		case KEY_DATA_ROLE_ZSK:
			return statenames[zskstate(key)];
		case KEY_DATA_ROLE_CSK:
			k = kskstate(key);
			z = zskstate(key);
			if (k != z) return statenames[KS_MIX];
			return statenames[k];
		default:
			return statenames[KS_UNK];
	}
}

/** Time of next transition. Caller responsible for freeing ret
 * @param zone: zone key belongs to
 * @param key: key to evaluate
 * @return: human readable transition time/event */
static char*
map_keytime(const zone_db_t *zone, const key_data_t *key)
{
	char ct[26];
	struct tm srtm;
	time_t t;

	switch(key_data_ds_at_parent(key)) {
		case KEY_DATA_DS_AT_PARENT_SUBMIT:
			return strdup("waiting for ds-submit");
		case KEY_DATA_DS_AT_PARENT_SUBMITTED:
			return strdup("waiting for ds-seen");
		case KEY_DATA_DS_AT_PARENT_RETRACT:
			return strdup("waiting for ds-retract");
		case KEY_DATA_DS_AT_PARENT_RETRACTED:
			return strdup("waiting for ds-gone");
                default:
			break;
	}
	if (zone_db_next_change(zone) < 0)
		return strdup("-");
	else if (zone_db_next_change(zone) < time_now())
		return strdup("now");

	t = (time_t)zone_db_next_change(zone);
	localtime_r(&t, &srtm);
	strftime(ct, 26, "%Y-%m-%d %H:%M:%S", &srtm);
	return strdup(ct);
}

static int
perform_keystate_list(int sockfd, db_connection_t *dbconn,
    const char* zonename, const char* keytype, const char* keystate,
    void (printheader)(int sockfd),
    void (printkey)(int sockfd, zone_db_t* zone, key_data_t* key, char* tchange, hsm_key_t* hsmKey)) {
    key_data_list_t* key_list;
    key_data_t* key;
    zone_db_t *zone = NULL;
    char* tchange;
    hsm_key_t *hsmkey;
    int cmp;

    if (!(key_list = key_data_list_new_get(dbconn))) {
        client_printf_err(sockfd, "Unable to get list of keys, memory "
                "allocation or database error!\n");
        return 1;
    }

    if (printheader) {
        (*printheader)(sockfd);
    }

    while ((key = key_data_list_get_next(key_list))) {
		/* only refetches zone if different from previous */
        if (zone
                && (db_value_cmp(zone_db_id(zone), key_data_zone_id(key), &cmp)
                || cmp)) {
            zone_db_free(zone);
            zone = NULL;
        }
        if (!zone) {
            zone = key_data_get_zone(key);
        }
        hsmkey = key_data_get_hsm_key(key);
        key_data_cache_key_states(key);
        tchange = map_keytime(zone, key); /* allocs */
        if ((printkey != NULL) && (!zonename || !strcmp(zone_db_name(zone), zonename)) && (!keytype || !strcasecmp(keytype,key_data_role_text(key))) && (!keystate || !strcasecmp(keystate, map_keystate(key))))
            (*printkey)(sockfd, zone, key, tchange, hsmkey);
        free(tchange);
        hsm_key_free(hsmkey);
        key_data_free(key);
    }
    zone_db_free(zone);
    key_data_list_free(key_list);
    return 0;
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key list\n"
		"	[--verbose]				aka -v\n"
		"	[--debug]				aka -d\n"
		"	[--full]				aka -f\n"
		"	[--parsable]				aka -p\n"
		"	[--zone]				aka -z  \n"
		"	[--keystate | --all]				aka -k | -a  \n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd, 
		"List the keys in the enforcer database.\n"
		"\nOptions:\n"
		"verbose		also show additional key parameters\n"
		"debug		print information about the keystate\n"
		"full		print information about the keystate and keytags\n"
		"parsable	output machine parsable list\n"
		"zone		limit the output to the specific zone\n"
		"keytype	limit the output to the given type, can be ZSK, KSK, or CSK\n"
		"keystate	limit the output to the given state\n"
		"all		print keys in all states (including generate) \n\n");
}

static void
printcompatheader(int sockfd) {
    client_printf(sockfd, "Keys:\n");
    client_printf(sockfd, "%-31s %-8s %-9s %s\n", "Zone:", "Keytype:", "State:",
            "Date of next transition:");
}

static void
printcompatkey(int sockfd, zone_db_t* zone, key_data_t* key, char* tchange, hsm_key_t* hsmkey) {
    (void)hsmkey;
    client_printf(sockfd,
            "%-31s %-8s %-9s %s\n",
            zone_db_name(zone),
            key_data_role_text(key),
            map_keystate(key),
            tchange);
}

static void
printverboseheader(int sockfd) {
    client_printf(sockfd, "Keys:\n");
    client_printf(sockfd, "%-31s %-8s %-9s %-24s %-5s %-10s %-32s %-11s %s\n", "Zone:", "Keytype:", "State:",
            "Date of next transition:", "Size:", "Algorithm:", "CKA_ID:",
            "Repository:", "KeyTag:");
}

static void
printverbosekey(int sockfd, zone_db_t* zone, key_data_t* key, char* tchange, hsm_key_t* hsmkey) {
    (void)tchange;
    client_printf(sockfd,
            "%-31s %-8s %-9s %-24s %-5d %-10d %-32s %-11s %d\n",
            zone_db_name(zone),
            key_data_role_text(key),
            map_keystate(key),
            tchange,
            hsm_key_bits(hsmkey),
            hsm_key_algorithm(hsmkey),
            hsm_key_locator(hsmkey),
            hsm_key_repository(hsmkey),
            key_data_keytag(key));
}

static void
printFullkey(int sockfd, zone_db_t* zone, key_data_t* key, char* tchange, hsm_key_t* hsmkey) {
    (void)tchange;
    client_printf(sockfd,
            "%-31s %-8s %-9s %d %s %-12s %-12s %-12s %-12s %d %4d    %s\n",
            zone_db_name(zone),
            key_data_role_text(key),
            map_keystate(key),
            key_data_keytag(key),
            hsm_key_locator(hsmkey),
            key_state_state_text(key_data_cached_ds(key)),
            key_state_state_text(key_data_cached_dnskey(key)),
            key_state_state_text(key_data_cached_rrsigdnskey(key)),
            key_state_state_text(key_data_cached_rrsig(key)),
            key_data_publish(key),
            key_data_active_ksk(key) | key_data_active_zsk(key),
            tchange);
}

static void
printverboseparsablekey(int sockfd, zone_db_t* zone, key_data_t* key, char* tchange, hsm_key_t* hsmkey) {
    client_printf(sockfd,
            "%s;%s;%s;%s;%d;%d;%s;%s;%d\n",
            zone_db_name(zone),
            key_data_role_text(key),
            map_keystate(key),
            tchange,
            hsm_key_bits(hsmkey),
            hsm_key_algorithm(hsmkey),
            hsm_key_locator(hsmkey),
            hsm_key_repository(hsmkey),
            key_data_keytag(key));
}

static void
printdebugheader(int sockfd) {
    client_printf(sockfd,
            "Keys:\nZone:                           Key role:     "
            "DS:          DNSKEY:      RRSIGDNSKEY: RRSIG:       "
            "Pub: Act: Id:\n");
}

static void
printdebugkey(int sockfd, zone_db_t* zone, key_data_t* key, char* tchange, hsm_key_t* hsmkey) {
    (void)tchange;
    client_printf(sockfd,
            "%-31s %-13s %-12s %-12s %-12s %-12s %d %4d    %s\n",
            zone_db_name(zone),
            key_data_role_text(key),
            key_state_state_text(key_data_cached_ds(key)),
            key_state_state_text(key_data_cached_dnskey(key)),
            key_state_state_text(key_data_cached_rrsigdnskey(key)),
            key_state_state_text(key_data_cached_rrsig(key)),
            key_data_publish(key),
            key_data_active_ksk(key) | key_data_active_zsk(key),
            hsm_key_locator(hsmkey));
}

static void
printdebugparsablekey(int sockfd, zone_db_t* zone, key_data_t* key, char* tchange, hsm_key_t* hsmkey) {
    (void)tchange;
    client_printf(sockfd,
            "%s;%s;%s;%s;%s;%s;%d;%d;%s\n",
            zone_db_name(zone),
            key_data_role_text(key),
            key_state_state_text(key_data_cached_ds(key)),
            key_state_state_text(key_data_cached_dnskey(key)),
            key_state_state_text(key_data_cached_rrsigdnskey(key)),
            key_state_state_text(key_data_cached_rrsig(key)),
            key_data_publish(key),
            key_data_active_ksk(key) | key_data_active_zsk(key),
            hsm_key_locator(hsmkey));
}

static int
run(cmdhandler_ctx_type* context, int argc, char* argv[])
{
    int sockfd = context->sockfd;
    struct longgetopt optctx;
    int success;
    int bVerbose = 0, bDebug = 0, bFull = 0, bParsable = 0, bAll = 0;
    int long_index = 0, opt = 0;
    const char* keytype = NULL;
    const char* keystate = NULL;
    const char* zonename = NULL;
    db_connection_t* dbconn = getconnectioncontext(context);

    static struct option long_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {"debug", no_argument, 0, 'd'},
        {"full", no_argument, 0, 'f'},
        {"parsable", no_argument, 0, 'p'},
        {"zone", required_argument, 0, 'z'},
        {"keytype", required_argument, 0, 't'},
        {"keystate", required_argument, 0, 'e'},
        {"all", no_argument, 0, 'a'},
        {0, 0, 0, 0}
    };

    for(opt = longgetopt(argc, argv, "vdfpz:t:e:a", long_options, &long_index, &optctx); opt != -1;
        opt = longgetopt(argc, argv, NULL,          long_options, &long_index, &optctx)) {
        switch (opt) {
            case 'v':
                bVerbose = 1;
                break;
            case 'd':
                bDebug = 1;
                break;
            case 'f':
                bFull = 1;
                break;
            case 'p':
                bParsable = 1;
                break;
            case 'z':
                zonename = optctx.optarg;
                break;
            case 't':
                keytype = optctx.optarg;
                break;
            case 'e':
                keystate = optctx.optarg;
                break;
            case 'a':
                bAll = 1;
                break;
            default:
                client_printf_err(sockfd, "unknown arguments\n");
                ods_log_error("[%s] unknown arguments for key list command", module_str);
                return -1;
        }
    }

    if (keystate != NULL && bAll) {
        client_printf(sockfd, "Error: --keystate and --all option cannot be given together\n");
        return -1;
    }

    if (bFull) {
        success = perform_keystate_list(sockfd, dbconn, zonename, keytype, keystate, NULL, &printFullkey);
    } else if (bDebug) {
        if (bParsable) {
            success = perform_keystate_list(sockfd, dbconn, zonename, keytype, keystate, NULL, &printdebugparsablekey);
        } else {
            success = perform_keystate_list(sockfd, dbconn, zonename, keytype, keystate, &printdebugheader, &printdebugkey);
        }
    } else if (bVerbose) {
        if (bParsable) {
            success = perform_keystate_list(sockfd, dbconn, zonename, keytype, keystate, NULL, &printverboseparsablekey);
        } else {
            success = perform_keystate_list(sockfd, dbconn, zonename, keytype, keystate, &printverboseheader, &printverbosekey);
        }
    } else {
        if (bParsable)
            client_printf_err(sockfd, "-p option only available in combination with -v and -d.\n");
        success = perform_keystate_list(sockfd, dbconn, zonename, keytype, keystate, &printcompatheader, &printcompatkey);
    }
    return success;
}

struct cmd_func_block key_list_funcblock = {
	"key list", &usage, &help, NULL, NULL, &run, NULL
};
