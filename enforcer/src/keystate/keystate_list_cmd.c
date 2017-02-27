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
#include "presentation.h"

#include "db/dbw.h"

#include "keystate/keystate_list_cmd.h"

static const char *module_str = "keystate_list_task";

/* shorter defines to keep keystate table more readable */
#define HID KEY_STATE_STATE_HIDDEN
#define RUM KEY_STATE_STATE_RUMOURED
#define OMN KEY_STATE_STATE_OMNIPRESENT
#define UNR KEY_STATE_STATE_UNRETENTIVE
#define NAV KEY_STATE_STATE_NA

enum {KS_GEN = 0, KS_PUB, KS_RDY, KS_ACT, KS_RET, KS_UNK, KS_MIX};
const char* statenames[] = {"generate", "publish", "ready",
		"active", "retire", "unknown", "mixed"};

/** Map 2.0 states to 1.x states
 * @param p: state of RR higher in the chain (e.g. DS)
 * @param c: state of RR lower in the chain (e.g. DNSKEY)
 * @param introducing: key goal
 * @return: state in 1.x speak
 **/
static int
keystate(int p, int c, int introducing, int dsstate)
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
zskstate(struct dbw_key *key)
{
    return keystate(
        key->keystate[KEY_STATE_TYPE_DNSKEY]->state,
        key->keystate[KEY_STATE_TYPE_RRSIG]->state,
        key->introducing,
        KEY_DATA_DS_AT_PARENT_INVALID);
}

static int
kskstate(struct dbw_key *key)
{
    return keystate(
        key->keystate[KEY_STATE_TYPE_DS]->state,
        key->keystate[KEY_STATE_TYPE_DNSKEY]->state,
        key->introducing,
        key->ds_at_parent);
}

/** Human readable keystate in 1.x speak
 * @param key: key to evaluate
 * @return: state as string
 **/
const char*
map_keystate(struct dbw_key *key)
{
    int z,k;
    switch(key->role) {
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

/*Only a placeholder to make it compile until key export in converted*/
const char *
map_keystate_defunc(key_data_t *k)
{
    return "TODO";
}

/** Time of next transition. Caller responsible for freeing ret
 * @param zone: zone key belongs to
 * @param key: key to evaluate
 * @return: human readable transition time/event */
static char*
map_keytime(const struct dbw_key *key)
{
	char ct[26];
	struct tm srtm;
	time_t t;

	switch(key->ds_at_parent) {
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
	if (key->zone->next_change < 0)
		return strdup("-");
	else if (key->zone->next_change < time_now())
		return strdup("now");

	t = (time_t)key->zone->next_change;
	localtime_r(&t, &srtm);
	strftime(ct, 26, "%Y-%m-%d %H:%M:%S", &srtm);
	return strdup(ct);
}

static int
perform_keystate_list(int sockfd, db_connection_t *dbconn, const char* zonename,
    int keyrole, const char* keystate, void (printheader)(int sockfd),
    void (printkey)(int sockfd, struct dbw_key *key, char* tchange))
{
    struct dbw_list *policies = dbw_policies_all_filtered(dbconn, NULL, zonename, keyrole);
    if (!policies) {
        client_printf_err(sockfd, "Unable to get list of keys, memory "
            "allocation or database error!\n");
        return 1;
    }
    if (printheader) (*printheader)(sockfd);
    for (size_t p = 0; p < policies->n; p++) {
        struct dbw_policy *policy = (struct dbw_policy *)policies->set[p];
        for (size_t z = 0; z < policy->zone_count; z++) {
            struct dbw_zone *zone = policy->zone[z];
            if (zonename && strcmp(zone->name, zonename)) continue;
            for (size_t k = 0; k < zone->key_count; k++) {
                struct dbw_key *key = zone->key[k];
                /*if (keytype && strcasecmp(present_key_role(key->role), keytype)) continue;*/
                if (keystate && strcasecmp(map_keystate(key), keystate)) continue;
                char* tchange = map_keytime(key); /* allocs */
                    (*printkey)(sockfd, key, tchange);
                free(tchange);
            }
        }
    }
    dbw_list_free(policies);
    return 0;
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key list\n"
		"	[--verbose]				aka -v\n"
		"	[--debug]				aka -d\n"
		"	[--parsable]				aka -p\n"
		"	[--zone]				aka -z  \n"
		"	[--type]				aka -t  \n"
		"	[--state]				aka -e  \n"
		"	[--all]                                 aka -a  \n"
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
		"parsable	output machine parsable list\n"
		"zone		limit the output to the specific zone\n"
		"keytype	limit the output to the given type, can be ZSK, KSK, or CSK\n"
		"keystate	limit the output to the given state\n"
		"all		print keys in all states (including generate) \n\n");
}

static void
printcompatheader(int sockfd)
{
    client_printf(sockfd, "Keys:\n");
    client_printf(sockfd, "%-31s %-8s %-9s %s\n", "Zone:", "Keytype:", "State:",
            "Date of next transition:");
}

static void
printcompatkey(int sockfd, struct dbw_key * key, char* tchange)
{
    client_printf(sockfd,
        "%-31s %-8s %-9s %s\n",
        key->zone->name,
        present_key_role(key->role),
        map_keystate(key),
        tchange);
}

static void
printverboseheader(int sockfd)
{
    client_printf(sockfd, "Keys:\n");
    client_printf(sockfd, "%-31s %-8s %-9s %-24s %-5s %-10s %-32s %-11s %s\n", "Zone:", "Keytype:", "State:",
            "Date of next transition:", "Size:", "Algorithm:", "CKA_ID:",
            "Repository:", "KeyTag:");
}

static void
printverbosekey(int sockfd, struct dbw_key * key, char* tchange)
{
    (void)tchange;
    client_printf(sockfd,
        "%-31s %-8s %-9s %-24s %-5d %-10d %-32s %-11s %d\n",
        key->zone->name,
        present_key_role(key->role),
        map_keystate(key),
        tchange,
        key->hsmkey->bits,
        key->hsmkey->algorithm,
        key->hsmkey->locator,
        key->hsmkey->repository,
        key->keytag);
}

static void
printverboseparsablekey(int sockfd, struct dbw_key * key, char* tchange)
{
    client_printf(sockfd,
        "%s;%s;%s;%s;%d;%d;%s;%s;%d\n",
        key->zone->name,
        present_key_role(key->role),
        map_keystate(key),
        tchange,
        key->hsmkey->bits,
        key->hsmkey->algorithm,
        key->hsmkey->locator,
        key->hsmkey->repository,
        key->keytag);
}

static void
printdebugheader(int sockfd) {
    client_printf(sockfd,
            "Keys:\nZone:                           Key role:     "
            "DS:          DNSKEY:      RRSIGDNSKEY: RRSIG:       "
            "Pub: Act: Id:\n");
}

static void
printdebugkey_fmt(int sockfd, char const *fmt, struct dbw_key *key, char const  *tchange)
{
    (void)tchange;
    client_printf(sockfd, fmt,
        key->zone->name,
        present_key_role(key->role),
        present_keystate_state(key->keystate[KEY_STATE_TYPE_DS]->state),
        present_keystate_state(key->keystate[KEY_STATE_TYPE_DNSKEY]->state),
        present_keystate_state(key->keystate[KEY_STATE_TYPE_RRSIGDNSKEY]->state),
        present_keystate_state(key->keystate[KEY_STATE_TYPE_RRSIG]->state),
        key->publish,
        key->active_ksk | key->active_zsk,
        key->hsmkey->locator);
}
static void
printdebugkey(int sockfd, struct dbw_key *key, char *tchange)
{
    printdebugkey_fmt(sockfd, "%-31s %-13s %-12s %-12s %-12s %-12s %d %4d    %s\n", key, tchange);
}
static void
printdebugparsablekey(int sockfd, struct dbw_key *key, char *tchange)
{
    printdebugkey_fmt(sockfd, "%s;%s;%s;%s;%s;%s;%d;%d;%s\n", key, tchange);
}

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
    char buf[ODS_SE_MAXLINE];
    #define NARGV 12
    const char *argv[NARGV];
    int success, argIndex;
    int argc = 0, bVerbose = 0, bDebug = 0, bParsable = 0, bAll = 0;
    int long_index = 0, opt = 0;
    const char* keytype = NULL;
    const char* keystate = NULL;
    const char* zonename = NULL;
    db_connection_t* dbconn = getconnectioncontext(context);

    static struct option long_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {"debug", no_argument, 0, 'd'},
        {"parsable", no_argument, 0, 'p'},
        {"zone", required_argument, 0, 'z'},
        {"keytype", required_argument, 0, 't'},
        {"keystate", required_argument, 0, 'e'},
        {"all", no_argument, 0, 'a'},
        {0, 0, 0, 0}
    };

    ods_log_debug("[%s] %s command", module_str, key_list_funcblock.cmdname);

    /* Use buf as an intermediate buffer for the command. */
    strncpy(buf, cmd, sizeof (buf));
    buf[sizeof (buf) - 1] = '\0';

    /* separate the arguments */
    argc = ods_str_explode(buf, NARGV, argv);
    if (argc == -1) {
        ods_log_error("[%s] too many arguments for %s command",
                module_str, key_list_funcblock.cmdname);
        client_printf_err(sockfd, "too many arguments\n");
        return -1;
    }
    optind = 0;
    while ((opt = getopt_long(argc, (char* const*)argv, "vdpz:t:e:a", long_options, &long_index) ) != -1) {
        switch (opt) {
            case 'v':
                bVerbose = 1;
                break;
            case 'd':
                bDebug = 1;
                break;
            case 'p':
                bParsable = 1;
                break;
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
                bAll = 1;
                break;
            default:
                client_printf_err(sockfd, "unknown arguments\n");
                ods_log_error("[%s] unknown arguments for %s command",
                              module_str, key_list_funcblock.cmdname);
                return -1;
        }
    }
    int keyrole = 0;
    if (keytype) {
        if (!strcasecmp("ksk", keytype))
            keyrole = 1;
        else if (!strcasecmp("zsk", keytype))
            keyrole = 2;
        else if (!strcasecmp("csk", keytype))
            keyrole = 3;
        else
            keyrole = -1;
    }
    if (keyrole == -1) {
        client_printf(sockfd, "Error: keytype not reconized. Must be either [KSK,ZSK,CSK].\n");
        return -1;
    }

    if (keystate != NULL && bAll) {
        client_printf(sockfd, "Error: --keystate and --all option cannot be given together\n");
        return -1;
    }

    if (bDebug) {
        if (bParsable) {
            success = perform_keystate_list(sockfd, dbconn, zonename, keyrole,
                keystate, NULL, &printdebugparsablekey);
        } else {
            success = perform_keystate_list(sockfd, dbconn, zonename, keyrole,
                keystate, &printdebugheader, &printdebugkey);
        }
    } else if (bVerbose) {
        if (bParsable) {
            success = perform_keystate_list(sockfd, dbconn, zonename, keyrole,
                keystate, NULL, &printverboseparsablekey);
        } else {
            success = perform_keystate_list(sockfd, dbconn, zonename, keyrole,
                keystate, &printverboseheader, &printverbosekey);
        }
    } else {
        if (bParsable)
            client_printf_err(sockfd, "-p option only available in combination with -v and -d.\n");
        success = perform_keystate_list(sockfd, dbconn, zonename, keyrole,
            keystate, &printcompatheader, &printcompatkey);
    }
    return success;
}

struct cmd_func_block key_list_funcblock = {
	"key list", &usage, &help, NULL, &run
};
