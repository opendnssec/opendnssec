/*
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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

#include "daemon/engine.h"
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "file.h"
#include "str.h"
#include "log.h"
#include "clientpipe.h"
#include "db/policy.h"
#include "db/zone_db.h"
#include "keystate/zonelist_update.h"
#include "enforcer/enforce_task.h"
#include "hsmkey/hsm_key_factory.h"

#include "keystate/zone_add_cmd.h"

#include <limits.h>
#include <getopt.h>

static const char *module_str = "zone_add_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"zone add\n"
		"	--zone <zone>				aka -z\n"
		"	[--policy <policy>]			aka -p\n"
		"	[--signerconf <path>]			aka -s\n"
		"	[--in-type <type>]			aka -j\n"
    );
    client_printf(sockfd,
		"	[--input <path>]			aka -i\n"
		"	[--out-type <type>]			aka -q\n"
		"	[--output <path>]			aka -o\n"
		"	[--xml]					aka -u\n"
	);
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Add a new zone to the enforcer database.\n"
	"\nOptions:\n"
        "zone		name of the zone\n"
        "policy		name of the policy, if not set the default policy is used\n"
        "signerconf	specify a location for signer configuration file, default is /var/opendnssec/signconf/\n"
        "in-type		specify the type of input, should be DNS or File, default is File \n"
        "input		specify a location for the unsigned zone, this location is set in conf.xml, default for File Adapter is /var/opendnssec/unsigned/ and for DNS Adapter is /etc/opendnssec/addns.xml \n"
        "out-type	specify the type of output, should be DNS or File, default is File\n"
        "output		specify a location for the signed zone, this location is set in conf.xml, default path for File Adapter is /var/opendnssec/signed/ and for DNS Adapter is /etc/opendnssec/addns.xml \n"
        "xml		update the zonelist.xml file\n\n"
    );
}

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
    #define NARGV 18
    char* buf;
    const char* argv[NARGV];
    int argc = 0;
    const char *zone_name = NULL;
    const char *policy_name = NULL;
    const char *signconf = NULL;
    const char *input = NULL;
    const char *output = NULL;
    const char *input_type = NULL;
    const char *output_type = NULL;
    char path[PATH_MAX];
    int write_xml = 0;
    policy_t* policy;
    zone_db_t* zone;
    int ret = 0;
    int suspend = 0;
    int long_index = 0, opt = 0;
    db_connection_t* dbconn = getconnectioncontext(context);
    engine_type* engine = getglobalcontext(context);

    static struct option long_options[] = {
        {"zone", required_argument, 0, 'z'},
        {"policy", required_argument, 0, 'p'},
        {"signerconf", required_argument, 0, 's'},
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"in-type", required_argument, 0, 'j'},
        {"out-type", required_argument, 0, 'q'},
        {"xml", no_argument, 0, 'u'},
        {"suspend", no_argument, 0, 'n'},
        {0, 0, 0, 0}
    };

    ods_log_debug("[%s] %s command", module_str, zone_add_funcblock.cmdname);

    if (!(buf = strdup(cmd))) {
        client_printf_err(sockfd, "memory error\n");
        return -1;
    }
    argc = ods_str_explode(buf, NARGV, argv);
    if (argc == -1) {
        client_printf_err(sockfd, "too many arguments\n");
        ods_log_error("[%s] too many arguments for %s command",
                      module_str, zone_add_funcblock.cmdname);
        free(buf);
        return -1;
    }

    optind = 0;
    while ((opt = getopt_long(argc, (char* const*)argv, "z:p:s:i:o:j:q:un", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'z':
                zone_name = optarg;
                break;
            case 'p':
                policy_name = optarg;
                break;
            case 's':
                signconf = optarg;
                break;
            case 'i':
                input = optarg;
                break;
            case 'o':
                output = optarg;
                break;
            case 'j':
                input_type = optarg;
                break;
            case 'q':
                output_type = optarg;
                break;
            case 'u':
                write_xml = 1;
                break;
            case 'n':
                suspend = 1;
                break;
            default:
                client_printf_err(sockfd, "unknown arguments\n");
                ods_log_error("[%s] unknown arguments for %s command",
                                module_str, zone_add_funcblock.cmdname);
                free(buf);
                return -1;
        }
    }

    if (!zone_name) {
        client_printf_err(sockfd, "expected option --zone <zone>\n");
        free(buf);
        return -1;
    }

    if ((zone = zone_db_new_get_by_name(dbconn, zone_name))) {
        client_printf_err(sockfd, "Unable to add zone, zone already exists!\n");
        zone_db_free(zone);
        free(buf);
        return 1;
    }

    if (!(policy = policy_new_get_by_name(dbconn, (policy_name ? policy_name : "default")))) {
        client_printf_err(sockfd, "Unable to find policy %s needed for adding the zone!\n", (policy_name ? policy_name : "default"));
        free(buf);
        return 1;
    }

    if (!(zone = zone_db_new(dbconn))) {
        client_printf_err(sockfd, "Unable to add zone, memory allocation problem!\n");
    }
    if (zone_db_set_name(zone, zone_name)) {
        client_printf_err(sockfd, "Unable to add zone, failed to set zone name!\n");
    }
    if (zone_db_set_policy_id(zone, policy_id(policy))) {
        client_printf_err(sockfd, "Unable to add zone, failed to set policy!\n");
    }
    if (input_type) {
        if (!strcasecmp(input_type, "DNS"))
            input_type = "DNS";
        else if (!strcasecmp(input_type, "File"))
            input_type = "File";
        else {
            client_printf_err(sockfd, "Unable to add zone, %s is not a valid input type! in_type must be File or DNS.\n", input_type);
            return 1;
        }
        if (zone_db_set_input_adapter_type(zone, input_type)) {
            client_printf_err(sockfd, "Unable to add zone, failed to set input type!\n");
        }
    }
    if (input) {
        if (input[0] == '/') {
            if (zone_db_set_input_adapter_uri(zone, input)) {
                client_printf_err(sockfd, "Unable to add zone, failed to set input!\n");
            }
        }
        else {
            if (input_type && !strcasecmp(input_type, "DNS")) {
                if (snprintf(path, sizeof(path), "%s/%s", OPENDNSSEC_CONFIG_DIR, input) >= (int)sizeof(path)
                    || zone_db_set_input_adapter_uri(zone, path))
                {
                    client_printf_err(sockfd, "Unable to add zone, failed to set input!\n");
                }
            }
            else {
                if (snprintf(path, sizeof(path), "%s/unsigned/%s", OPENDNSSEC_STATE_DIR, input) >= (int)sizeof(path)
                    || zone_db_set_input_adapter_uri(zone, path))
                {
                    client_printf_err(sockfd, "Unable to add zone, failed to set input!\n");
                }
            }
        }
    }
    else {
        if (input_type && !strcasecmp(input_type, "DNS")) {
            if (snprintf(path, sizeof(path), "%s/addns.xml", OPENDNSSEC_CONFIG_DIR) >= (int)sizeof(path)
                || zone_db_set_input_adapter_uri(zone, path))
            {
                client_printf_err(sockfd, "Unable to add zone, failed to set input!\n");
            }
        }
        else {
            if (snprintf(path, sizeof(path), "%s/unsigned/%s", OPENDNSSEC_STATE_DIR, zone_name) >= (int)sizeof(path)
                || zone_db_set_input_adapter_uri(zone, path))
            {
                client_printf_err(sockfd, "Unable to add zone, failed to set input!\n");
            }
        }
    }
    client_printf(sockfd, "input is set to %s. \n", zone_db_input_adapter_uri(zone));
    if (access(zone_db_input_adapter_uri(zone), F_OK) == -1) {
        client_printf_err(sockfd, "WARNING: The input file %s for zone %s does not currently exist. The zone will be added to the database anyway. \n", zone_db_input_adapter_uri(zone), zone_name);
        ods_log_warning("[%s] WARNING: The input file %s for zone %s does not currently exist. The zone will be added to the database anyway.", module_str, zone_db_input_adapter_uri(zone), zone_name);
    }
    else if (access(zone_db_input_adapter_uri(zone), R_OK)) {
        client_printf_err(sockfd, "WARNING: Read access to input file %s for zone %s denied! \n ", zone_db_input_adapter_uri(zone), zone_name);
        ods_log_warning("[%s] WARNING: Read access to input file %s for zone %s denied! ", module_str, zone_db_input_adapter_uri(zone), zone_name);
    }

    if (output_type) {
        if (!strcasecmp(output_type, "DNS"))
            output_type = "DNS";
        else if (!strcasecmp(output_type, "File"))
            output_type = "File";
        else {
            client_printf_err(sockfd, "Unable to add zone, %s is not a valid output type! out_type must be File or DNS.\n", output_type);
            return 1;
        }
        if (zone_db_set_output_adapter_type(zone, output_type)) {
            client_printf_err(sockfd, "Unable to add zone, failed to set output type!\n");
        }
    }
    if (output) {
        if (output[0] == '/') {
            if (zone_db_set_output_adapter_uri(zone, output)) {
                client_printf_err(sockfd, "Unable to add zone, failed to set output!\n");
            }
        }
        else {
            if (output_type && !strcasecmp(output_type, "DNS")) {
                if (snprintf(path, sizeof(path), "%s/%s", OPENDNSSEC_CONFIG_DIR, output) >= (int)sizeof(path)
                || zone_db_set_output_adapter_uri(zone, path))
                {
                    client_printf_err(sockfd, "Unable to add zone, failed to set output!\n");
                }
            }
	    else {
                if (snprintf(path, sizeof(path), "%s/signed/%s", OPENDNSSEC_STATE_DIR, output) >= (int)sizeof(path)
                    || zone_db_set_output_adapter_uri(zone, path))
                {
                    client_printf_err(sockfd, "Unable to add zone, failed to set output!\n");
                }
            }
        }
    }
    else {
        if(output_type && !strcasecmp(output_type, "DNS")) {
            if (snprintf(path, sizeof(path), "%s/addns.xml", OPENDNSSEC_CONFIG_DIR) >= (int)sizeof(path)
            || zone_db_set_output_adapter_uri(zone, path))
            {
                client_printf_err(sockfd, "Unable to add zone, failed to set output!\n");
            }
        }
        else {
            if (snprintf(path, sizeof(path), "%s/signed/%s", OPENDNSSEC_STATE_DIR, zone_name) >= (int)sizeof(path)
                || zone_db_set_output_adapter_uri(zone, path))
            {
                client_printf_err(sockfd, "Unable to add zone, failed to set output!\n");
            }
        }
    }

    client_printf(sockfd, "output is set to %s. \n", zone_db_output_adapter_uri(zone));
    if (output_type && !strcasecmp(output_type, "DNS")) {
        if (access(zone_db_output_adapter_uri(zone), F_OK) == -1) {
            client_printf_err(sockfd, "WARNING: The output file %s for zone %s does not currently exist. The zone will be added to the database anyway. \n", zone_db_output_adapter_uri(zone), zone_name);
            ods_log_warning("[%s] WARNING: The output file %s for zone %s does not currently exist. The zone will be added to the database anyway.", module_str, zone_db_output_adapter_uri(zone), zone_name);
        }
        else if (access(zone_db_output_adapter_uri(zone), R_OK)) {
            client_printf_err(sockfd, "WARNING: Read access to output file %s for zone %s denied! \n ", zone_db_output_adapter_uri(zone), zone_name);
            ods_log_warning("[%s] WARNING: Read access to output file %s for zone %s denied! ", module_str, zone_db_output_adapter_uri(zone), zone_name);
        }
    }

    if (signconf) {
        if (signconf[0] == '/') {
            if (zone_db_set_signconf_path(zone, signconf)) {
                client_printf_err(sockfd, "Unable to add zone, failed to set signconf!\n");
            }
        }
        else {
            if (snprintf(path, sizeof(path), "%s/signconf/%s", OPENDNSSEC_STATE_DIR, signconf) >= (int)sizeof(path)
                || zone_db_set_signconf_path(zone, path))
            {
                client_printf_err(sockfd, "Unable to add zone, failed to set signconf!\n");
            }
        }
    }
    else {
        if (snprintf(path, sizeof(path), "%s/signconf/%s.xml", OPENDNSSEC_STATE_DIR, zone_name) >= (int)sizeof(path)
            || zone_db_set_signconf_path(zone, path))
        {
            client_printf_err(sockfd, "Unable to add zone, failed to set signconf!\n");
        }
    }
    if (suspend) {
        if (zone_db_set_next_change(zone, -1)) {
            ods_log_error("[%s] Cannot suspend zone %s, database error!", module_str, zone_name);
            client_printf_err(sockfd, "Cannot suspend zone %s, database error!\n", zone_name);
	}
    }

    if (zone_db_create(zone)) {
        client_printf_err(sockfd, "Unable to add zone, database error!\n");
        zone_db_free(zone);
        policy_free(policy);
        free(buf);
        return 1;
    }
    ods_log_info("[%s] zone %s added [policy: %s]", module_str, zone_name, (policy_name ? policy_name : "default"));
    client_printf(sockfd, "Zone %s added successfully\n", zone_name);
    free(buf);

    if (write_xml) {
        if (zonelist_update_add(sockfd, engine->config->zonelist_filename_enforcer, zone, 1) != ZONELIST_UPDATE_OK) {
            ods_log_error("[%s] zonelist %s updated failed", module_str, engine->config->zonelist_filename_enforcer);
            client_printf_err(sockfd, "Zonelist %s update failed!\n", engine->config->zonelist_filename_enforcer);
            ret = 1;
        }
        else {
            ods_log_info("[%s] zonelist %s updated successfully", module_str, engine->config->zonelist_filename_enforcer);
            client_printf(sockfd, "Zonelist %s updated successfully\n", engine->config->zonelist_filename_enforcer);
        }
    }

    if (snprintf(path, sizeof(path), "%s/%s", engine->config->working_dir_enforcer, OPENDNSSEC_ENFORCER_ZONELIST) >= (int)sizeof(path)
        || zonelist_update_add(sockfd, path, zone, 0) != ZONELIST_UPDATE_OK)
    {
        ods_log_error("[%s] internal zonelist update failed", module_str);
        client_printf_err(sockfd, "Unable to update the internal zonelist %s, updates will not reach the Signer!\n", path);
        ret = 1;
    }
    else {
        ods_log_info("[%s] internal zonelist updated successfully", module_str);
    }

    /*
     * On successful generate HSM keys and add/flush enforce task.
     */
    if (!suspend) {
        (void)hsm_key_factory_generate_policy(engine, dbconn, policy, 0);
        ods_log_debug("[%s] Flushing enforce task", module_str);
        (void)schedule_task(engine->taskq, enforce_task(engine, zone->name), 1, 0);
    }

    policy_free(policy);

    zone_db_free(zone);

    return ret;
}

struct cmd_func_block zone_add_funcblock = {
	"zone add", &usage, &help, NULL, &run
};
