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

#include "daemon/engine.h"
#include "daemon/cmdhandler.h"
#include "shared/file.h"
#include "shared/str.h"
#include "shared/log.h"
#include "daemon/clientpipe.h"
#include "db/policy.h"
#include "db/zone.h"
#include "keystate/zonelist_update.h"

#include "keystate/zone_add_cmd.h"

#include <limits.h>

static const char *module_str = "zone_add_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"zone add               Add a new zone to the enforcer database.\n"
		"      --zone <zone>              (aka -z)  zone.\n"
		"      [--policy <policy>]        (aka -p)  policy.\n"
		"      [--signerconf <path>]      (aka -s)  signer configuration file.\n"
		"      [--in-type <type>]         (aka -j)  input adapter type.\n"
    );
    client_printf(sockfd,
		"      [--input <path>]           (aka -i)  input adapter zone or config file.\n"
		"      [--out-type <type>]        (aka -q)  output adapter type.\n"
		"      [--output <path>]          (aka -o)  output adapter zone or config file.\n"
		"      [--xml]                    (aka -u)  update the zonelist.xml file.\n"
	);
}

static void
help(int sockfd)
{
    client_printf(sockfd,
        "Add a new zone to the enforcer database.\n"
    );
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, zone_add_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
    char* buf;
    const char* argv[17];
    int argc;
    const char *zone_name = NULL;
    const char *policy_name = NULL;
    const char *signconf = NULL;
    const char *input = NULL;
    const char *output = NULL;
    const char *input_type = NULL;
    const char *output_type = NULL;
    char path[PATH_MAX];
    int write_xml;
    policy_t* policy;
    zone_t* zone;
    (void)engine;

	ods_log_debug("[%s] %s command", module_str, zone_add_funcblock()->cmdname);
    cmd = ods_check_command(cmd, n, zone_add_funcblock()->cmdname);

    if (!(buf = strdup(cmd))) {
        client_printf_err(sockfd, "memory error\n");
        return -1;
    }

    argc = ods_str_explode(buf, 17, argv);
    if (argc > 17) {
        client_printf_err(sockfd, "too many arguments\n");
        free(buf);
        return -1;
    }

    ods_find_arg_and_param(&argc, argv, "zone", "z", &zone_name);
    ods_find_arg_and_param(&argc, argv, "policy", "p", &policy_name);
    ods_find_arg_and_param(&argc, argv, "signerconf", "s", &signconf);
    ods_find_arg_and_param(&argc, argv, "input", "i", &input);
    ods_find_arg_and_param(&argc, argv, "output", "o", &output);
    ods_find_arg_and_param(&argc, argv, "in-type", "j", &input_type);
    ods_find_arg_and_param(&argc, argv, "out-type", "q", &output_type);
    write_xml = ods_find_arg(&argc, argv, "xml", "u") > -1 ? 1 : 0;

    if (argc) {
        client_printf_err(sockfd, "unknown arguments\n");
        free(buf);
        return -1;
    }
    if (!zone_name) {
        client_printf_err(sockfd, "expected option --zone <zone>\n");
        free(buf);
        return -1;
    }

    if ((zone = zone_new_get_by_name(dbconn, zone_name))) {
        client_printf_err(sockfd, "Unable to add zone, zone already exists!\n");
        zone_free(zone);
        free(buf);
        return 1;
    }

    if (!(policy = policy_new_get_by_name(dbconn, (policy_name ? policy_name : "default")))) {
        client_printf_err(sockfd, "Unable to find policy %s needed for adding the zone!\n", (policy_name ? policy_name : "default"));
        free(buf);
        return 1;
    }

    if (!(zone = zone_new(dbconn))) {
        client_printf_err(sockfd, "Unable to add zone, memory allocation problem!\n");
    }
    if (zone_set_name(zone, zone_name)) {
        client_printf_err(sockfd, "Unable to add zone, failed to set zone name!\n");
    }
    if (zone_set_policy_id(zone, policy_id(policy))) {
        client_printf_err(sockfd, "Unable to add zone, failed to set policy!\n");
    }
    if (input_type && zone_set_input_adapter_type(zone, input_type)) {
        client_printf_err(sockfd, "Unable to add zone, failed to set input type!\n");
    }
    if (input) {
        if (input[0] == '/') {
            if (zone_set_input_adapter_uri(zone, input)) {
                client_printf_err(sockfd, "Unable to add zone, failed to set input!\n");
            }
        }
        else {
            if (snprintf(path, sizeof(path), "%s/unsigned/%s", OPENDNSSEC_STATE_DIR, input) >= (int)sizeof(path)
                || zone_set_input_adapter_uri(zone, path))
            {
                client_printf_err(sockfd, "Unable to add zone, failed to set input!\n");
            }
        }
    }
    else {
        if (snprintf(path, sizeof(path), "%s/unsigned/%s", OPENDNSSEC_STATE_DIR, zone_name) >= (int)sizeof(path)
            || zone_set_input_adapter_uri(zone, path))
        {
            client_printf_err(sockfd, "Unable to add zone, failed to set input!\n");
        }
    }
    if (output_type && zone_set_output_adapter_type(zone, output_type)) {
        client_printf_err(sockfd, "Unable to add zone, failed to set output type!\n");
    }
    if (output) {
        if (output[0] == '/') {
            if (zone_set_output_adapter_uri(zone, output)) {
                client_printf_err(sockfd, "Unable to add zone, failed to set output!\n");
            }
        }
        else {
            if (snprintf(path, sizeof(path), "%s/signed/%s", OPENDNSSEC_STATE_DIR, output) >= (int)sizeof(path)
                || zone_set_output_adapter_uri(zone, path))
            {
                client_printf_err(sockfd, "Unable to add zone, failed to set output!\n");
            }
        }
    }
    else {
        if (snprintf(path, sizeof(path), "%s/signed/%s", OPENDNSSEC_STATE_DIR, zone_name) >= (int)sizeof(path)
            || zone_set_output_adapter_uri(zone, path))
        {
            client_printf_err(sockfd, "Unable to add zone, failed to set output!\n");
        }
    }
    if (signconf) {
        if (signconf[0] == '/') {
            if (zone_set_signconf_path(zone, signconf)) {
                client_printf_err(sockfd, "Unable to add zone, failed to set signconf!\n");
            }
        }
        else {
            if (snprintf(path, sizeof(path), "%s/signconf/%s", OPENDNSSEC_STATE_DIR, signconf) >= (int)sizeof(path)
                || zone_set_signconf_path(zone, path))
            {
                client_printf_err(sockfd, "Unable to add zone, failed to set signconf!\n");
            }
        }
    }
    else {
        if (snprintf(path, sizeof(path), "%s/signconf/%s", OPENDNSSEC_STATE_DIR, zone_name) >= (int)sizeof(path)
            || zone_set_signconf_path(zone, path))
        {
            client_printf_err(sockfd, "Unable to add zone, failed to set signconf!\n");
        }
    }

    if (zone_create(zone)) {
        client_printf_err(sockfd, "Unable to add zone, database error!\n");
        zone_free(zone);
        policy_free(policy);
        free(buf);
        return 1;
    }
    ods_log_info("[zone_add_cmd] zone %s added [policy: %s]", zone_name, (policy_name ? policy_name : "default"));
    client_printf(sockfd, "Zone added successfully\n");
    policy_free(policy);
    free(buf);

    if (write_xml
        && zonelist_update_add(engine->config->zonelist_filename, zone) != ZONELIST_UPDATE_OK)
    {
        client_printf_err(sockfd, "Zonelist update failed!\n");
        zone_free(zone);
        return 1;
    }
    client_printf(sockfd, "Zonelist updated successfully!\n");

    zone_free(zone);
    return 0;
}

static struct cmd_func_block funcblock = {
	"zone add", &usage, &help, &handles, &run
};

struct cmd_func_block*
zone_add_funcblock(void)
{
	return &funcblock;
}
