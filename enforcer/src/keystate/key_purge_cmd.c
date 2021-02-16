#include "daemon/engine.h"
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "enforcer/enforce_task.h"
#include "db/key_data.h"
#include "keystate/key_purge.h"

#include "keystate/key_purge_cmd.h"

#include <getopt.h>

#define MAX_ARGS 4

static const char *module_str = "key_purge_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key purge\n"
		"	--policy <policy> | --zone <zone>	aka -p | -z\n"
                "       --delete or -d\n");
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"This command will remove keys from the database (and HSM) that "
		"are dead. Use with caution.\n"
		"\nOptions:\n"
		"policy		limit the purge to the given policy\n"
		"zone		limit the purge to the given zone\n"
                "the -d flag will cause the keys to be deleted from the HSM\n\n"
	);
}


/**
 * Purge
 * @param dbconn, Active database connection
 *
 * @return: error status, >0 on error
 */

static int
run(int sockfd, cmdhandler_ctx_type* context, const char *cmd)
{
	zone_db_t *zone;
	policy_t *policy;
	const char *zone_name = NULL;
	const char *policy_name = NULL;
	char *buf;
	int argc = 0;
	const char *argv[MAX_ARGS];
	int long_index = 0, opt = 0;
	int error = 0;
        int hsmPurge = 0;
        db_connection_t* dbconn = getconnectioncontext(context);

	static struct option long_options[] = {
		{"zone", required_argument, 0, 'z'},
		{"policy", required_argument, 0, 'p'},
		{"delete", no_argument, 0, 'd'},
		{0, 0, 0, 0}
	};

        if (!dbconn) return 1;

	ods_log_debug("[%s] %s command", module_str, key_purge_funcblock.cmdname);

	if (!(buf = strdup(cmd))) {
        	client_printf_err(sockfd, "memory error\n");
	        return -1;
   	}

	argc = ods_str_explode(buf, MAX_ARGS, argv);
	if (argc == -1) {
	client_printf_err(sockfd, "too many arguments\n");
	ods_log_error("[%s] too many arguments for %s command",
                      module_str, key_purge_funcblock.cmdname);
        free(buf);
        return -1;
	}

	optind = 0;
	while ((opt = getopt_long(argc, (char* const*)argv, "z:p:d", long_options, &long_index)) != -1) {
		switch (opt) {
			case 'z':
				zone_name = optarg;
				break;
			case 'p':
				policy_name = optarg;
				break;
			case 'd':
				hsmPurge = 1;
				break;
			default:
				client_printf_err(sockfd, "unknown arguments\n");
				ods_log_error("[%s] unknown arguments for %s command",
						module_str, key_purge_funcblock.cmdname);
				free(buf);
				return -1;
		}
	}

        if ((!zone_name && !policy_name) || (zone_name && policy_name)) {
                ods_log_error("[%s] expected either --zone or --policy", module_str);
                client_printf_err(sockfd, "expected either --zone or --policy \n");
		free(buf);
                return -1;
        }
	
	if (zone_name) {
		zone = zone_db_new(dbconn);
		if (zone_db_get_by_name(zone, zone_name)) {
			client_printf_err(sockfd, "unknown zone %s\n", zone_name);
			zone_db_free(zone);
			zone = NULL;
			free(buf);
			return -1;
		}
		error = removeDeadKeysNow(sockfd, dbconn, NULL, zone, hsmPurge);
		zone_db_free(zone);
		zone = NULL;
		free(buf);
		return error;
	}

	/* have policy_name since it is mutualy exlusive with zone_name */
	policy = policy_new(dbconn);
	if (policy_get_by_name(policy, policy_name)){
		policy_free(policy);
		policy = NULL;
		free(buf);
		client_printf_err(sockfd, "unknown policy %s\n", policy_name);
		return -1;
	}
	error = removeDeadKeysNow(sockfd, dbconn, policy, NULL, hsmPurge);
	policy_free(policy);
	policy = NULL;
	free(buf);
	return error;
}

struct cmd_func_block key_purge_funcblock = {
	"key purge", &usage, &help, NULL, &run
};
