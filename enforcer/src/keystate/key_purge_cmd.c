/* TODO COPYRIGHT */

#include "daemon/engine.h"
#include "cmdhandler.h"
#include "daemon/enforcercommands.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "enforcer/enforce_task.h"
#include "db/dbw.h"
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
		"	--policy <policy> | --zone <zone>	aka -p | -z\n");
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"This command will remove keys from the database and HSM that "
		"are dead. Use with caution.\n"
		"\nOptions:\n"
		"policy		limit the purge to the given policy\n"
		"zone		limit the purge to the given zone\n\n"
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
	const char *zone_name = NULL;
	const char *policy_name = NULL;
	char *buf;
	int argc = 0;
	const char *argv[MAX_ARGS];
	int long_index = 0, opt = 0;
	int error = 0;
        db_connection_t* dbconn = getconnectioncontext(context);

	static struct option long_options[] = {
		{"zone", required_argument, 0, 'z'},
		{"policy", required_argument, 0, 'p'},
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
	while ((opt = getopt_long(argc, (char* const*)argv, "z:p:", long_options, &long_index)) != -1) {
		switch (opt) {
			case 'z':
				zone_name = optarg;
				break;
			case 'p':
				policy_name = optarg;
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

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) {
        free(buf);
        return 1;
    }
    int purged;
    if (zone_name) {
        struct dbw_zone *zone = dbw_get_zone(db, zone_name);
        if (!zone) {
            client_printf_err(sockfd, "unknown zone %s\n", zone_name);
            free(buf);
            dbw_free(db);
            return -1;
        }
        purged = removeDeadKeysNow_zone(sockfd, db, zone);
    } else {
        /* have policy_name since it is mutually exclusive with zone_name */
        struct dbw_policy *policy = dbw_get_policy(db, policy_name);
        if (!policy) {
            client_printf_err(sockfd, "unknown policy %s\n", policy_name);
            free(buf);
            dbw_free(db);
            return -1;
        }
        purged = removeDeadKeysNow_policy(sockfd, db, policy);
    }
    if (purged)
        error = dbw_commit(db);
    dbw_free(db);
    free(buf);
    return error;
}

struct cmd_func_block key_purge_funcblock = {
	"key purge", &usage, &help, NULL, &run
};
