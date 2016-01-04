#include "daemon/engine.h"
#include "daemon/cmdhandler.h"
#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "enforcer/enforce_task.h"
#include "db/key_data.h"
#include "keystate/key_purge.h"

#include "keystate/key_purge_cmd.h"

#define MAX_ARGS 16

static const char *module_str = "key_purge_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key purge           Purge keys from database and HSM which"
			" are dead.\n"
		"	--policy <policy>     (aka -p) \n");
	client_printf(sockfd,
		"key purge  \n"
		"	--zone <zone>         (aka -z) \n");
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"This command will remove keys from the database and HSM that "
		"are dead. Use with caution.\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_purge_funcblock()->cmdname) ? 1 : 0;
}


/**
 * Purge
 * @param dbconn, Active database connection
 *
 * @return: error status, >0 on error
 */

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	zone_t *zone;
	policy_t *policy;
	const char *zone_name = NULL;
	const char *policy_name = NULL;
	char *buf;
	int argc;
	const char *argv[4];
	int error = 0;

        if (!dbconn) return 1;

	ods_log_debug("[%s] %s command", module_str, key_purge_funcblock()->cmdname);
	cmd = ods_check_command(cmd, n, key_purge_funcblock()->cmdname);

	if (!(buf = strdup(cmd))) {
        	client_printf_err(sockfd, "memory error\n");
	        return -1;
   	}

    	argc = ods_str_explode(buf, MAX_ARGS, argv);
	
	ods_find_arg_and_param(&argc, argv, "zone", "z", &zone_name);
	ods_find_arg_and_param(&argc, argv, "policy", "p", &policy_name);


        if ((!zone_name && !policy_name) || (zone_name && policy_name)) {
                ods_log_error("[%s] expected either --zone or --policy", module_str);
                client_printf_err(sockfd, "expected either --zone or --policy \n");
		free(buf);
                return -1;
        }
	
        if (argc) {
                client_printf_err(sockfd, "unknown arguments\n");
                free(buf);
                return -1;
        }

	if (zone_name) {
		zone = zone_new(dbconn);
		if (zone_get_by_name(zone, zone_name)) {
			client_printf_err(sockfd, "unknown zone %s\n", zone_name);
			zone_free(zone);
			zone = NULL;
	                free(buf);
			return -1;
		}
		error = removeDeadKeysNow(sockfd, dbconn, NULL, zone);
		zone_free(zone);
		zone = NULL;
		return error;
	}

	if (policy_name) {
		policy = policy_new(dbconn);
		if (policy_get_by_name(policy, policy_name)){
			policy_free(policy);
			policy = NULL;
	                free(buf);
			client_printf_err(sockfd, "unknown policy %s\n", policy_name);
			return -1;
		}
		error = removeDeadKeysNow(sockfd, dbconn, policy, NULL);
		policy_free(policy);
		policy = NULL;
		return error;
	}
	return -1;
}

static struct cmd_func_block funcblock = {
	"key purge", &usage, &help, &handles, &run
};

struct cmd_func_block*
key_purge_funcblock(void)
{
	return &funcblock;
}
