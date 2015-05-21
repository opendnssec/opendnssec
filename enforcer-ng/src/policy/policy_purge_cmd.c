#include "daemon/engine.h"
#include "daemon/cmdhandler.h"
#include "shared/log.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"
#include "enforcer/enforce_task.h"
#include "db/policy.h"

#include "policy/policy_purge_cmd.h"

static const char *module_str = "policy_purge_cmd";

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"policy purge           Purge policies from database which"
			" have no associated zones.\n"
	);
}

static void
help(int sockfd)
{
	client_printf(sockfd,
		"This command will remove any policy from the database that "
		"have no zones using it. Use with caution.\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, policy_purge_funcblock()->cmdname) ? 1 : 0;
}

/**
 * Purge
 * @param dbconn, Active database connection
 *
 * @return: error status, >0 on error
 */
static int
purge_policies(int sockfd, db_connection_t *dbconn)
{
	policy_list_t* policy_list;
	policy_t* policy;
	zone_list_t* zonelist;
	const char* name;
	size_t listsize;
	int result = 0;

	client_printf(sockfd, "Purging policies\n");

	policy_list = policy_list_new_get(dbconn);
	if (!policy_list) return 1;

	while ((policy = policy_list_get_next(policy_list))) {
		name = policy_name(policy);
		/*fetch zonelist from db, owned by policy*/
		if (policy_retrieve_zone_list(policy)) {
			result = 1;
			client_printf(sockfd, "Error fetching zones\n");
			break;
		}
		zonelist = policy_zone_list(policy);
		listsize = zone_list_size(zonelist);
		if (listsize == 0) {
			ods_log_info("[%s] No zones on policy %s; purging...", module_str, name);
			client_printf(sockfd, "No zones on policy %s; purging...\n", name);
			if (policy_delete(policy)) {
				ods_log_crit("[%s] Error while purging policy from database", module_str, name);
				client_printf(sockfd, "Error while updating database\n", name);
				result++;
			}
		}
		policy_free(policy);
	}
	policy_list_free(policy_list);
	return result;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	(void)cmd; (void)n; (void)engine;

	ods_log_debug("[%s] %s command", module_str, policy_purge_funcblock()->cmdname);
	if (!dbconn) return 1;
	return purge_policies(sockfd, dbconn);
}

static struct cmd_func_block funcblock = {
	"policy purge", &usage, &help, &handles, &run
};

struct cmd_func_block*
policy_purge_funcblock(void)
{
	return &funcblock;
}

