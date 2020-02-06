#include "config.h"

#include "file.h"
#include "str.h"
#include "locks.h"
#include "log.h"
#include "status.h"
#include "util.h"
#include "daemon/engine.h"
#include "cmdhandler.h"
#include "enforcercommands.h"
#include "db/dbw.h"

/* commands to handle */
#include "policy/policy_resalt_cmd.h"
#include "policy/policy_list_cmd.h"
#include "daemon/help_cmd.h"
#include "daemon/time_leap_cmd.h"
#include "daemon/queue_cmd.h"
#include "daemon/verbosity_cmd.h"
#include "daemon/ctrl_cmd.h"
#include "enforcer/update_repositorylist_cmd.h"
#include "enforcer/repositorylist_cmd.h"
#include "enforcer/update_all_cmd.h"
#include "enforcer/update_conf_cmd.h"
#include "enforcer/enforce_cmd.h"
#include "enforcer/lookahead_cmd.h"
#include "policy/policy_import_cmd.h"
#include "policy/policy_export_cmd.h"
#include "policy/policy_purge_cmd.h"
#include "keystate/zone_list_cmd.h"
#include "keystate/zone_del_cmd.h"
#include "keystate/zone_add_cmd.h"
#include "keystate/zone_set_policy_cmd.h"
#include "keystate/keystate_ds_submit_cmd.h"
#include "keystate/keystate_ds_seen_cmd.h"
#include "keystate/keystate_ds_retract_cmd.h"
#include "keystate/keystate_ds_gone_cmd.h"
#include "keystate/keystate_export_cmd.h"
#include "keystate/keystate_import_cmd.h"
#include "keystate/keystate_list_cmd.h"
#include "keystate/key_purge_cmd.h"
#include "keystate/rollover_list_cmd.h"
#include "keystate/keystate_rollover_cmd.h"
#include "keystate/zonelist_import_cmd.h"
#include "keystate/zonelist_export_cmd.h"
#include "signconf/signconf_cmd.h"
#include "hsmkey/backup_hsmkeys_cmd.h"
#include "hsmkey/key_generate_cmd.h"
#include "hsmkey/hsmkey_list_cmd.h"

static char const * cmdh_str = "cmdhandler";

static struct cmd_func_block* enforcecommands[] = {
        /* Thoughts has gone into the ordering of this list, it affects 
         * the output of the help command */
        &update_conf_funcblock,
        &update_repositorylist_funcblock,
	&repositorylist_funcblock,
        &hsmkey_list_funcblock,
        &update_all_funcblock,
        &policy_list_funcblock,
        &policy_export_funcblock,
        &policy_import_funcblock,
        &policy_purge_funcblock,
        &resalt_funcblock,

        &zone_list_funcblock,
        &zone_add_funcblock,
        &zone_del_funcblock,
        &zone_set_policy_funcblock,

        &zonelist_export_funcblock,
        &zonelist_import_funcblock,

        &key_list_funcblock,
        &key_export_funcblock,
        &key_import_funcblock,
        &key_ds_submit_funcblock,
        &key_ds_seen_funcblock,
        &key_ds_retract_funcblock,
        &key_ds_gone_funcblock,
        &key_generate_funcblock,
	&key_purge_funcblock,

        &key_rollover_funcblock,
        &rollover_list_funcblock,
        
        &backup_funcblock,

        &enforce_funcblock,
        &lookahead_funcblock,
        &signconf_funcblock,


        &queue_funcblock,
        &time_leap_funcblock,
        &flush_funcblock,
        &ctrl_funcblock,
        &verbosity_funcblock,
        &help_funcblock,
        NULL
};

struct cmd_func_block** enforcercommands = enforcecommands;

engine_type*
getglobalcontext(cmdhandler_ctx_type* context)
{
    return (engine_type*) context->globalcontext;
}

db_connection_t*
getconnectioncontext(cmdhandler_ctx_type* context)
{
    return (db_connection_t*) context->localcontext;
}
