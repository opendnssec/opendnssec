#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/kasp.pb.h"

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "enforcer/setup_cmd.h"

#include "policy/update_kasp_task.h"
#include "keystate/update_keyzones_task.h"

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
}

static const char *module_str = "setup_cmd";

/**
 * Print help for the 'setup' command
 *
 */
void help_setup_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "setup           delete existing database files and then perform:\n"
        "                  update kasp - to import kasp.xml\n"
        "                  update zonelist - to import zonelist.xml\n"
        );
    ods_writen(sockfd, buf, strlen(buf));
}

static void
delete_database_files(int sockfd, const char *datastore)
{
    char buf[ODS_SE_MAXLINE];
    std::string policy_pb = std::string(datastore) + ".policy.pb";
    std::string keystate_pb = std::string(datastore) + ".keystate.pb";
    std::string hsmkey_pb = std::string(datastore) + ".hsmkey.pb";
    if (unlink(policy_pb.c_str())==-1) {
        ods_log_error("[%s] unlink of \"%s\" failed: %s",
                      module_str,policy_pb.c_str(),strerror(errno));
        (void)snprintf(buf, ODS_SE_MAXLINE, "unlink of \"%s\" failed: %s\n",
                       policy_pb.c_str(),strerror(errno));
        ods_writen(sockfd, buf, strlen(buf));
    }
    if (unlink(keystate_pb.c_str())==-1) {
        ods_log_error("[%s] unlink of \"%s\" failed: %s",
                      module_str,keystate_pb.c_str(),strerror(errno));
        (void)snprintf(buf, ODS_SE_MAXLINE, "unlink of \"%s\" failed: %s\n",
                       keystate_pb.c_str(),strerror(errno));
        ods_writen(sockfd, buf, strlen(buf));
    }
    if (unlink(hsmkey_pb.c_str())==-1) {
        ods_log_error("[%s] unlink of \"%s\" failed: %s",
                      module_str,hsmkey_pb.c_str(),strerror(errno));
        (void)snprintf(buf, ODS_SE_MAXLINE, "unlink of \"%s\" failed: %s\n",
                       hsmkey_pb.c_str(),strerror(errno));
        ods_writen(sockfd, buf, strlen(buf));
    }
}

static void reload_engine(int sockfd, engine_type* engine)
{
    char buf[ODS_SE_MAXLINE];
    ods_log_assert(engine);
    engine->need_to_reload = 1;
    lock_basic_lock(&engine->signal_lock);
    /* [LOCK] signal */
    lock_basic_alarm(&engine->signal_cond);
    /* [UNLOCK] signal */
    lock_basic_unlock(&engine->signal_lock);
    ods_log_debug("[%s] reloading engine...", module_str);
    (void)snprintf(buf, ODS_SE_MAXLINE, "reloading engine...\n");
    ods_writen(sockfd, buf, strlen(buf));
}

/**
 * Handle the 'setup' command.
 *
 */
int handled_setup_cmd(int sockfd, engine_type* engine,
                      const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    const char *scmd = "setup";

    cmd = ods_check_command(cmd,n,scmd);
    if (!cmd)
        return 0; // not handled

    ods_log_debug("[%s] %s command", module_str, scmd);

    time_t tstart = time(NULL);

    delete_database_files(sockfd, engine->config->datastore);

    perform_update_kasp(sockfd, engine->config);

    perform_update_keyzones(sockfd, engine->config);

    reload_engine(sockfd, engine);

    (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                   scmd,time(NULL)-tstart);
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}
