#include <ctime>
#include <iostream>
#include <cassert>

#include "policy/kasp.pb.h"

#include "enforcer/setup_cmd.h"

#include "policy/update_kasp_task.h"
#include "keystate/update_keyzones_task.h"
#include "hsmkey/hsmkey_gen_task.h"    

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"

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
    if (unlink(policy_pb.c_str())==-1 && errno!=ENOENT) {
        ods_log_error("[%s] unlink of \"%s\" failed: %s",
                      module_str,policy_pb.c_str(),strerror(errno));
        (void)snprintf(buf, ODS_SE_MAXLINE, "unlink of \"%s\" failed: %s (%d)\n",
                       policy_pb.c_str(),strerror(errno),errno);
        ods_writen(sockfd, buf, strlen(buf));
    }
    if (unlink(keystate_pb.c_str())==-1 && errno!=ENOENT) {
        ods_log_error("[%s] unlink of \"%s\" failed: %s",
                      module_str,keystate_pb.c_str(),strerror(errno));
        (void)snprintf(buf, ODS_SE_MAXLINE, "unlink of \"%s\" failed: %s (%d)\n",
                       keystate_pb.c_str(),strerror(errno),errno);
        ods_writen(sockfd, buf, strlen(buf));
    }
    if (unlink(hsmkey_pb.c_str())==-1 && errno!=ENOENT) {
        ods_log_error("[%s] unlink of \"%s\" failed: %s",
                      module_str,hsmkey_pb.c_str(),strerror(errno));
        (void)snprintf(buf, ODS_SE_MAXLINE, "unlink of \"%s\" failed: %s (%d)\n",
                       hsmkey_pb.c_str(),strerror(errno),errno);
        ods_writen(sockfd, buf, strlen(buf));
    }
}

static void flush_all_tasks(int sockfd, engine_type* engine)
{
    char buf[ODS_SE_MAXLINE];
    ods_log_debug("[%s] flushing all tasks...", module_str);
    (void)snprintf(buf, ODS_SE_MAXLINE, "flushing all tasks...\n");
    ods_writen(sockfd, buf, strlen(buf));
    
    ods_log_assert(engine);
    ods_log_assert(engine->taskq);
    lock_basic_lock(&engine->taskq->schedule_lock);
    /* [LOCK] schedule */
    schedule_flush(engine->taskq, TASK_NONE);
    /* [UNLOCK] schedule */
    lock_basic_unlock(&engine->taskq->schedule_lock);
    engine_wakeup_workers(engine);
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
    perform_hsmkey_gen(sockfd, engine->config, 0 /* automatic */);

    flush_all_tasks(sockfd, engine);

    (void)snprintf(buf, ODS_SE_MAXLINE, "%s completed in %ld seconds.\n",
                   scmd,time(NULL)-tstart);
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}
