#include <ctime>
#include <iostream>
#include <cassert>


// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "zone/zones_cmd.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "daemon/engine.h"
}

#include "policy/kasp.pb.h"

static const char *zones_cmd_str = "zones_cmd";

void help_zones_cmd(int sockfd)
{
    char buf[ODS_SE_MAXLINE];
    (void) snprintf(buf, ODS_SE_MAXLINE,
            "zones           show the currently known zones.\n"
            );
    ods_writen(sockfd, buf, strlen(buf));
}

/**
 * Handle the 'zones' command.
 *
 */
int 
handled_zones_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    size_t i;
    
    if (n != 5 || strncmp(cmd, "zones", n) != 0) return 0;
    ods_log_debug("[%s] list zones command", zones_cmd_str);

    ods_log_assert(engine);
    if (!engine) return 0;
#if HAVE_ZONELIST
    if (!engine->zonelist || !engine->zonelist->zones) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "I have no zones configured\n");
        ods_writen(sockfd, buf, strlen(buf));
        return;
    }
    
    lock_basic_lock(&engine->zonelist->zl_lock);
    /* how many zones */
    /* [LOCK] zonelist */
    (void)snprintf(buf, ODS_SE_MAXLINE, "I have %i zones configured\n",
                   (int) engine->zonelist->zones->count);
    ods_writen(sockfd, buf, strlen(buf));
    
    /* list zones */
    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->data;
        for (i=0; i < ODS_SE_MAXLINE; i++) {
            buf[i] = 0;
        }
        (void)snprintf(buf, ODS_SE_MAXLINE, "- %s\n", zone->name);
        ods_writen(sockfd, buf, strlen(buf));
        node = ldns_rbtree_next(node);
    }
    /* [UNLOCK] zonelist */
    lock_basic_unlock(&engine->zonelist->zl_lock);
#endif
    return 1;
}
