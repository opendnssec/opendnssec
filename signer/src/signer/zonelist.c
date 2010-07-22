/*
 * $Id$
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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

/**
 *
 * The zonelist and all.
 */

#include "config.h"
#include "parser/confparser.h"
#include "parser/zonelistparser.h"
#include "scheduler/task.h"
#include "signer/zone.h"
#include "signer/zonelist.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h> /* ldns_dname_compare(), ldns_rbtree_*() */


/**
 * Compare two zones.
 *
 */
static int
zone_compare(const void* a, const void* b)
{
    zone_type* x = (zone_type*)a;
    zone_type* y = (zone_type*)b;

    se_log_assert(x);
    se_log_assert(y);

    if (x->klass != y->klass) {
        if (x->klass < y->klass) {
            return -1;
        }
        return 1;
    }
    return ldns_dname_compare(x->dname, y->dname);
}


/**
 * Create a new zone list.
 *
 */
zonelist_type*
zonelist_create(void)
{
    zonelist_type* zlist = (zonelist_type*) se_malloc(sizeof(zonelist_type));
    zlist->zones = ldns_rbtree_create(zone_compare);
    zlist->last_modified = 0;
    return zlist;
}


/**
 * Read a zonelist file.
 *
 */
zonelist_type*
zonelist_read(const char* zonelistfile, time_t last_modified)
{
    zonelist_type* zlist = NULL;
    const char* rngfile = ODS_SE_RNGDIR "/zonelist.rng";
    time_t st_mtime = 0;

    se_log_assert(zonelistfile);
    se_log_verbose("read zone list file %s", zonelistfile);

    /* is the file updated? */
    st_mtime = se_file_lastmodified(zonelistfile);
    if (st_mtime <= last_modified) {
        se_log_debug("zone list file %s is unchanged", zonelistfile);
        return NULL;
    }
    /* does the file have no parse errors? */
    if (parse_file_check(zonelistfile, rngfile) != 0) {
        se_log_error("unable to parse zone list file %s", zonelistfile);
        return NULL;
    }
    /* ok, parse it! */
    zlist = parse_zonelist_zones(zonelistfile);
    if (zlist) {
        zlist->last_modified = st_mtime;
    } else {
        se_log_error("unable to read zone list file %s", zonelistfile);
        return NULL;
    }
    return zlist;
}


/**
 * Lock all zones in zone list.
 *
 */
void
zonelist_lock(zonelist_type* zonelist)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;

    se_log_assert(zonelist);
    se_log_assert(zonelist->zones);

    node = ldns_rbtree_first(zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->key;
        lock_basic_lock(&zone->zone_lock);
        node = ldns_rbtree_next(node);
    }
    return;
}

/**
 * Lock all zones in zone list.
 *
 */
void
zonelist_unlock(zonelist_type* zonelist)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;

    se_log_assert(zonelist);
    se_log_assert(zonelist->zones);

    node = ldns_rbtree_first(zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->key;
        lock_basic_unlock(&zone->zone_lock);
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Convert a zone to a tree node.
 *
 */
static ldns_rbnode_t*
zone2node(zone_type* zone)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) se_malloc(sizeof(ldns_rbnode_t));
    node->key = zone;
    node->data = zone;
    return node;
}


/**
 * Lookup zone.
 *
 */
static zone_type*
zonelist_lookup_zone(zonelist_type* zonelist, zone_type* zone)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    se_log_assert(zonelist);
    se_log_assert(zonelist->zones);
    se_log_assert(zone);

    node = ldns_rbtree_search(zonelist->zones, zone);
    if (node) {
        return (zone_type*) node->key;
    }
    return NULL;
}


/**
 * Add zone.
 *
 */
zone_type*
zonelist_add_zone(zonelist_type* zonelist, zone_type* zone)
{
    ldns_rbnode_t* new_node = NULL;

    se_log_assert(zonelist);
    se_log_assert(zonelist->zones);
    se_log_assert(zone);

    if (zonelist_lookup_zone(zonelist, zone) != NULL) {
        se_log_warning("unable to add zone %s: already present", zone->name);
        zone_cleanup(zone);
        return NULL;
    }

    new_node = zone2node(zone);
    if (ldns_rbtree_insert(zonelist->zones, new_node) == NULL) {
        se_log_error("unable to add zone %s: rbtree insert failed", zone->name);
        zone_cleanup(zone);
        se_free((void*) new_node);
        return NULL;
    }
    zone->just_added = 1;
    return zone;
}


/**
 * Delete a zone
 *
 */
static zone_type*
zonelist_delete_zone(zonelist_type* zonelist, zone_type* zone)
{
    ldns_rbnode_t* old_node = LDNS_RBTREE_NULL;

    se_log_assert(zonelist);
    se_log_assert(zonelist->zones);
    se_log_assert(zone);

    old_node = ldns_rbtree_delete(zonelist->zones, zone);
    if (!old_node) {
        se_log_warning("unable to delete zone %s: not present", zone->name);
        return zone;
    }

    se_free((void*) old_node);
    zone_cleanup(zone);
    return NULL;
}


/**
 * Update zone list.
 *
 */
void
zonelist_update(zonelist_type* zl, struct tasklist_struct* tl, char* buf)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;
    task_type* task = NULL;
    int just_removed = 0;
    int just_added = 0;
    int just_updated = 0;

    se_log_debug("update zone list");

    node = ldns_rbtree_first(zl->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->key;
        /* removed */
        if (zone->tobe_removed) {
            if (zone->task) {
                /* remove task from queue */
                task = tasklist_delete_task(tl, zone->task);
                task_cleanup(task);
            }
            node = ldns_rbtree_next(node);
            se_log_debug("delete zone %s from zone list", zone->name);
            lock_basic_unlock(&zone->zone_lock);
            (void)zonelist_delete_zone(zl, zone);
            zone = NULL;
            just_removed++;
            continue;
        }
        /* added */
        else if (zone->just_added) {
            zone->just_added = 0;
            just_added++;
        }
        /* updated */
        else if (zone->just_updated) {
            zone->just_updated = 0;
            just_updated++;
        }

        node = ldns_rbtree_next(node);
    }

    if (buf) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "Zone list updated: %i removed, %i added, "
            "%i updated.\n", just_removed, just_added, just_updated);
    }
    return;
}


/**
 * Merge zone lists.
 *
 */
void
zonelist_merge(zonelist_type* zl1, zonelist_type* zl2)
{
    zone_type* z1 = NULL;
    zone_type* z2 = NULL;
    ldns_rbnode_t* n1 = LDNS_RBTREE_NULL;
    ldns_rbnode_t* n2 = LDNS_RBTREE_NULL;
    int ret = 0;

    se_log_assert(zl1);
    se_log_assert(zl2);
    se_log_assert(zl1->zones);
    se_log_assert(zl2->zones);

    n1 = ldns_rbtree_first(zl1->zones);
    n2 = ldns_rbtree_first(zl2->zones);
    while (n2 && n2 != LDNS_RBTREE_NULL) {
        z2 = (zone_type*) n2->key;
        if (n1 && n1 != LDNS_RBTREE_NULL) {
            z1 = (zone_type*) n1->key;
        } else {
            z1 = NULL;
        }

        if (!z2) {
            /* no more zones to merge into zl1 */
            return;
        } else if (!z1) {
            /* just add remaining zones from zl2 */
            se_log_debug("add zone %s to zone list", z2->name);
            z2 = zonelist_add_zone(zl1, z2);
            if (!z2) {
                se_log_error("zone list merge failed, z2 not added");
                return;
            }
            lock_basic_lock(&z2->zone_lock);
            n2 = ldns_rbtree_next(n2);
        } else {
            /* compare the zones z1 and z2 */
            ret = zone_compare(z1, z2);
            if (ret < 0) {
                /* remove zone z1, it is not present in the new zonelist zl2 */
                z1->tobe_removed = 1;
                n1 = ldns_rbtree_next(n1);
            } else if (ret > 0) {
                /* add the new zone z2 */
                se_log_debug("add zone %s to zone list", z2->name);
                z2 = zonelist_add_zone(zl1, z2);
                if (!z2) {
                    se_log_error("zone list merge failed, z2 not added");
                    return;
                }
                lock_basic_lock(&z2->zone_lock);
                n2 = ldns_rbtree_next(n2);
            } else {
                /* just update zone z1 */
                n1 = ldns_rbtree_next(n1);
                n2 = ldns_rbtree_next(n2);
                zone_update_zonelist(z1, z2);
            }
        }
    }

    /* remove remaining zones from z1 */
    while (n1 && n1 != LDNS_RBTREE_NULL) {
        z1 = (zone_type*) n1->key;
        z1->tobe_removed = 1;
        n1 = ldns_rbtree_next(n1);
    }

    zl1->last_modified = zl2->last_modified;
    if (zl2->zones) {
        se_rbnode_free(zl2->zones->root);
        ldns_rbtree_free(zl2->zones);
    }
    se_free((void*) zl2);
    return;
}


/**
 * Clean up a zonelist.
 *
 */
void
zonelist_cleanup(zonelist_type* zonelist)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;

    if (zonelist) {
        if (zonelist->zones) {
            node = ldns_rbtree_first(zonelist->zones);
            while (node != LDNS_RBTREE_NULL) {
                zone = (zone_type*) node->key;
                zone_cleanup(zone);
                node = ldns_rbtree_next(node);
            }
            se_rbnode_free(zonelist->zones->root);
            ldns_rbtree_free(zonelist->zones);
            zonelist->zones = NULL;
        }
        se_free((void*) zonelist);
    } else {
        se_log_warning("cleanup empty zone list");
    }
}
