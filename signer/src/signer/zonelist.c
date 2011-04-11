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
#include "shared/allocator.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/status.h"
#include "signer/zone.h"
#include "signer/zonelist.h"

#include <ldns/ldns.h>
#include <stdlib.h>

static const char* zl_str = "zonelist";


/**
 * Compare two zones.
 *
 */
static int
zone_compare(const void* a, const void* b)
{
    zone_type* x = (zone_type*)a;
    zone_type* y = (zone_type*)b;

    ods_log_assert(x);
    ods_log_assert(y);

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
zonelist_create(allocator_type* allocator)
{
    zonelist_type* zlist;
    if (!allocator) {
        ods_log_error("[%s] cannot create: no allocator available", zl_str);
        return NULL;
    }
    ods_log_assert(allocator);

    zlist = (zonelist_type*) allocator_alloc(allocator, sizeof(zonelist_type));
    if (!zlist) {
        ods_log_error("[%s] cannot create: allocator failed", zl_str);
        return NULL;
    }
    ods_log_assert(zlist);

    zlist->allocator = allocator;
    zlist->zones = ldns_rbtree_create(zone_compare);
    zlist->last_modified = 0;
    lock_basic_init(&zlist->zl_lock);
    return zlist;
}


/**
 * Read a zonelist file.
 *
 */
static ods_status
zonelist_read(zonelist_type* zl, const char* zlfile)
{
    const char* rngfile = ODS_SE_RNGDIR "/zonelist.rng";
    ods_status status = ODS_STATUS_OK;

    ods_log_assert(zlfile);
    ods_log_verbose("[%s] read file %s", zl_str, zlfile);

    /* does the file have no parse errors? */
    status = parse_file_check(zlfile, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to parse file %s: %s", zl_str,
            zlfile, ods_status2str(status));
        return status;
    }

    /* ok, parse it */
    return parse_zonelist_zones((struct zonelist_struct*) zl, zlfile);
}


/**
 * Convert a zone to a tree node.
 *
 */
static ldns_rbnode_t*
zone2node(zone_type* zone)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    if (!node) {
        return NULL;
    }
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

    if (!zonelist || !zonelist->zones) {
        ods_log_error("[%s] unable to lookup zone: no zonelist", zl_str);
        return NULL;
    }
    ods_log_assert(zonelist);
    ods_log_assert(zonelist->zones);
    if (!zone) {
        ods_log_error("[%s] unable to lookup zone: zone is null", zl_str);
        return NULL;
    }
    ods_log_assert(zone);

    node = ldns_rbtree_search(zonelist->zones, zone);
    if (node) {
        return (zone_type*) node->data;
    }
    return NULL;
}


/**
 * Lookup zone by name.
 *
 */
zone_type*
zonelist_lookup_zone_by_name(zonelist_type* zonelist, const char* name,
    ldns_rr_class klass)
{
    zone_type* zone = NULL;
    zone_type* result = NULL;

    if (!zonelist || !zonelist->zones || !name || !klass) {
        return NULL;
    }
    ods_log_assert(zonelist);
    ods_log_assert(zonelist->zones);
    ods_log_assert(name);
    ods_log_assert(klass);

    zone = zone_create((char*) name, klass);
    if (!zone) {
        ods_log_error("[%s] unable to lookup zone: create zone failed", zl_str);
        return NULL;
    }
    result = zonelist_lookup_zone(zonelist, zone);
    zone_cleanup(zone);
    return result;
}


/**
 * Add zone.
 *
 */
zone_type*
zonelist_add_zone(zonelist_type* zlist, zone_type* zone)
{
    ldns_rbnode_t* new_node = NULL;

    if (!zone) {
        ods_log_error("[%s] unable to add zone: zone is null", zl_str);
        return NULL;
    }
    ods_log_assert(zone);
    if (!zlist || !zlist->zones) {
        ods_log_error("[%s] unable to add zone %s: no zonelist", zl_str,
            zone->name);
        zone_cleanup(zone);
        return NULL;
    }
    ods_log_assert(zlist);
    ods_log_assert(zlist->zones);

    if (zonelist_lookup_zone(zlist, zone) != NULL) {
        ods_log_warning("[%s] unable to add zone %s: already present", zl_str,
            zone->name);
        zone_cleanup(zone);
        return NULL;
    }

    new_node = zone2node(zone);
    if (ldns_rbtree_insert(zlist->zones, new_node) == NULL) {
        ods_log_error("[%s] unable to add zone %s: rbtree insert failed",
            zl_str, zone->name);
        free((void*) new_node);
        zone_cleanup(zone);
        return NULL;
    }
    zone->just_added = 1;
    zlist->just_added++;
    return zone;
}


/**
 * Delete zone.
 *
 */
zone_type*
zonelist_del_zone(zonelist_type* zlist, zone_type* zone)
{
    ldns_rbnode_t* old_node = LDNS_RBTREE_NULL;

    if (!zone) {
        ods_log_warning("[%s] unable to delete zone %s: zone is null", zl_str);
        return NULL;
    }
    ods_log_assert(zone);
    if (!zlist || !zlist->zones) {
        ods_log_error("[%s] unable to delete zone %s: no zone list", zl_str,
            zone->name);
        return zone;
    }
    ods_log_assert(zlist);
    ods_log_assert(zlist->zones);

    old_node = ldns_rbtree_delete(zlist->zones, zone);
    if (!old_node) {
        ods_log_warning("[%s] unable to delete zone %s: not present", zl_str,
            zone->name);
        return zone;
    }
    free((void*) old_node);
    return zone;
}


/**
 * Merge zone lists.
 *
 */
static void
zonelist_merge(zonelist_type* zl1, zonelist_type* zl2)
{
    zone_type* z1 = NULL;
    zone_type* z2 = NULL;
    ldns_rbnode_t* n1 = LDNS_RBTREE_NULL;
    ldns_rbnode_t* n2 = LDNS_RBTREE_NULL;
    int ret = 0;

    ods_log_assert(zl1);
    ods_log_assert(zl2);
    ods_log_assert(zl1->zones);
    ods_log_assert(zl2->zones);
    ods_log_debug("[%s] merge two zone lists", zl_str);

    n1 = ldns_rbtree_first(zl1->zones);
    n2 = ldns_rbtree_first(zl2->zones);
    while (n2 && n2 != LDNS_RBTREE_NULL) {
        z2 = (zone_type*) n2->data;
        if (n1 && n1 != LDNS_RBTREE_NULL) {
            z1 = (zone_type*) n1->data;
        } else {
            z1 = NULL;
        }

        if (!z2) {
            /* no more zones to merge into zl1 */
            return;
        } else if (!z1) {
            /* just add remaining zones from zl2 */
            z2 = zonelist_add_zone(zl1, z2);
            if (!z2) {
                ods_log_error("[%s] merge failed: z2 not added", zl_str);
                return;
            }
            n2 = ldns_rbtree_next(n2);
        } else {
            /* compare the zones z1 and z2 */
            ret = zone_compare(z1, z2);
            if (ret < 0) {
                /* remove zone z1, it is not present in the new list zl2 */
                z1->tobe_removed = 1;
                zl1->just_removed++;
                n1 = ldns_rbtree_next(n1);
            } else if (ret > 0) {
                /* add the new zone z2 */
                z2 = zonelist_add_zone(zl1, z2);
                if (!z2) {
                    ods_log_error("[%s] merge failed: z2 not added", zl_str);
                    return;
                }
                n2 = ldns_rbtree_next(n2);
            } else {
                /* just update zone z1 */
                n1 = ldns_rbtree_next(n1);
                n2 = ldns_rbtree_next(n2);
                zone_merge(z1, z2);
                zone_cleanup(z2);
                if (z1->just_updated) {
                    zl1->just_updated++;
                }
                z1->just_updated = 1;
            }
        }
    }

    /* remove remaining zones from z1 */
    while (n1 && n1 != LDNS_RBTREE_NULL) {
        z1 = (zone_type*) n1->data;
        z1->tobe_removed = 1;
        zl1->just_removed++;
        n1 = ldns_rbtree_next(n1);
    }

    zl1->last_modified = zl2->last_modified;
    return;
}


/**
 * Update zone list.
 *
 */
ods_status
zonelist_update(zonelist_type* zl, const char* zlfile)
{
    zonelist_type* new_zlist = NULL;
    allocator_type* tmp_alloc = NULL;
    time_t st_mtime = 0;
    ods_status status = ODS_STATUS_OK;
    char* datestamp = NULL;
    uint32_t ustamp = 0;

    ods_log_debug("[%s] update zone list", zl_str);
    if (!zl|| !zl->zones) {
        ods_log_error("[%s] cannot update: no zonelist storaga", zl_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zl);
    ods_log_assert(zl->zones);
    if (!zlfile) {
        ods_log_error("[%s] cannot update: no filename", zl_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zlfile);

    /* is the file updated? */
    st_mtime = ods_file_lastmodified(zlfile);
    if (st_mtime <= zl->last_modified) {
        ustamp = time_datestamp(zl->last_modified,
            "%Y-%m-%d %T", &datestamp);
        ods_log_debug("[%s] zonelist file %s is unchanged since %s",
            zl_str, zlfile, datestamp?datestamp:"Unknown");
        free((void*)datestamp);
        return ODS_STATUS_UNCHANGED;
    }

    /* create new zonelist */
    tmp_alloc = allocator_create(malloc, free);
    if (!tmp_alloc) {
        ods_log_error("[%s] error creating allocator for zone list",
            zl_str);
        return ODS_STATUS_ERR;
    }
    new_zlist = zonelist_create(tmp_alloc);
    if (!new_zlist) {
        ods_log_error("[%s] error creating new zone list", zl_str);
        allocator_cleanup(tmp_alloc);
        return ODS_STATUS_ERR;
    }

    /* read zonelist */
    status = zonelist_read(new_zlist, zlfile);
    if (status == ODS_STATUS_OK) {
        zl->just_removed = 0;
        zl->just_added = 0;
        zl->just_updated = 0;
        new_zlist->last_modified = st_mtime;
        zonelist_merge(zl, new_zlist);
        ustamp = time_datestamp(zl->last_modified, "%Y-%m-%d %T",
            &datestamp);
        ods_log_debug("[%s] file %s is modified since %s", zl_str, zlfile,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
    } else {
        ods_log_error("[%s] unable to read file %s: %s", zl_str, zlfile,
            ods_status2str(status));
    }

    zonelist_free(new_zlist);
    allocator_cleanup(tmp_alloc);
    return status;
}


/**
 * Internal zone cleanup function.
 *
 */
static void
zone_delfunc(ldns_rbnode_t* elem)
{
    zone_type* zone;

    if (elem && elem != LDNS_RBTREE_NULL) {
        zone = (zone_type*) elem->data;
        zone_delfunc(elem->left);
        zone_delfunc(elem->right);

        ods_log_debug("[%s] cleanup zone %s", zl_str, zone->name);
        zone_cleanup(zone);
        free((void*)elem);
    }
    return;
}


/**
 * Internal node cleanup function.
 *
 */
static void
node_delfunc(ldns_rbnode_t* elem)
{
    if (elem && elem != LDNS_RBTREE_NULL) {
        node_delfunc(elem->left);
        node_delfunc(elem->right);
        free((void*)elem);
    }
    return;
}


/**
 * Clean up a zonelist.
 *
 */
void
zonelist_cleanup(zonelist_type* zl)
{
    allocator_type* allocator;
    lock_basic_type zl_lock;

    if (!zl) {
        return;
    }

    ods_log_debug("[%s] cleanup zonelist", zl_str);
    if (zl->zones) {
        zone_delfunc(zl->zones->root);
        ldns_rbtree_free(zl->zones);
        zl->zones = NULL;
    }

    allocator = zl->allocator;
    zl_lock = zl->zl_lock;

    allocator_deallocate(allocator, (void*) zl);
    lock_basic_destroy(&zl_lock);
    return;
}


/**
 * Free zonelist.
 *
 */
void
zonelist_free(zonelist_type* zl)
{
    allocator_type* allocator;
    lock_basic_type zl_lock;

    if (!zl) {
        return;
    }

    if (zl->zones) {
        node_delfunc(zl->zones->root);
        ldns_rbtree_free(zl->zones);
        zl->zones = NULL;
    }

    allocator = zl->allocator;
    zl_lock = zl->zl_lock;

    allocator_deallocate(allocator, (void*) zl);
    lock_basic_destroy(&zl_lock);
    return;
}
