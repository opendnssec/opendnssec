/*
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
#include "duration.h"
#include "file.h"
#include "log.h"
#include "status.h"
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
    return ldns_dname_compare(x->apex, y->apex);
}


/**
 * Create a new zone list.
 *
 */
zonelist_type*
zonelist_create()
{
    zonelist_type* zlist = NULL;
    CHECKALLOC(zlist = (zonelist_type*) malloc(sizeof(zonelist_type)));
    zlist->zones = ldns_rbtree_create(zone_compare);
    if (!zlist->zones) {
        ods_log_error("[%s] unable to create zonelist: ldns_rbtree_create() "
            "failed", zl_str);
        free(zlist);
        return NULL;
    }
    zlist->last_modified = 0;
    pthread_mutex_init(&zlist->zl_lock, NULL);
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
    status = parse_file_check(zlfile, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read file: parse error in %s", zl_str,
            zlfile);
        return status;
    }
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

void*
zonelist_get(zonelist_type* zonelist, const char* name)
{
    struct ldns_rbnode_t* node;
    node = ldns_rbtree_search(zonelist->zones, name);
    if (node == NULL || node == LDNS_RBTREE_NULL) {
        return NULL;
    } else {
        return (void*) node->data;
    }
}

void*
zonelist_obtainresource(zonelist_type* zonelist, const char* name, size_t offset)
{
    struct ldns_rbnode_t* node;
    zone_type* zone;
    names_view_type* viewptr;
    names_view_type view;
    pthread_mutex_lock(&zonelist->zl_lock);
    node = ldns_rbtree_search(zonelist->zones, name);
    if (node == NULL || node == LDNS_RBTREE_NULL) {
        view = NULL;
    } else {
        zone = (zone_type*) node->data;
        viewptr = (void*)&(((char*)zone)[offset]);
        view = *viewptr;
        if(view == NULL) {
            if(viewptr == &zone->inputview) {
            } else if(viewptr == &zone->inputview) {
                // FIXME
            }
        }
        *viewptr = NULL;
    }
    pthread_mutex_lock(&zonelist->zl_lock);
    return view;
}


void*
zonelist_releaseresource(zonelist_type* zonelist, const char* name, size_t offset, names_view_type view)
{
    struct ldns_rbnode_t* node;
    zone_type* zone;
    names_view_type* viewptr;
    pthread_mutex_lock(&zonelist->zl_lock);
    node = ldns_rbtree_search(zonelist->zones, name);
    if (node == NULL || node == LDNS_RBTREE_NULL) {
        view = NULL;
    } else {
        zone = (zone_type*) node->data;
        viewptr = (void*)&(((char*)zone)[offset]);
        *viewptr = view;
    }
    pthread_mutex_lock(&zonelist->zl_lock);
    return view;
}


/**
 * Lookup zone.
 *
 */
static zone_type*
zonelist_lookup_zone(zonelist_type* zonelist, zone_type* zone)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    if (zonelist && zonelist->zones && zone) {
        node = ldns_rbtree_search(zonelist->zones, zone);
        if (node) {
            return (zone_type*) node->data;
        }
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
    if (zonelist && zonelist->zones && name  && klass) {
        zone = zone_create((char*) name, klass);
        result = zonelist_lookup_zone(zonelist, zone);
        zone_cleanup(zone);
    }
    return result;
}


/**
 * Lookup zone by dname.
 *
 */
zone_type*
zonelist_lookup_zone_by_dname(zonelist_type* zonelist, ldns_rdf* dname,
    ldns_rr_class klass)
{
    char* name = NULL;
    zone_type* result = NULL;
    if (zonelist && zonelist->zones && dname && klass) {
        name = ldns_rdf2str(dname);
        result = zonelist_lookup_zone_by_name(zonelist, name, klass);
        free((void*)name);
    }
    return result;
}


static const char* baseviewkeys[] = { "namerevision", NULL};
static const char* inputviewkeys[] = { "nameupcoming", "namehierarchy", NULL};
static const char* prepareviewkeys[] = { "namerevision", "namenoserial", "namenewserial", NULL};
static const char* neighviewkeys[] = { "nameready", "denialname", NULL};
static const char* signviewkeys[] = { "nameready", "expiry", "denialname", NULL};
static const char* outputviewkeys[] = { "validnow", NULL};

/**
 * Add zone.
 *
 */
zone_type*
zonelist_add_zone(zonelist_type* zlist, zone_type* zone)
{
    ldns_rbnode_t* new_node = NULL;
    char* zoneapex;
    if (!zone) {
        return NULL;
    }
    if (!zlist || !zlist->zones) {
        zone_cleanup(zone);
        return NULL;
    }
    /* look up */
    if (zonelist_lookup_zone(zlist, zone) != NULL) {
        ods_log_warning("[%s] unable to add zone %s: already present", zl_str,
            zone->name);
        zone_cleanup(zone);
        return NULL;
    }
    /* add */
    new_node = zone2node(zone);
    if (ldns_rbtree_insert(zlist->zones, new_node) == NULL) {
        ods_log_error("[%s] unable to add zone %s: ldns_rbtree_insert() "
            "failed", zl_str, zone->name);
        free((void*) new_node);
        zone_cleanup(zone);
        return NULL;
    }
    zone->zl_status = ZONE_ZL_ADDED;

    zoneapex = ldns_rdf2str(zone->apex);
    /*if(zoneapex[strlen(zoneapex)-1] == '.')
        zoneapex[strlen(zoneapex)-1] = '\0';*/
    zone->baseview = names_viewcreate(NULL, "  base    ", baseviewkeys);
    names_viewrestore(zone->baseview, zoneapex, -1, NULL); // FIXME proper restore filename
    zone->inputview = names_viewcreate(zone->baseview,   "  input   ", inputviewkeys);
    zone->prepareview = names_viewcreate(zone->baseview, "  prepare ", prepareviewkeys);
    zone->neighview = names_viewcreate(zone->baseview, "  neighbr ", neighviewkeys);
    zone->signview = names_viewcreate(zone->baseview,    "  sign    ", signviewkeys);
    zone->outputview = names_viewcreate(zone->baseview,  "  output  ", outputviewkeys);
    free(zoneapex);

    zlist->just_added++;
    return zone;
}


/**
 * Delete zone.
 *
 */
void
zonelist_del_zone(zonelist_type* zlist, zone_type* zone)
{
    ldns_rbnode_t* old_node = LDNS_RBTREE_NULL;
    assert(zone);
    if (!zlist || !zlist->zones) {
        goto zone_not_present;
    }
    old_node = ldns_rbtree_delete(zlist->zones, zone);
    if (!old_node) {
        goto zone_not_present;
    }
    free((void*) old_node);
    return;

zone_not_present:
    ods_log_warning("[%s] unable to delete zone %s: not present", zl_str,
        zone->name);
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
                ods_log_crit("[%s] merge failed: z2 not added", zl_str);
                return;
            }
            n2 = ldns_rbtree_next(n2);
        } else {
            /* compare the zones z1 and z2 */
            ret = zone_compare(z1, z2);
            if (ret < 0) {
                /* remove zone z1, it is not present in the new list zl2 */
                z1->zl_status = ZONE_ZL_REMOVED;
                zl1->just_removed++;
                n1 = ldns_rbtree_next(n1);
            } else if (ret > 0) {
                /* add the new zone z2 */
                z2 = zonelist_add_zone(zl1, z2);
                if (!z2) {
                    ods_log_crit("[%s] merge failed: z2 not added", zl_str);
                    return;
                }
                n2 = ldns_rbtree_next(n2);
            } else {
                /* just update zone z1 */
                n1 = ldns_rbtree_next(n1);
                n2 = ldns_rbtree_next(n2);
                zone_merge(z1, z2);
                zone_cleanup(z2);
                if (z1->zl_status == ZONE_ZL_UPDATED) {
                    zl1->just_updated++;
                }
                z1->zl_status = ZONE_ZL_UPDATED;
            }
        }
    }
    /* remove remaining zones from z1 */
    while (n1 && n1 != LDNS_RBTREE_NULL) {
        z1 = (zone_type*) n1->data;
        z1->zl_status = ZONE_ZL_REMOVED;
        zl1->just_removed++;
        n1 = ldns_rbtree_next(n1);
    }
    zl1->last_modified = zl2->last_modified;
}


/**
 * Update zone list.
 *
 */
ods_status
zonelist_update(zonelist_type* zl, const char* zlfile)
{
    zonelist_type* new_zlist = NULL;
    time_t st_mtime = 0;
    ods_status status = ODS_STATUS_OK;
    char* datestamp = NULL;

    ods_log_debug("[%s] update zone list", zl_str);
    if (!zl|| !zl->zones || !zlfile) {
        return ODS_STATUS_ASSERT_ERR;
    }
    /* is the file updated? */
    /* OPENDNSSEC-686: changes happening within one second will not be
     * seen
     */
    st_mtime = ods_file_lastmodified(zlfile);
    if (st_mtime <= zl->last_modified) {
        (void)time_datestamp(zl->last_modified, "%Y-%m-%d %T", &datestamp);
        ods_log_error("[%s] zonelist file %s is unchanged since %s",
            zl_str, zlfile, datestamp?datestamp:"Unknown");
        free((void*)datestamp);
        return ODS_STATUS_UNCHANGED;
    }
    /* create new zonelist */
    new_zlist = zonelist_create();
    /* read zonelist */
    status = zonelist_read(new_zlist, zlfile);
    if (status == ODS_STATUS_OK) {
        zl->just_removed = 0;
        zl->just_added = 0;
        zl->just_updated = 0;
        new_zlist->last_modified = st_mtime;
        zonelist_merge(zl, new_zlist);
        (void)time_datestamp(zl->last_modified, "%Y-%m-%d %T", &datestamp);
        ods_log_error("[%s] file %s is modified since %s", zl_str, zlfile,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
    } else {
        ods_log_error("[%s] unable to update zonelist: read file %s failed "
            "(%s)", zl_str, zlfile, ods_status2str(status));
    }
    zonelist_free(new_zlist);
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
        ods_log_deeebug("[%s] cleanup zone %s", zl_str, zone->name);
        zone_cleanup(zone);
        free((void*)elem);
    }
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
}


/**
 * Clean up a zonelist.
 *
 */
void
zonelist_cleanup(zonelist_type* zl)
{
    if (!zl) {
        return;
    }
    ods_log_debug("[%s] cleanup zonelist", zl_str);
    if (zl->zones) {
        zone_delfunc(zl->zones->root);
        ldns_rbtree_free(zl->zones);
        zl->zones = NULL;
    }
    pthread_mutex_destroy(&zl->zl_lock);
    free(zl);
}


/**
 * Free zonelist.
 *
 */
void
zonelist_free(zonelist_type* zl)
{
    if (!zl) {
        return;
    }
    if (zl->zones) {
        node_delfunc(zl->zones->root);
        ldns_rbtree_free(zl->zones);
        zl->zones = NULL;
    }
    pthread_mutex_destroy(&zl->zl_lock);
    free(zl);
}
