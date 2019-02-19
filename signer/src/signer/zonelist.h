/*
 * Copyright (c) 2009-2018 NLNet Labs.
 * All rights reserved.
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
 */

#ifndef SIGNER_ZONELIST_H
#define SIGNER_ZONELIST_H

#include <ldns/ldns.h>
#include <stdio.h>
#include <time.h>

typedef struct zonelist_struct zonelist_type;
typedef struct names_viewfactory_struct* names_viewfactory_type;

#include "status.h"
#include "locks.h"
#include "signer/zone.h"
#include "views/proto.h"

/**
 * Zone list
 *
 */
struct zonelist_struct {
    ldns_rbtree_t* zones;
    time_t last_modified;
    int just_added;
    int just_updated;
    int just_removed;
    pthread_mutex_t zl_lock;
};

/**
 * Create zone list.
 * \param[in] allocator memory allocator
 * \return zonelist_type* created zone list
 *
 */
zonelist_type* zonelist_create(void);

/**
 * Lookup zone by name and class.
 * \param[in] zl zone list
 * \param[in] name zone name
 * \param[in] klass zone class
 * \return zone_type* found zone
 *
 */
zone_type* zonelist_lookup_zone_by_name(zonelist_type* zonelist,
    const char* name, ldns_rr_class klass);

/**
 * Lookup zone by dname and class.
 * \param[in] zl zone list
 * \param[in] dname zone domain name
 * \param[in] klass zone class
 * \return zone_type* found zone
 *
 */
zone_type* zonelist_lookup_zone_by_dname(zonelist_type* zonelist,
    ldns_rdf* dname, ldns_rr_class klass);

/**
 * Add zone.
 * \param[in] zl zone list
 * \param[in] zone zone
 * \return zone_type* added zone
 *
 */
zone_type* zonelist_add_zone(zonelist_type* zl, zone_type* zone);

/**
 * Delete zone.
 * \param[in] zl zone list
 * \param[in] zone zone
 *
 */
void zonelist_del_zone(zonelist_type* zlist, zone_type* zone);

/**
 * Update zonelist.
 * \param[in] zl zone list
 * \param[in] zlfile zone list filename
 * \return ods_status status
 *
 */
ods_status zonelist_update(zonelist_type* zl, const char* zlfile);

/**
 * Clean up zone list.
 * \param[in] zl zone list
 *
 */
void zonelist_cleanup(zonelist_type* zl);

/**
 * Free zone list.
 * \param[in] zl zone list
 *
 */
void zonelist_free(zonelist_type* zl);

/**
 * Obtain a certain view from for the named zone. 
 * This method will block until the resource is available. if the
 * zone exists.  The zone is searched for in the zonelist if the zone
 * is not given (NULL).  A zone obtianed must be released using
 * zonelist_releaseresource.
 *
 * @param zonelist The zonelist to search for the named zone
 * @param name The zone name
 * @param zone The zone pointer, if already known
 * @param offset The offset of the view or viewfactory in the zone_type structure
 * @return The view or NULL if the zone could not be found.
 */
names_view_type zonelist_obtainresource(zonelist_type* zonelist, zone_type* zone, const char* name, size_t offset);

/**
 * Releases a previous obtained view from zonelist_obtainresource 
 * The zone is searched for in the zonelist if the zone is not given (NULL).
 *
 * @param zonelist The zonelist to search for the named zone
 * @param name The zone name
 * @param zone The zone pointer, if already known
 * @param offset The offset of the view or viewfactory in the zone_type structure
 * @param view The previous obtained resource from zonelist_releaseresource.
 * @return The view or NULL if the zone could not be found.
 */
void
zonelist_releaseresource(zonelist_type* zonelist, zone_type* zone, const char* name, size_t offset, names_view_type view);

/**
 * Creates a viewfactory which holds one or multiple views with the same properties.
 * @param base the base view
 * @param viewname the view name for human consumption
 * @param keynames the keynames passed to names_viewcreate
 * @param mincount the initial and minimum number of similar views
 * @param maxcount the maximum number of view, after which the zonelist_obtainresourc will block when 
 * @return the created viewfactory
 */
names_viewfactory_type zonelist_createresource(names_view_type base, const char* viewname, const char** keynames, int mincount, int maxcount);

/**
 * Destroys the viewfactory and all views containes therein
 * @param viewfactory the viewfactory earlier created using zonelist_createresource
 */
void zonelist_destroyresource(names_viewfactory_type viewfactory);

/**
 * Calls the provided callback function on all views created by the view
 * factory.  Should only be used in case it is certain no other threads are
 * using the views.
 * @param viewfactory the viewfactory for which to bring all views up to date
 */
void zonelist_traverseresource(names_viewfactory_type viewfactory, void (*callback)(names_view_type));

/**
 * Emits debugging output on stderrr (only) concerning all views in the zone.
 * Should only be used in case it is certain no other threads are using the
 * views.
 * @param zone the zone containing the views and viewfactories.
 */
void zonelist_zonedumpviews(zone_type* zone);

/**
 * Validate all views produced by the view factory in a zone.  These are
 * the views that share the same purpose.  Used as sanity test and
 * debugging.  The state of the views is outputted to standard error.
 * @param viewfactory the views factory which to check for
 */
void zonelist_zonevalidateviewfactory(names_viewfactory_type viewfactory);

#endif /* SIGNER_ZONELIST_H */
