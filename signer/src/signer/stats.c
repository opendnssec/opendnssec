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
 * Signer statistics.
 *
 */

#include "signer/stats.h"
#include "util/log.h"
#include "util/se_malloc.h"

/**
 * Initialize statistics.
 *
 */
stats_type*
stats_create(void)
{
    stats_type* stats = (stats_type*) se_malloc(sizeof(stats_type));
    stats_clear(stats);
    return stats;
}


/**
 * Clear statistics.
 *
 */
void
stats_clear(stats_type* stats)
{
    se_log_assert(stats);
    stats->sort_count = 0;
    stats->sort_time = 0;
    stats->nsec_count = 0;
    stats->nsec_time = 0;
    stats->sig_count = 0;
    stats->sig_reuse = 0;
    stats->sig_time = 0;
}


/**
 * Log statistics.
 *
 */
void
stats_log(stats_type* stats, const char* name, ldns_rr_type nsec_type)
{
    uint32_t avsign = 0;

    se_log_assert(stats);
    se_log_assert(name);
    if (stats->sig_time) {
        avsign = (uint32_t) (stats->sig_count/stats->sig_time);
    }

    se_log_info("[STATS] %s RR[count=%u time=%u(sec)) "
        "NSEC%s[count=%u time=%u(sec)] "
        "RRSIG[new=%u reused=%u time=%u(sec) avg=%u(sig/sec)]",
        name?name:"(null)", stats->sort_count, stats->sort_time,
        nsec_type==LDNS_RR_TYPE_NSEC3?"3":"", stats->nsec_count,
        stats->nsec_time,
        stats->sig_count, stats->sig_reuse, stats->sig_time, avsign);
    return;
}


/**
 * Clean up statistics.
 *
 */
void
stats_cleanup(stats_type* stats)
{
    if (stats) {
	se_free((void*) stats);
    } else {
        se_log_warning("cleanup empty statistics");
    }
    return;
}
