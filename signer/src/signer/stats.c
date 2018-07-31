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

/**
 * Signer statistics.
 *
 */

#include "log.h"
#include "signer/stats.h"

/**
 * Initialize statistics.
 *
 */
stats_type*
stats_create(void)
{
    stats_type* stats = (stats_type*) malloc(sizeof(stats_type));
    stats_clear(stats);
    pthread_mutex_init(&stats->stats_lock, NULL);
    return stats;
}


/**
 * Clear statistics.
 *
 */
void
stats_clear(stats_type* stats)
{
    ods_log_assert(stats);
    stats->sort_count = 0;
    stats->sort_time = 0;
    stats->sort_done = 0;
    stats->nsec_count = 0;
    stats->nsec_time = 0;
    stats->sig_count = 0;
    stats->sig_soa_count = 0;
    stats->sig_reuse = 0;
    stats->sig_time = 0;
    stats->start_time = 0;
    stats->end_time = 0;
}


/**
 * Log statistics.
 *
 */
void
stats_log(stats_type* stats, const char* name, uint32_t serial,
   ldns_rr_type nsec_type)
{
    uint32_t avsign = 0;

    if (!stats) {
        return;
    }
    ods_log_assert(stats);
    if (stats->sig_time) {
        avsign = (uint32_t) (stats->sig_count/stats->sig_time);
    }
    ods_log_info("[STATS] %s %u RR[count=%u time=%lu(sec)] "
        "NSEC%s[count=%u time=%lu(sec)] "
        "RRSIG[new=%u reused=%u time=%lu(sec) avg=%u(sig/sec)] "
        "TOTAL[time=%u(sec)] ",
        name?name:"(null)", (unsigned) serial,
        stats->sort_count, (unsigned long)stats->sort_time,
        nsec_type==LDNS_RR_TYPE_NSEC3?"3":"", stats->nsec_count,
        (unsigned long)stats->nsec_time, stats->sig_count, stats->sig_reuse,
        (unsigned long)stats->sig_time, avsign,
        (uint32_t) (stats->end_time - stats->start_time));
}


/**
 * Clean up statistics.
 *
 */
void
stats_cleanup(stats_type* stats)
{
    pthread_mutex_destroy(&stats->stats_lock);
    free((void*) stats);
}
