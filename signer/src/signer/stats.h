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

#ifndef SIGNER_STATS_H
#define SIGNER_STATS_H

#include "config.h"
#include <ctype.h>
#include <stdint.h>
#include <time.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <ldns/ldns.h>

typedef struct stats_struct stats_type;

#include "locks.h"

/**
 * Statistics structure.
 */
struct stats_struct {
    uint32_t    sort_count;
    time_t      sort_time;
    int         sort_done;
    uint32_t    nsec_count;
    time_t      nsec_time;
    uint32_t    sig_count;
    uint32_t    sig_soa_count;
    uint32_t    sig_reuse;
    time_t      sig_time;
    time_t      start_time;
    time_t      end_time;
    pthread_mutex_t stats_lock;
};

/**
 * Initialize statistics.
 * \return the initialized stats;
 *
 */
extern stats_type* stats_create(void);

/**
 * Log statistics.
 * \param[in] stats statistics
 * \param[in] name zone name
 * \param[in] serial serial
 * \param[in] nsec_type NSEC or NSEC3
 *
 */
extern void stats_log(stats_type* stats, const char* name, uint32_t serial,
    ldns_rr_type nsec_type);

/**
 * Clear statistics.
 * \param[in] stats statistics to be cleared
 *
 */
extern void stats_clear(stats_type* stats);

/**
 * Clean up statistics.
 * \param[in] stats statistics to be deleted
 *
 */
extern void stats_cleanup(stats_type* stats);

#endif /* SIGNER_STATS_H */
