/*
 * $Id: journal.h 5190 2011-05-30 13:12:12Z matthijs $
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
 * Journal.
 *
 */

#ifndef SIGNER_JOURNAL_H
#define SIGNER_JOURNAL_H

#include "shared/allocator.h"
#include "shared/status.h"

#include <config.h>
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

/**
 * Entry structure.
 */
typedef struct entry_struct entry_type;
struct entry_struct {
    uint32_t serial;
    ldns_rr_list* deleted;
    ldns_rr_list* added;
    entry_type* next;
};

/**
 * Journal structure.
 */
typedef struct journal_struct journal_type;
struct journal_struct {
    allocator_type* allocator;
    entry_type* entries;
};


/**
 * Create entry.
 * \param[in] allocator memory allocator
 * \return entry_type* the created entry
 *
 */
entry_type* entry_create(allocator_type* allocator);

/**
 * Add +RR to entry.
 * \param[in] entry entry
 * \param[in] rr RR
 * \return ods_status status
 *
 */
ods_status entry_plus_rr(entry_type* entry, ldns_rr* rr);

/**
 * Add -RR to entry.
 * \param[in] entry entry
 * \param[in] rr RR
 * \return ods_status status
 *
 */
ods_status entry_min_rr(entry_type* entry, ldns_rr* rr);

/**
 * Print entry.
 * \param[in] fd file descriptor
 * \param[in] entry entry to be deleted
 *
 */
void entry_print(FILE* fd, entry_type* entry);

/**
 * Clear entry.
 * \param[in] entry entry to be cleared
 *
 */
void entry_clear(entry_type* entry);

/**
 * Clean up entry.
 * \param[in] allocator memory allocator
 * \param[in] entry entry to be deleted
 *
 */
void entry_cleanup(allocator_type* allocator, entry_type* entry);


/**
 * Create journal.
 * \return journal_type* the created journal
 *
 */
journal_type* journal_create(void);

/**
 * Add entry to journal.
 * \param[in] journal journal
 * \param[in] entry entry
 * \return ods_status status
 *
 */
ods_status journal_add_entry(journal_type* journal, entry_type* entry);

/**
 * Purge journal.
 * \param[in] journal journal to be purged
 *
 */
void journal_purge(journal_type* journal);

/**
 * Print journal.
 * \param[in] fd file descriptor
 * \param[in] journal journal to be printed
 *
 */
void journal_print(FILE* fd, journal_type* journal);

/**
 * Clean up journal.
 * \param[in] journal journal to be deleted
 *
 */
void journal_cleanup(journal_type* journal);

#endif /* SIGNER_JOURNAL_H */
