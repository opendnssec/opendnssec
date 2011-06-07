/*
 * $Id: journal.c 5190 2011-05-30 13:12:12Z matthijs $
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

#include "config.h"
#include "shared/log.h"
#include "shared/util.h"
#include "signer/journal.h"

static const char* journal_str = "journal";


/**
 * Create entry.
 *
 */
entry_type* entry_create(allocator_type* allocator)
{
    entry_type* entry = NULL;

    if (!allocator) {
        ods_log_error("[%s] unable to create journal entry: no allocator",
            journal_str);
        return NULL;
    }
    ods_log_assert(allocator);

    entry = (entry_type*) allocator_alloc(allocator, sizeof(entry_type));
    if (!entry) {
        ods_log_error("[%s] unable to create journal entry: allocator failed",
            journal_str);
        return NULL;
    }
    ods_log_assert(entry);

    entry->added = ldns_rr_list_new();
    entry->deleted = ldns_rr_list_new();
    if (!entry->added || !entry->deleted) {
        ods_log_error("[%s] unable to create journal entry: create rr lists "
            "failed", journal_str);
        entry_cleanup(allocator, entry);
        return NULL;
    }
    entry->serial = 0;
    entry->next = NULL;
    return entry;
}


/**
 * Add +RR to entry.
 *
 */
ods_status
entry_plus_rr(entry_type* entry, ldns_rr* rr)
{
    if (!entry || !rr) {
        ods_log_error("[%s] unable to do +RR to journal entry: no entry or rr",
            journal_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);
    ods_log_assert(entry);
    ods_log_assert(entry->added);
    if (0 == (int) ldns_rr_list_push_rr(entry->added, rr)) {
        ods_log_error("[%s] unable to do +RR to journal entry: push rr failed",
            journal_str);
        return ODS_STATUS_ERR;
    }
    /* else ok */
    return ODS_STATUS_OK;
}


/**
 * Add -RR to entry.
 *
 */
ods_status
entry_min_rr(entry_type* entry, ldns_rr* rr)
{
    if (!entry || !rr) {
        ods_log_error("[%s] unable to do -RR to journal entry: no entry or rr",
            journal_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);
    ods_log_assert(entry);
    ods_log_assert(entry->deleted);
    if (0 == (int) ldns_rr_list_push_rr(entry->deleted, rr)) {
        ods_log_error("[%s] unable to do -RR to journal entry: push rr failed",
            journal_str);
        return ODS_STATUS_ERR;
    }
    /* else ok */
    return ODS_STATUS_OK;
}


/**
 * Print entry.
 *
 */
void
entry_print(FILE* fd, entry_type* entry)
{
    if (!fd || !entry) {
        return;
    }
    fprintf(fd, "; entry serial %u\n", entry->serial);
    /* TODO print +RRs and -RRs */
    return;
}


/**
 * Clear entry.
 *
 */
void
entry_clear(entry_type* entry)
{
    if (!entry) {
        return;
    }
    /* +RR: list needs to be freed, but RRs not */
    ldns_rr_list_free(entry->added);
    /* -RR: list needs to be freed, including RRs */
    ldns_rr_list_deep_free(entry->deleted);
    entry->serial = 0;
    return;
}

/**
 * Clean up entry.
 *
 */
void
entry_cleanup(allocator_type* allocator, entry_type* entry)
{
    if (!entry || !allocator) {
        return;
    }
    entry_cleanup(allocator, entry->next);

    entry_clear(entry);
    allocator_deallocate(allocator, (void*) entry);
    return;
}


/**
 * Create journal.
 *
 */
journal_type* journal_create(void)
{
    allocator_type* allocator = NULL;
    journal_type* journal = NULL;

    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create journal: create allocator "
            "failed", journal_str);
        return NULL;
    }
    ods_log_assert(allocator);

    journal = (journal_type*) allocator_alloc(allocator, sizeof(journal_type));
    if (!journal) {
        ods_log_error("[%s] unable to create journal: allocator failed",
            journal_str);
        allocator_cleanup(allocator);
        return NULL;
    }
    ods_log_assert(journal);

    journal->allocator = allocator;
    journal->entries = NULL;
    return journal;
}


/**
 * Add entry to journal.
 *
 */
ods_status
journal_add_entry(journal_type* journal, entry_type* entry)
{
    entry_type* prev_entry = NULL;

    if (!journal || !entry) {
        ods_log_error("[%s] unable to add entry to journal: no journal or "
            "entry", journal_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(journal);
    ods_log_assert(entry);

    if (journal->entries == NULL) {
        journal->entries = entry;
        return ODS_STATUS_OK;
    }
    /* else find right place in journal */
    prev_entry = journal->entries;
    while (prev_entry->next) {
        prev_entry = prev_entry->next;
    }
    /* make sure that the previous entry serial -lt new serial */
    if (!DNS_SERIAL_GT(entry->serial, prev_entry->serial)) {
        ods_log_error("[%s] unable to add entry to journal: serial %u does "
            "not increment previous entry serial %u", journal_str,
            entry->serial, prev_entry->serial);
        return ODS_STATUS_CONFLICT_ERR;
    }
    /* ok */
    prev_entry->next = entry;
    return ODS_STATUS_OK;
}


/**
 * Purge journal.
 *
 */
void
journal_purge(journal_type* journal)
{
    if (!journal) {
        return;
    }
    /* no purging strategy */
    return;
}


/**
 * Print journal.
 *
 */
void
journal_print(FILE* fd, journal_type* journal)
{
    entry_type* entry = NULL;

    if (!fd || !journal) {
        return;
    }

    entry = journal->entries;
    while (entry) {
        entry_print(fd, entry);
        entry = entry->next;
    }
    return;

}


/**
 * Clean up journal.
 *
 */
void
journal_cleanup(journal_type* journal)
{
    allocator_type* allocator = NULL;

    if (!journal) {
        return;
    }
    allocator = journal->allocator;
    entry_cleanup(allocator, journal->entries);
    allocator_deallocate(allocator, (void*) journal);
    allocator_cleanup(allocator);
    return;
}
