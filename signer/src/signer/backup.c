/*
 * Copyright (c) 2006-2010 NLNet Labs. All rights reserved.
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
 * Recover from backup.
 *
 */

#include "config.h"
#include "adapter/adapi.h"
#include "adapter/adutil.h"
#include "duration.h"
#include "file.h"
#include "log.h"
#include "status.h"
#include "util.h"
#include "signer/backup.h"
#include "signer/zone.h"

#include <ldns/ldns.h>

static const char* backup_str = "backup";


/**
 * Read token from backup file.
 *
 */
char*
backup_read_token(FILE* in)
{
    static char buf[4000];
    buf[sizeof(buf)-1]=0;

    while (1) {
        if (fscanf(in, "%3990s", buf) != 1) {
            return 0;
        }
        if (buf[0] != '#') {
            return buf;
        }
        if (!fgets(buf, sizeof(buf), in)) {
            return 0;
        }
    }
    return 0;
}

/**
 * Read and match a string from backup file.
 *
 */
int
backup_read_check_str(FILE* in, const char* str)
{
    char *p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read check string \'%s\'", backup_str, str);
        return 0;
    }
    if (ods_strcmp(p, str) != 0) {
        ods_log_debug("[%s] \'%s\' does not match \'%s\'", backup_str, p, str);
        return 0;
    }
    return 1;
}


/**
 * Read a string from backup file.
 *
 */
int
backup_read_str(FILE* in, const char** str)
{
    char *p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read string", backup_str);
        return 0;
    }
    *str = strdup(p);
    return 1;
}


/**
 * Read time from backup file.
 *
 */
int
backup_read_time_t(FILE* in, time_t* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read time", backup_str);
       return 0;
    }
    *v=atol(p);
    return 1;
}


/**
 * Read duration from backup file.
 *
 */
int
backup_read_duration(FILE* in, duration_type** v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read duration", backup_str);
       return 0;
    }
    *v=duration_create_from_string((const char*) p);
    return 1;
}


/**
 * Read rr type from backup file.
 *
 */
int
backup_read_rr_type(FILE* in, ldns_rr_type* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read rr type", backup_str);
       return 0;
    }
    *v=(ldns_rr_type) atoi(p);
    return 1;
}


/**
 * Read integer from backup file.
 *
 */
int
backup_read_int(FILE* in, int* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read integer", backup_str);
       return 0;
    }
    *v=atoi(p);
    return 1;
}


/**
 * Read 8bit unsigned integer from backup file.
 *
 */
int
backup_read_uint8_t(FILE* in, uint8_t* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read uint8_t", backup_str);
       return 0;
    }
    *v= (uint8_t)atoi(p);
    return 1;
}


/**
 * Read 32bit unsigned integer from backup file.
 *
 */
int
backup_read_uint32_t(FILE* in, uint32_t* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read uint32_t", backup_str);
       return 0;
    }
    *v= (uint32_t)atol(p);
    return 1;
}


/**
 * Read the next RR from the backup file.
 *
 */
static ldns_rr*
backup_read_rr(FILE* in, zone_type* zone, char* line, ldns_rdf** orig,
    ldns_rdf** prev, ldns_status* status, unsigned int* l)
{
    ldns_rr* rr = NULL;
    int len = 0;
backup_read_line:
    len = adutil_readline_frm_file(in, line, l, 1);
    if (len >= 0) {
        switch (line[0]) {
            case ';':
                /* done */
                *status = LDNS_STATUS_OK;
                return NULL;
                break;
            case '\n':
            case '\0':
                goto backup_read_line; /* perhaps next line is rr */
                break;
            /* let's hope its a RR */
            default:
                *status = ldns_rr_new_frm_str(&rr, line, zone->default_ttl,
                    *orig, prev);
                if (*status == LDNS_STATUS_OK) {
                    return rr;
                } else if (*status == LDNS_STATUS_SYNTAX_EMPTY) {
                    if (rr) {
                        ldns_rr_free(rr);
                        rr = NULL;
                    }
                    *status = LDNS_STATUS_OK;
                    goto backup_read_line; /* perhaps next line is rr */
                    break;
                } else {
                    ods_log_error("[%s] error parsing RR #%i (%s): %s",
                        backup_str, l&&*l?*l:0,
                        ldns_get_errorstr_by_id(*status), line);
                    if (rr) {
                        ldns_rr_free(rr);
                        rr = NULL;
                    }
                    return NULL;
                }
                break;
        }
    }
    /* -1, EOF */
    *status = LDNS_STATUS_OK;
    return NULL;
}


/**
 * Get locator from string.
 *
 */
static char*
replace_space_with_nul(char* str)
{
    int i = 0;
    if (!str) {
        return NULL;
    }
    i = strlen(str);
    while (i>0) {
        --i;
        if (str[i] == ' ') {
            str[i] = '\0';
        }
    }
    return strdup(str);
}


/**
 * Read namedb from backup file.
 *
 */
ods_status
backup_read_namedb(FILE* in, void* zone)
{
    zone_type* z = (zone_type*) zone;
    denial_type* denial = NULL;
    rrset_type* rrset = NULL;
    ods_status result = ODS_STATUS_OK;
    ldns_rr_type type_covered;
    ldns_rr* rr = NULL;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    ldns_rdf* dname = NULL;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    char* str = NULL;
    char* locator = NULL;
    uint32_t flags = 0;
    unsigned int l = 0;

    ods_log_assert(in);
    ods_log_assert(z);

    /* $ORIGIN <zone name> */
    dname = adapi_get_origin(z);
    if (!dname) {
        ods_log_error("[%s] error getting default value for $ORIGIN",
            backup_str);
        return ODS_STATUS_ERR;
    }
    orig = ldns_rdf_clone(dname);
    if (!orig) {
        ods_log_error("[%s] error setting default value for $ORIGIN",
            backup_str);
        return ODS_STATUS_ERR;
    }
    /* read RRs */
    ods_log_debug("[%s] read RRs %s", backup_str, z->name);
    while ((rr = backup_read_rr(in, z, line, &orig, &prev, &status, &l))
        != NULL) {
        /* check status */
        if (status != LDNS_STATUS_OK) {
            ods_log_error("[%s] error reading RR #%i (%s): %s",
                backup_str, l, ldns_get_errorstr_by_id(status), line);
            result = ODS_STATUS_ERR;
            goto backup_namedb_done;
        }
        /* add to the database */
        result = adapi_add_rr(z, rr, 1);
        if (result == ODS_STATUS_UNCHANGED) {
            ods_log_debug("[%s] skipping RR #%i (duplicate): %s",
                backup_str, l, line);
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_OK;
            continue;
        } else if (result != ODS_STATUS_OK) {
            ods_log_error("[%s] error adding RR #%i: %s",
                backup_str, l, line);
            ldns_rr_free(rr);
            rr = NULL;
            goto backup_namedb_done;
        }
    }
    if (result == ODS_STATUS_OK && status != LDNS_STATUS_OK) {
        ods_log_error("[%s] error reading RR #%i (%s): %s",
            backup_str, l, ldns_get_errorstr_by_id(status), line);
        result = ODS_STATUS_ERR;
        goto backup_namedb_done;
    }
    namedb_diff(z->db, 0, 0);

    /* read NSEC(3)s */
    ods_log_debug("[%s] read NSEC(3)s %s", backup_str, z->name);
    l = 0;
    while ((rr = backup_read_rr(in, z, line, &orig, &prev, &status, &l))
        != NULL) {
        /* check status */
        if (status != LDNS_STATUS_OK) {
            ods_log_error("[%s] error reading NSEC(3) #%i (%s): %s",
                backup_str, l, ldns_get_errorstr_by_id(status), line);
            result = ODS_STATUS_ERR;
            goto backup_namedb_done;
        }
        if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_NSEC &&
            ldns_rr_get_type(rr) != LDNS_RR_TYPE_NSEC3) {
            ods_log_error("[%s] error NSEC(3) #%i is not NSEC(3): %s",
                backup_str, l, line);
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_ERR;
            goto backup_namedb_done;
        }
        /* add to the denial chain */
        denial = namedb_lookup_denial(z->db, ldns_rr_owner(rr));
        if (!denial) {
            ods_log_error("[%s] error adding NSEC(3) #%i: %s",
                backup_str, l, line);
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_ERR;
            goto backup_namedb_done;
        }
        denial_add_rr(denial, rr);
    }
    if (result == ODS_STATUS_OK && status != LDNS_STATUS_OK) {
        ods_log_error("[%s] error reading NSEC(3) #%i (%s): %s",
            backup_str, l, ldns_get_errorstr_by_id(status), line);
        result = ODS_STATUS_ERR;
        goto backup_namedb_done;
    }

    /* read RRSIGs */
    ods_log_debug("[%s] read RRSIGs %s", backup_str, z->name);
    l = 0;
    while ((rr = backup_read_rr(in, z, line, &orig, &prev, &status, &l))
        != NULL) {
        /* check status */
        if (status != LDNS_STATUS_OK) {
            ods_log_error("[%s] error reading RRSIG #%i (%s): %s",
                backup_str, l, ldns_get_errorstr_by_id(status), line);
            result = ODS_STATUS_ERR;
            goto backup_namedb_done;
        }
        if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
            ods_log_error("[%s] error RRSIG #%i is not RRSIG: %s",
                backup_str, l, line);
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_ERR;
            goto backup_namedb_done;
        }
        /* read locator and flags */
        str = strstr(line, "flags");
        if (str) {
            flags = (uint32_t) atoi(str+6);
        }
        str = strstr(line, "locator");
        if (str) {
            locator = replace_space_with_nul(str+8);
        }
        /* add signatures */
        type_covered = ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rr));
        if (type_covered == LDNS_RR_TYPE_NSEC ||
            type_covered == LDNS_RR_TYPE_NSEC3) {
            denial = namedb_lookup_denial(z->db, ldns_rr_owner(rr));
            if (!denial) {
                ods_log_error("[%s] error restoring RRSIG #%i (%s): %s",
                    backup_str, l, ldns_get_errorstr_by_id(status), line);
                ldns_rr_free(rr);
                rr = NULL;
                result = ODS_STATUS_ERR;
                goto backup_namedb_done;
            }
            rrset = denial->rrset;
        } else {
            rrset = zone_lookup_rrset(z, ldns_rr_owner(rr), type_covered);
        }
        if (!rrset) {
            ods_log_error("[%s] error restoring RRSIG #%i (%s): %s",
                backup_str, l, ldns_get_errorstr_by_id(status), line);
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_ERR;
            goto backup_namedb_done;
        }
        rrset_add_rrsig(rrset, rr, locator, flags);
        locator = NULL; /* Locator is owned by rrset now */
        rrset->needs_signing = 0;
    }
    if (result == ODS_STATUS_OK && status != LDNS_STATUS_OK) {
        ods_log_error("[%s] error reading RRSIG #%i (%s): %s",
            backup_str, l, ldns_get_errorstr_by_id(status), line);
        result = ODS_STATUS_ERR;
    }

backup_namedb_done:
    if (orig) {
        ldns_rdf_deep_free(orig);
        orig = NULL;
    }
    if (prev) {
        ldns_rdf_deep_free(prev);
        prev = NULL;
    }
    return result;
}


/**
 * Read ixfr journal from file.
 *
 *
 */
ods_status
backup_read_ixfr(FILE* in, void* zone)
{
    zone_type* z = (zone_type*) zone;
    ods_status result = ODS_STATUS_OK;
    ldns_rr* rr = NULL;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    ldns_rdf* dname = NULL;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    uint32_t serial = 0;
    unsigned l = 0;
    unsigned first_soa = 0;
    unsigned del_mode = 0;

    ods_log_assert(in);
    ods_log_assert(z);

    /* $ORIGIN <zone name> */
    dname = adapi_get_origin(z);
    if (!dname) {
        ods_log_error("[%s] error getting default value for $ORIGIN",
            backup_str);
        return ODS_STATUS_ERR;
    }
    orig = ldns_rdf_clone(dname);
    if (!orig) {
        ods_log_error("[%s] error setting default value for $ORIGIN",
            backup_str);
        return ODS_STATUS_ERR;
    }
    /* read RRs */
    while ((rr = backup_read_rr(in, z, line, &orig, &prev, &status, &l))
        != NULL) {
        /* check status */
        if (status != LDNS_STATUS_OK) {
            ods_log_error("[%s] error reading RR #%i (%s): %s",
                backup_str, l, ldns_get_errorstr_by_id(status), line);
            result = ODS_STATUS_ERR;
            goto backup_ixfr_done;
        }
        if (first_soa == 2) {
            ods_log_error("[%s] bad ixfr journal: trailing RRs after final "
               "SOA", backup_str);
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_ERR;
            goto backup_ixfr_done;
        }
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
            serial = ldns_rdf2native_int32(
                ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
            if (!first_soa) {
                ods_log_debug("[%s] ixfr first SOA: %s", backup_str,
                    ldns_rr2str(rr));
                /* first SOA */
                ldns_rr_free(rr);
                rr = NULL;
                if (z->db->outserial != serial) {
                    ods_log_error("[%s] bad ixfr journal: first SOA wrong "
                        "serial (was %u, expected %u)", backup_str,
                        serial, z->db->outserial);
                    result = ODS_STATUS_ERR;
                    goto backup_ixfr_done;
                }
                first_soa = 1;
                continue;
            }
            ods_log_assert(first_soa);
            if (!del_mode) {
                if (z->db->outserial == serial) {
                    /* final SOA */
                    ods_log_debug("[%s] ixfr final SOA: %s", backup_str,
                        ldns_rr2str(rr));
                    ldns_rr_free(rr);
                    rr = NULL;
                    result = ODS_STATUS_OK;
                    first_soa = 2;
                    continue;
                } else {
                    ods_log_debug("[%s] new part SOA: %s", backup_str,
                        ldns_rr2str(rr));
                    lock_basic_lock(&z->ixfr->ixfr_lock);
                    ixfr_purge(z->ixfr);
                    lock_basic_unlock(&z->ixfr->ixfr_lock);
                }
            } else {
                ods_log_debug("[%s] second part SOA: %s", backup_str,
                    ldns_rr2str(rr));
            }
            del_mode = !del_mode;
        }
        /* ixfr add or del rr */
        if (!first_soa) {
            ods_log_error("[%s] bad ixfr journal: first RR not SOA",
                backup_str);
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_ERR;
            goto backup_ixfr_done;
        }
        ods_log_assert(first_soa);
        lock_basic_lock(&z->ixfr->ixfr_lock);
        if (del_mode) {
            ods_log_deeebug("[%s] -IXFR: %s", backup_str, ldns_rr2str(rr));
            ixfr_del_rr(z->ixfr, rr);
        } else {
            ods_log_deeebug("[%s] +IXFR: %s", backup_str, ldns_rr2str(rr));
            ixfr_add_rr(z->ixfr, rr);
        }
        lock_basic_unlock(&z->ixfr->ixfr_lock);
    }
    if (result == ODS_STATUS_OK && status != LDNS_STATUS_OK) {
        ods_log_error("[%s] error reading RR #%i (%s): %s",
            backup_str, l, ldns_get_errorstr_by_id(status), line);
        result = ODS_STATUS_ERR;
    }

backup_ixfr_done:
    if (orig) {
        ldns_rdf_deep_free(orig);
        orig = NULL;
    }
    if (prev) {
        ldns_rdf_deep_free(prev);
        prev = NULL;
    }
    return result;
}

