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
#include "signer/zone.h"
#include "adapter/adapi.h"
#include "adapter/adutil.h"
#include "duration.h"
#include "file.h"
#include "log.h"
#include "status.h"
#include "util.h"
#include "signer/signconf.h"
#include "views/proto.h"

#include <ldns/ldns.h>

static const char* backup_str = "backup";

static recordset_type
lookupdenial(names_view_type view, ldns_rdf* dname)
{
    char* name;
    recordset_type record;
    name = ldns_rdf2str(dname);
    record = names_take(view, 1, name);
    free(name);
    return record;
}

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
        if (!strcmp(p, "rfc5011") && !strcmp(str, "keytag")) {
            return 1;
        }
        if (!strcmp(p, "jitter") && !strcmp(str, "keyset")) {
            return fseek(in, -7, SEEK_CUR) == 0;
        }

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
    if (!strcmp(p, "jitter")) {
        return fseek(in, -7, SEEK_CUR) == 0;
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
backup_read_namedb(FILE* in, zone_type* zone, names_view_type view)
{
    zone_type* z = (zone_type*) zone;
    recordset_type record;
    ldns_rr_list* rrset;
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
    char* name;
    uint32_t flags = 0;
    unsigned int l = 0;

    ods_log_assert(in);
    ods_log_assert(z);

    /* $ORIGIN <zone name> */
    dname = zone->apex;
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
        result = adapi_add_rr(z, view, rr, 1);
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

    names_viewcommit(view);
    
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
        record = lookupdenial(view, ldns_rr_owner(rr));
        if(record)
            names_recordsetdenial(record, rr);
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
#ifdef NOTDEFINED
        if (type_covered == LDNS_RR_TYPE_NSEC ||
            type_covered == LDNS_RR_TYPE_NSEC3) {
            names_viewlookupall(view, ldns_rr_owner(rr), type_covered, NULL, &rrset);
        } else {
            names_viewlookupall(view, ldns_rr_owner(rr), type_covered, NULL, &rrset);
        }
        if (!rrset) {
            ods_log_error("[%s] error restoring RRSIG #%i (%s): %s",
                backup_str, l, ldns_get_errorstr_by_id(status), line);
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_ERR;
            goto backup_namedb_done;
        }
#endif
        name = ldns_rdf2str(ldns_rr_owner(rr));
        record = names_place(view, name);
        free(name);
        names_recordaddsignature(record, type_covered, rr, locator, flags);
        locator = NULL; /* Locator is owned by rrset now */
    }
    if (result == ODS_STATUS_OK && status != LDNS_STATUS_OK) {
        ods_log_error("[%s] error reading RRSIG #%i (%s): %s",
            backup_str, l, ldns_get_errorstr_by_id(status), line);
        result = ODS_STATUS_ERR;
    }
    names_viewcommit(view);

backup_namedb_done:
    if (orig) {
        ldns_rdf_deep_free(orig);
        orig = NULL;
    }
    if (prev) {
        ldns_rdf_deep_free(prev);
        prev = NULL;
    }
    free(locator); /* if everything went well this is NULL. otherwise
                    clean up. */
    return result;
}


/**
 * Recover key from backup.
 *
 */
key_type*
key_recover2(FILE* fd, keylist_type* kl)
{
    const char* locator = NULL;
    const char* resourcerecord = NULL;
    uint8_t algorithm = 0;
    uint32_t flags = 0;
    int publish = 0;
    int ksk = 0;
    int zsk = 0;
    int keytag = 0; /* We are not actually interested but we must
        parse it to continue correctly in the stream.
        When reading 1.4.8 or later version backup file, the real value of keytag is 
        rfc5011, but not importat due to not using it.*/
    ods_log_assert(fd);

    if (!backup_read_check_str(fd, "locator") ||
        !backup_read_str(fd, &locator) ||
        !backup_read_check_str(fd, "algorithm") ||
        !backup_read_uint8_t(fd, &algorithm) ||
        !backup_read_check_str(fd, "flags") ||
        !backup_read_uint32_t(fd, &flags) ||
        !backup_read_check_str(fd, "publish") ||
        !backup_read_int(fd, &publish) ||
        !backup_read_check_str(fd, "ksk") ||
        !backup_read_int(fd, &ksk) ||
        !backup_read_check_str(fd, "zsk") ||
        !backup_read_int(fd, &zsk) ||
        !backup_read_check_str(fd, "keytag") ||
        !backup_read_int(fd, &keytag)) {
        if (locator) {
           free((void*)locator);
           locator = NULL;
        }
        return NULL;
    }
    /* key ok */
    return keylist_push(kl, locator, resourcerecord, algorithm, flags, publish, ksk, zsk);
}


/**
 * Backup duration.
 *
 */
static void
signconf_backup_duration(FILE* fd, const char* opt, duration_type* duration)
{
    char* str = (duration == NULL ? NULL : duration2string(duration));
    fprintf(fd, "%s %s ", opt, (str?str:"0"));
    free(str);
}

static void
upgraderecords(zone_type* zone, names_view_type view)
{
    names_iterator iter;
    recordset_type record;
    time_t expiration = LONG_MAX;
    ldns_rr_list* rrsigs;
    ldns_rr* rrsig;
    ldns_rdf* rrsigexpiration;
    time_t rrsigexpirationtime;
    uint32_t serial;
    serial = *zone->outboundserial;
    for(iter=names_viewiterator(view,NULL); names_iterate(&iter,&record);  names_advance(&iter,NULL)) {
        names_amend(view, record);
        names_recordsetvalidfrom(record, serial);
        names_recordlookupall(record, LDNS_RR_TYPE_RRSIG, NULL, NULL, &rrsigs);
        while ((rrsig=ldns_rr_list_pop_rr(rrsigs))) {
            rrsigexpiration = ldns_rr_rrsig_expiration(rrsig);
            rrsigexpirationtime = ldns_rdf2native_time_t(rrsigexpiration);
            if(rrsigexpirationtime < expiration)
                expiration = rrsigexpirationtime;
        }
        ldns_rr_list_free(rrsigs);
        names_recordsetexpiry(record, expiration);
    }
    names_viewcommit(view);
}

/**
 * Recover zone from backup.
 *
 */
ods_status
zone_recover(zone_type* zone)
{
    char* filename = NULL;
    FILE* fd = NULL;
    const char* token = NULL;
    time_t when = 0;
    ods_status status = ODS_STATUS_OK;
    /* zone part */
    int klass = 0;
    uint32_t inbound = 0, internal = 0, outbound = 0;
    /* signconf part */
    time_t lastmod = 0;
    /* nsec3params part */
    const char* salt = NULL;
    names_view_type view;

    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);

    filename = ods_build_path(zone->name, ".backup2", 0, 1);
    if (!filename) {
        return ODS_STATUS_MALLOC_ERR;
    }
    fd = ods_fopen(filename, NULL, "r");
    if (fd) {
        /* start recovery */
        if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC_V3)) {
            ods_log_error("[%s] corrupted backup file zone %s: read magic "
                "error", backup_str, zone->name);
            goto recover_error2;
        }
        if (!backup_read_check_str(fd, ";;Time:") |
            !backup_read_time_t(fd, &when)) {
            ods_log_error("[%s] corrupted backup file zone %s: read time "
                "error", backup_str, zone->name);
            goto recover_error2;
        }
        /* zone stuff */
        if (!backup_read_check_str(fd, ";;Zone:") |
            !backup_read_check_str(fd, "name") |
            !backup_read_check_str(fd, zone->name)) {
            ods_log_error("[%s] corrupted backup file zone %s: read name "
                "error", backup_str, zone->name);
            goto recover_error2;
        }
        if (!backup_read_check_str(fd, "class") |
            !backup_read_int(fd, &klass)) {
            ods_log_error("[%s] corrupted backup file zone %s: read class "
                "error", backup_str, zone->name);
            goto recover_error2;
        }
        if (!backup_read_check_str(fd, "inbound") |
            !backup_read_uint32_t(fd, &inbound) |
            !backup_read_check_str(fd, "internal") |
            !backup_read_uint32_t(fd, &internal) |
            !backup_read_check_str(fd, "outbound") |
            !backup_read_uint32_t(fd, &outbound)) {
            ods_log_error("[%s] corrupted backup file zone %s: read serial "
                "error", backup_str, zone->name);
            goto recover_error2;
        }
        zone->klass = (ldns_rr_class) klass;
        zone->inboundserial   = malloc(sizeof(uint32_t));
        zone->nextserial      = malloc(sizeof(uint32_t));
        zone->outboundserial  = malloc(sizeof(uint32_t));
        *zone->inboundserial  = inbound;
        *zone->nextserial     = internal;
        *zone->outboundserial = outbound;
        /* signconf part */
        if (!backup_read_check_str(fd, ";;Signconf:") |
            !backup_read_check_str(fd, "lastmod") |
            !backup_read_time_t(fd, &lastmod) |
            !backup_read_check_str(fd, "maxzonettl") |
            !backup_read_check_str(fd, "0") |
            !backup_read_check_str(fd, "resign") |
            !backup_read_duration(fd, &zone->signconf->sig_resign_interval) |
            !backup_read_check_str(fd, "refresh") |
            !backup_read_duration(fd, &zone->signconf->sig_refresh_interval) |
            !backup_read_check_str(fd, "valid") |
            !backup_read_duration(fd, &zone->signconf->sig_validity_default) |
            !backup_read_check_str(fd, "denial") |
            !backup_read_duration(fd,&zone->signconf->sig_validity_denial) |
            !backup_read_check_str(fd, "keyset") |
            !backup_read_duration(fd,&zone->signconf->sig_validity_keyset) |
            !backup_read_check_str(fd, "jitter") |
            !backup_read_duration(fd, &zone->signconf->sig_jitter) |
            !backup_read_check_str(fd, "offset") |
            !backup_read_duration(fd, &zone->signconf->sig_inception_offset) |
            !backup_read_check_str(fd, "nsec") |
            !backup_read_rr_type(fd, &zone->signconf->nsec_type) |
            !backup_read_check_str(fd, "dnskeyttl") |
            !backup_read_duration(fd, &zone->signconf->dnskey_ttl) |
            !backup_read_check_str(fd, "soattl") |
            !backup_read_duration(fd, &zone->signconf->soa_ttl) |
            !backup_read_check_str(fd, "soamin") |
            !backup_read_duration(fd, &zone->signconf->soa_min) |
            !backup_read_check_str(fd, "serial") |
            !backup_read_str(fd, &zone->signconf->soa_serial)) {
            ods_log_error("[%s] corrupted backup file zone %s: read signconf "
                "error", backup_str, zone->name);
            goto recover_error2;
        }
        /* nsec3params part */
        if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
            if (!backup_read_check_str(fd, ";;Nsec3parameters:") |
                !backup_read_check_str(fd, "salt") |
                !backup_read_str(fd, &salt) |
                !backup_read_check_str(fd, "algorithm") |
                !backup_read_uint32_t(fd, &zone->signconf->nsec3_algo) |
                !backup_read_check_str(fd, "optout") |
                !backup_read_int(fd, &zone->signconf->nsec3_optout) |
                !backup_read_check_str(fd, "iterations") |
                !backup_read_uint32_t(fd, &zone->signconf->nsec3_iterations)) {
                ods_log_error("[%s] corrupted backup file zone %s: read "
                    "nsec3parameters error", backup_str, zone->name);
                goto recover_error2;
            }
            zone->signconf->nsec3_salt = strdup(salt);
            free((void*) salt);
            salt = NULL;
            zone->signconf->nsec3params = nsec3params_create(
                zone->signconf,
                (uint8_t) zone->signconf->nsec3_algo,
                (uint8_t) zone->signconf->nsec3_optout,
                (uint16_t) zone->signconf->nsec3_iterations,
                zone->signconf->nsec3_salt);
            if (!zone->signconf->nsec3params) {
                ods_log_error("[%s] corrupted backup file zone %s: unable to "
                    "create nsec3param", backup_str, zone->name);
                goto recover_error2;
            }
        }
        zone->signconf->last_modified = lastmod;
        zone->zoneconfigvalid = 1;
        zone->default_ttl = (uint32_t) duration2time(zone->signconf->soa_min);
        /* keys part */
        zone->signconf->keys = keylist_create((void*) zone->signconf);
        while (backup_read_str(fd, &token)) {
            if (ods_strcmp(token, ";;Key:") == 0) {
                if (!key_recover2(fd, zone->signconf->keys)) {
                    ods_log_error("[%s] corrupted backup file zone %s: read "
                        "key error", backup_str, zone->name);
                    goto recover_error2;
                }
            } else if (ods_strcmp(token, ";;") == 0) {
                /* keylist done */
                free((void*) token);
                token = NULL;
                break;
            } else {
                /* keylist corrupted */
                goto recover_error2;
            }
            free((void*) token);
            token = NULL;
        }

        view = names_viewcreate(zone->baseview, names_view_BACKUP[0], &names_view_BACKUP[1]);

        /* publish dnskeys */
        status = zone_publish_dnskeys(zone, view, 1);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] corrupted backup file zone %s: unable to "
                "publish dnskeys (%s)", backup_str, zone->name,
                ods_status2str(status));
            goto recover_error2;
        }
        /* publish nsec3param */
        if (zone->signconf->passthrough != 1)
            status = zone_publish_nsec3param(zone, view);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] corrupted backup file zone %s: unable to "
                "publish nsec3param (%s)", backup_str, zone->name,
                ods_status2str(status));
            goto recover_error2;
        }
        /* publish other records */
        status = backup_read_namedb(fd, zone, view);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] corrupted backup file zone %s: unable to "
                "read resource records (%s)", backup_str, zone->name,
                ods_status2str(status));
            goto recover_error2;
        }

        upgraderecords(zone, view);

        /* all ok */
        names_viewdestroy(view);
        if (fd != NULL) {
            ods_fclose(fd);
        }
        if (zone->stats) {
            pthread_mutex_lock(&zone->stats->stats_lock);
            stats_clear(zone->stats);
            pthread_mutex_unlock(&zone->stats->stats_lock);
        }
        return ODS_STATUS_OK;
    }
    free(filename);
    return ODS_STATUS_UNCHANGED;

  recover_error2:
    return -1;
}
