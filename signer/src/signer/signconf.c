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
 * Signer configuration.
 *
 */

#include "parser/signconfparser.h"
#include "duration.h"
#include "file.h"
#include "log.h"
#include "status.h"
#include "signer/signconf.h"

static const char* sc_str = "signconf";


/**
 * Create a new signer configuration with the 'empty' settings.
 *
 */
signconf_type*
signconf_create(void)
{
    signconf_type* sc = NULL;
    CHECKALLOC(sc = (signconf_type*) malloc(sizeof(signconf_type)));
    sc->filename = NULL;
    sc->passthrough = 0;
    /* Signatures */
    sc->sig_resign_interval = NULL;
    sc->sig_refresh_interval = NULL;
    sc->sig_validity_default = NULL;
    sc->sig_validity_denial = NULL;
    sc->sig_validity_keyset = NULL;
    sc->sig_jitter = NULL;
    sc->sig_inception_offset = NULL;
    /* Denial of existence */
    sc->nsec3param_ttl = NULL;
    sc->nsec_type = 0;
    sc->nsec3_optout = 0;
    sc->nsec3_algo = 0;
    sc->nsec3_iterations = 0;
    sc->nsec3_salt = NULL;
    sc->nsec3params = NULL;
    /* Keys */
    sc->dnskey_ttl = NULL;
    sc->dnskey_signature = NULL;
    sc->keys = NULL;
    /* Source of authority */
    sc->soa_ttl = NULL;
    sc->soa_min = NULL;
    sc->soa_serial = NULL;
    /* Other useful information */
    sc->max_zone_ttl = NULL;
    sc->last_modified = 0;
    return sc;
}


/**
 * Read signer configuration.
 *
 */
static ods_status
signconf_read(signconf_type* signconf, const char* scfile)
{
    const char* rngfile = ODS_SE_RNGDIR "/signconf.rng";
    ods_status status = ODS_STATUS_OK;
    FILE* fd = NULL;

    if (!scfile || !signconf) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_debug("[%s] read signconf file %s", sc_str, scfile);
    status = parse_file_check(scfile, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read signconf: parse error in "
            "file %s (%s)", sc_str, scfile, ods_status2str(status));
        return status;
    }
    fd = ods_fopen(scfile, NULL, "r");
    if (fd) {
        signconf->filename = strdup(scfile);
        signconf->passthrough = parse_sc_passthrough(scfile);
        signconf->sig_resign_interval = parse_sc_sig_resign_interval(scfile);
        signconf->sig_refresh_interval = parse_sc_sig_refresh_interval(scfile);
        signconf->sig_validity_default = parse_sc_sig_validity_default(scfile);
        signconf->sig_validity_denial = parse_sc_sig_validity_denial(scfile);
        signconf->sig_validity_keyset = parse_sc_sig_validity_keyset(scfile);
        signconf->sig_jitter = parse_sc_sig_jitter(scfile);
        signconf->sig_inception_offset = parse_sc_sig_inception_offset(scfile);
        signconf->nsec_type = parse_sc_nsec_type(scfile);
        if (signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
            signconf->nsec3param_ttl = parse_sc_nsec3param_ttl(scfile);
            signconf->nsec3_optout = parse_sc_nsec3_optout(scfile);
            signconf->nsec3_algo = parse_sc_nsec3_algorithm(scfile);
            signconf->nsec3_iterations = parse_sc_nsec3_iterations(scfile);
            signconf->nsec3_salt = parse_sc_nsec3_salt(scfile);
            signconf->nsec3params = nsec3params_create((void*) signconf,
            (uint8_t) signconf->nsec3_algo, (uint8_t) signconf->nsec3_optout,
            (uint16_t)signconf->nsec3_iterations, signconf->nsec3_salt);
            if (!signconf->nsec3params) {
                ods_log_error("[%s] unable to read signconf %s: "
                    "nsec3params_create() failed", sc_str, scfile);
                ods_fclose(fd);
                return ODS_STATUS_MALLOC_ERR;
            }
        }
        signconf->keys = parse_sc_keys((void*) signconf, scfile);
        signconf->dnskey_ttl = parse_sc_dnskey_ttl(scfile);
        signconf->dnskey_signature = parse_sc_dnskey_sigrrs(scfile);
        signconf->soa_ttl = parse_sc_soa_ttl(scfile);
        signconf->soa_min = parse_sc_soa_min(scfile);
        signconf->soa_serial = parse_sc_soa_serial(scfile);
        signconf->max_zone_ttl = parse_sc_max_zone_ttl(scfile);
        ods_fclose(fd);
        return ODS_STATUS_OK;
    }
    ods_log_error("[%s] unable to read signconf: failed to open file %s",
        sc_str, scfile);
    return ODS_STATUS_ERR;
}


/**
 * Update signer configuration.
 *
 */
ods_status
signconf_update(signconf_type** signconf, const char* scfile,
    time_t last_modified)
{
    signconf_type* new_sc = NULL;
    time_t st_mtime = 0;
    ods_status status = ODS_STATUS_OK;

    if (!scfile || !signconf) {
        return ODS_STATUS_UNCHANGED;
    }
    /* is the file updated? */
    st_mtime = ods_file_lastmodified(scfile);
    if (st_mtime <= last_modified) {
        return ODS_STATUS_UNCHANGED;
    }
    /* if so, read the new signer configuration */
    new_sc = signconf_create();
    if (!new_sc) {
        ods_log_error("[%s] unable to update signconf: signconf_create() "
            "failed", sc_str);
        return ODS_STATUS_ERR;
    }
    status = signconf_read(new_sc, scfile);
    if (status == ODS_STATUS_OK) {
        new_sc->last_modified = st_mtime;
        if (signconf_check(new_sc) != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to update signconf: signconf %s has "
                "errors", sc_str, scfile);
            signconf_cleanup(new_sc);
            return ODS_STATUS_CFG_ERR;
        }
        *signconf = new_sc;
    } else {
        ods_log_error("[%s] unable to update signconf: failed to read file "
            "%s (%s)", sc_str, scfile, ods_status2str(status));
        signconf_cleanup(new_sc);
    }
    return status;
}


/**
 * Check the SOA/Serial type.
 *
 */
static int
signconf_soa_serial_check(const char* serial) {
    if (!serial) {
        return 1;
    }

    if (strlen(serial) == 4 && strncmp(serial, "keep", 4) == 0) {
        return 0;
    }
    if (strlen(serial) == 7 && strncmp(serial, "counter", 7) == 0) {
        return 0;
    }
    if (strlen(serial) == 8 && strncmp(serial, "unixtime", 8) == 0) {
        return 0;
    }
    if (strlen(serial) == 11 && strncmp(serial, "datecounter", 11) == 0) {
        return 0;
    }
    return 1;
}


/**
 * Check signer configuration settings.
 *
 */
ods_status
signconf_check(signconf_type* sc)
{
    ods_status status = ODS_STATUS_OK;

    if (!sc->sig_resign_interval) {
        ods_log_error("[%s] check failed: no signature resign interval found",
            sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!sc->sig_refresh_interval) {
        ods_log_error("[%s] check failed: no signature resign interval found",
            sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!sc->sig_validity_default) {
        ods_log_error("[%s] check failed: no signature default validity found",
            sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!sc->sig_validity_denial) {
        ods_log_error("[%s] check failed: no signature denial validity found",
            sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!sc->sig_jitter) {
        ods_log_error("[%s] check failed: no signature jitter found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!sc->sig_inception_offset) {
        ods_log_error("[%s] check failed: no signature inception offset found",
            sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (sc->nsec_type == LDNS_RR_TYPE_NSEC3) {
        if (sc->nsec3_algo != LDNS_SHA1) {
            ods_log_error("[%s] check failed: invalid nsec3 algorithm",
                sc_str);
            status = ODS_STATUS_CFG_ERR;
        }
        /* iterations */
        /* salt */
        /* optout */
    } else if (sc->nsec_type != LDNS_RR_TYPE_NSEC) {
        ods_log_error("[%s] check failed: wrong nsec type %i", sc_str,
            sc->nsec_type);
        status = ODS_STATUS_CFG_ERR;
    }
    if ((!sc->keys || sc->keys->count == 0) && !sc->passthrough) {
        ods_log_error("[%s] check failed: no keys found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!sc->dnskey_ttl) {
        ods_log_error("[%s] check failed: no dnskey ttl found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!sc->soa_ttl) {
        ods_log_error("[%s] check failed: no soa ttl found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!sc->soa_min) {
        ods_log_error("[%s] check failed: no soa minimum found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!sc->soa_serial) {
        ods_log_error("[%s] check failed: no soa serial type found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    } else if (signconf_soa_serial_check(sc->soa_serial) != 0) {
        ods_log_error("[%s] check failed: wrong soa serial type %s", sc_str,
            sc->soa_serial);
        status = ODS_STATUS_CFG_ERR;
    }
    return status;
}


/**
 * Compare signer configurations on denial of existence material.
 *
 */
task_id
signconf_compare_denial(signconf_type* a, signconf_type* b)
{
    task_id new_task = TASK_NONE;
    if (!a || !b) {
        return TASK_NONE;
    }
    ods_log_assert(a);
    ods_log_assert(b);

   if (duration_compare(a->soa_min, b->soa_min)) {
       new_task = TASK_NSECIFY;
   } else if (a->nsec_type != b->nsec_type) {
       new_task = TASK_NSECIFY;
   } else if (a->nsec_type == LDNS_RR_TYPE_NSEC3) {
       if ((ods_strcmp(a->nsec3_salt, b->nsec3_salt) != 0) ||
           (a->nsec3_algo != b->nsec3_algo) ||
           (a->nsec3_iterations != b->nsec3_iterations) ||
           (a->nsec3_optout != b->nsec3_optout)) {

            new_task = TASK_NSECIFY;
        } else if (duration_compare(a->nsec3param_ttl, b->nsec3param_ttl)) {
           new_task = TASK_READ;
        }
    }
    return new_task;
}


/**
 * Log sign configuration.
 *
 */
void
signconf_log(signconf_type* sc, const char* name)
{
    char* resign = NULL;
    char* refresh = NULL;
    char* validity = NULL;
    char* denial = NULL;
    char* keyset = NULL;
    char* jitter = NULL;
    char* offset = NULL;
    char* dnskeyttl = NULL;
    char* soattl = NULL;
    char* soamin = NULL;
    char* paramttl = NULL;

    if (sc) {
        resign = duration2string(sc->sig_resign_interval);
        refresh = duration2string(sc->sig_refresh_interval);
        validity = duration2string(sc->sig_validity_default);
        denial = duration2string(sc->sig_validity_denial);
        if (sc->sig_validity_keyset) {
            keyset = duration2string(sc->sig_validity_keyset);
        }
        jitter = duration2string(sc->sig_jitter);
        offset = duration2string(sc->sig_inception_offset);
        dnskeyttl = duration2string(sc->dnskey_ttl);
        paramttl = duration2string(sc->nsec3param_ttl);
        soattl = duration2string(sc->soa_ttl);
        soamin = duration2string(sc->soa_min);
        /* signconf */
        ods_log_info("[%s] zone %s signconf: RESIGN[%s] REFRESH[%s] "
            "%sVALIDITY[%s] DENIAL[%s] KEYSET[%s] JITTER[%s] OFFSET[%s] NSEC[%i] "
            "DNSKEYTTL[%s] SOATTL[%s] MINIMUM[%s] SERIAL[%s]",
            sc_str,
            name?name:"(null)",
            resign?resign:"(null)",
            refresh?refresh:"(null)",
            sc->passthrough?"PASSTHROUGH ":"",
            validity?validity:"(null)",
            denial?denial:"(null)",
            keyset?keyset:"(null)",
            jitter?jitter:"(null)",
            offset?offset:"(null)",
            (int) sc->nsec_type,
            dnskeyttl?dnskeyttl:"(null)",
            soattl?soattl:"(null)",
            soamin?soamin:"(null)",
            sc->soa_serial?sc->soa_serial:"(null)");
        /* nsec3 parameters */
        if (sc->nsec_type == LDNS_RR_TYPE_NSEC3) {
            ods_log_debug("[%s] zone %s nsec3: PARAMTTL[%s] OPTOUT[%i] "
                "ALGORITHM[%u] ITERATIONS[%u] SALT[%s]",
                sc_str,
                name?name:"(null)",
                paramttl?paramttl:"PT0S",
                sc->nsec3_optout,
                sc->nsec3_algo,
                sc->nsec3_iterations,
                sc->nsec3_salt?sc->nsec3_salt:"(null)");
        }
        /* keys */
        keylist_log(sc->keys, name);
        /* cleanup */
        free((void*)resign);
        free((void*)refresh);
        free((void*)validity);
        free((void*)denial);
        free((void*)keyset);
        free((void*)jitter);
        free((void*)offset);
        free((void*)dnskeyttl);
        free((void*)paramttl);
        free((void*)soattl);
        free((void*)soamin);
    }
}


/**
 * Clean up signer configuration.
 *
 */
void
signconf_cleanup(signconf_type* sc)
{
    if (!sc) {
        return;
    }
    duration_cleanup(sc->sig_resign_interval);
    duration_cleanup(sc->sig_refresh_interval);
    duration_cleanup(sc->sig_validity_default);
    duration_cleanup(sc->sig_validity_denial);
    duration_cleanup(sc->sig_validity_keyset);
    duration_cleanup(sc->sig_jitter);
    duration_cleanup(sc->sig_inception_offset);
    duration_cleanup(sc->dnskey_ttl);
    duration_cleanup(sc->soa_ttl);
    duration_cleanup(sc->soa_min);
    duration_cleanup(sc->max_zone_ttl);
    keylist_cleanup(sc->keys);
    nsec3params_cleanup(sc->nsec3params);
    free((void*)sc->filename);
    free((void*)sc->nsec3_salt);
    free((void*)sc->soa_serial);
    free(sc);
}
