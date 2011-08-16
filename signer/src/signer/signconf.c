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
 * Signer configuration.
 *
 */

#include "parser/confparser.h"
#include "parser/signconfparser.h"
#include "scheduler/task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/hsm.h"
#include "shared/log.h"
#include "signer/backup.h"
#include "shared/status.h"
#include "signer/keys.h"
#include "signer/signconf.h"

static const char* sc_str = "signconf";


/**
 * Create a new signer configuration with the 'empty' settings.
 *
 */
signconf_type*
signconf_create(void)
{
    signconf_type* sc;
    allocator_type* allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create: create allocator failed",
            sc_str);
        return NULL;
    }
    ods_log_assert(allocator);

    sc = (signconf_type*) allocator_alloc(allocator, sizeof(signconf_type));
    if (!sc) {
        ods_log_error("[%s] unable to create: allocator failed", sc_str);
        allocator_cleanup(allocator);
        return NULL;
    }
    ods_log_assert(sc);
    sc->allocator = allocator;
    sc->filename = NULL;
    /* Signatures */
    sc->sig_resign_interval = NULL;
    sc->sig_refresh_interval = NULL;
    sc->sig_validity_default = NULL;
    sc->sig_validity_denial = NULL;
    sc->sig_jitter = NULL;
    sc->sig_inception_offset = NULL;
    /* Denial of existence */
    sc->nsec_type = 0;
    sc->nsec3_optout = 0;
    sc->nsec3_algo = 0;
    sc->nsec3_iterations = 0;
    sc->nsec3_salt = NULL;
    /* Keys */
    sc->dnskey_ttl = NULL;
    sc->keys = NULL;
    /* Source of authority */
    sc->soa_ttl = NULL;
    sc->soa_min = NULL;
    sc->soa_serial = NULL;
    /* Other useful information */
    sc->last_modified = 0;
    sc->audit = 0;
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

    ods_log_assert(scfile);
    ods_log_assert(signconf);
    ods_log_debug("[%s] read file %s", sc_str, scfile);

    status = parse_file_check(scfile, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to parse file %s: %s", sc_str, scfile,
            ods_status2str(status));
        return status;
    }

    fd = ods_fopen(scfile, NULL, "r");
    if (fd) {
        signconf->filename = allocator_strdup(signconf->allocator, scfile);
        signconf->sig_resign_interval = parse_sc_sig_resign_interval(scfile);
        signconf->sig_refresh_interval = parse_sc_sig_refresh_interval(scfile);
        signconf->sig_validity_default = parse_sc_sig_validity_default(scfile);
        signconf->sig_validity_denial = parse_sc_sig_validity_denial(scfile);
        signconf->sig_jitter = parse_sc_sig_jitter(scfile);
        signconf->sig_inception_offset = parse_sc_sig_inception_offset(scfile);
        signconf->nsec_type = parse_sc_nsec_type(scfile);
        if (signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
            signconf->nsec3_optout = parse_sc_nsec3_optout(scfile);
            signconf->nsec3_algo = parse_sc_nsec3_algorithm(scfile);
            signconf->nsec3_iterations = parse_sc_nsec3_iterations(scfile);
            signconf->nsec3_salt = parse_sc_nsec3_salt(signconf->allocator,
                scfile);
        }
        signconf->keys = parse_sc_keys(signconf->allocator, scfile);
        signconf->dnskey_ttl = parse_sc_dnskey_ttl(scfile);
        signconf->soa_ttl = parse_sc_soa_ttl(scfile);
        signconf->soa_min = parse_sc_soa_min(scfile);
        signconf->soa_serial = parse_sc_soa_serial(signconf->allocator,
            scfile);
        signconf->audit = parse_sc_audit(scfile);
        ods_fclose(fd);
        return ODS_STATUS_OK;
    }
    ods_log_error("[%s] unable to read signconf file %s", sc_str, scfile);
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

    if (!signconf) {
        ods_log_error("[%s] no signconf storage", sc_str);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_assert(signconf);
    if (!scfile) {
        ods_log_error("[%s] no signconf filename", sc_str);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_assert(scfile);

    /* is the file updated? */
    st_mtime = ods_file_lastmodified(scfile);
    if (st_mtime <= last_modified) {
        return ODS_STATUS_UNCHANGED;
    }

    new_sc = signconf_create();
    if (!new_sc) {
        ods_log_error("[%s] error creating new signconf", sc_str);
        return ODS_STATUS_ERR;
    }

    status = signconf_read(new_sc, scfile);
    if (status == ODS_STATUS_OK) {
        new_sc->last_modified = st_mtime;
        if (signconf_check(new_sc) != ODS_STATUS_OK) {
            ods_log_error("[%s] signconf %s has errors", sc_str, scfile);
            signconf_cleanup(new_sc);
            return ODS_STATUS_CFG_ERR;
        }
        *signconf = new_sc;
    } else {
        ods_log_error("[%s] unable to read file %s: %s", sc_str, scfile,
            ods_status2str(status));
        signconf_cleanup(new_sc);
    }
    return status;
}


/**
 * Read a signer configuration from backup.
 *
 */
signconf_type*
signconf_recover_from_backup(const char* filename)
{
    signconf_type* signconf = NULL;
    const char* zonename = NULL;
    FILE* scfd = NULL;

    scfd = ods_fopen(filename, NULL, "r");
    if (scfd) {
        signconf = signconf_create();

        if (!backup_read_check_str(scfd, ODS_SE_FILE_MAGIC) ||
            !backup_read_check_str(scfd, ";name:") ||
            !backup_read_str(scfd, &zonename) ||
            !backup_read_check_str(scfd, ";filename:") ||
            !backup_read_str(scfd, &signconf->filename) ||
            !backup_read_check_str(scfd, ";last_modified:") ||
            !backup_read_time_t(scfd, &signconf->last_modified) ||
            !backup_read_check_str(scfd, ";sig_resign_interval:") ||
            !backup_read_duration(scfd, &signconf->sig_resign_interval) ||
            !backup_read_check_str(scfd, ";sig_refresh_interval:") ||
            !backup_read_duration(scfd, &signconf->sig_refresh_interval) ||
            !backup_read_check_str(scfd, ";sig_validity_default:") ||
            !backup_read_duration(scfd, &signconf->sig_validity_default) ||
            !backup_read_check_str(scfd, ";sig_validity_denial:") ||
            !backup_read_duration(scfd, &signconf->sig_validity_denial) ||
            !backup_read_check_str(scfd, ";sig_jitter:") ||
            !backup_read_duration(scfd, &signconf->sig_jitter) ||
            !backup_read_check_str(scfd, ";sig_inception_offset:") ||
            !backup_read_duration(scfd, &signconf->sig_inception_offset) ||
            !backup_read_check_str(scfd, ";nsec_type:") ||
            !backup_read_rr_type(scfd, &signconf->nsec_type) ||
            !backup_read_check_str(scfd, ";dnskey_ttl:") ||
            !backup_read_duration(scfd, &signconf->dnskey_ttl) ||
            !backup_read_check_str(scfd, ";soa_ttl:") ||
            !backup_read_duration(scfd, &signconf->soa_ttl) ||
            !backup_read_check_str(scfd, ";soa_min:") ||
            !backup_read_duration(scfd, &signconf->soa_min) ||
            !backup_read_check_str(scfd, ";soa_serial:") ||
            !backup_read_str(scfd, &signconf->soa_serial) ||
            !backup_read_check_str(scfd, ";audit:") ||
            !backup_read_int(scfd, &signconf->audit) ||
            !backup_read_check_str(scfd, ODS_SE_FILE_MAGIC))
        {
            ods_log_error("[%s] unable to recover signconf backup file %s: corrupt "
                "backup file ", sc_str, filename?filename:"(null)");
            signconf_cleanup(signconf);
            signconf = NULL;
        }

        if (zonename) {
            free((void*) zonename);
        }
        ods_fclose(scfd);
        return signconf;
    }

    ods_log_debug("[%s] unable to recover signconf backup file %s", sc_str,
        filename?filename:"(null)");
    return NULL;
}


/**
 * Backup duration.
 *
 */
static void
signconf_backup_duration(FILE* fd, const char* opt, duration_type* duration)
{
    char* str = duration2string(duration);
    fprintf(fd, "%s %s ", opt, str);
    free((void*) str);
    return;
}



/**
 * Backup signconf values.
 *
 */
void
signconf_backup(FILE* fd, signconf_type* sc)
{
    if (!fd || !sc) {
        return;
    }
    ods_log_assert(fd);
    ods_log_assert(sc);

    fprintf(fd, ";;Signconf: lastmod %u ", (unsigned) sc->last_modified);
    signconf_backup_duration(fd, "resign", sc->sig_resign_interval);
    signconf_backup_duration(fd, "refresh", sc->sig_refresh_interval);
    signconf_backup_duration(fd, "valid", sc->sig_validity_default);
    signconf_backup_duration(fd, "denial", sc->sig_validity_denial);
    signconf_backup_duration(fd, "jitter", sc->sig_jitter);
    signconf_backup_duration(fd, "offset", sc->sig_inception_offset);
    fprintf(fd, "nsec %u ", (unsigned) sc->nsec_type);
    signconf_backup_duration(fd, "dnskeyttl", sc->dnskey_ttl);
    signconf_backup_duration(fd, "soattl", sc->soa_ttl);
    signconf_backup_duration(fd, "soamin", sc->soa_min);
    fprintf(fd, "serial %s ", sc->soa_serial?sc->soa_serial:"(null)");
    fprintf(fd, "audit %i\n", sc->audit);
    return;
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
        if (sc->nsec3_algo == 0) {
            ods_log_error("[%s] check failed: no nsec3 algorithm found",
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
    if (!sc->keys || sc->keys->count == 0) {
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

   if (a->nsec_type != b->nsec_type) {
       new_task = TASK_NSECIFY;
   } else if (a->nsec_type == LDNS_RR_TYPE_NSEC3) {
       if ((ods_strcmp(a->nsec3_salt, b->nsec3_salt) != 0) ||
           (a->nsec3_algo != b->nsec3_algo) ||
           (a->nsec3_iterations != b->nsec3_iterations) ||
           (a->nsec3_optout != b->nsec3_optout)) {

           new_task = TASK_NSECIFY;
       }
   }
   return new_task;
}


/**
 * Compare signer configurations on key material.
 *
 */
task_id
signconf_compare_keys(signconf_type* a, signconf_type* b, ldns_rr_list* del)
{
   task_id new_task = TASK_NONE;
    ods_status status = ODS_STATUS_OK;
    key_type* walk = NULL;
    key_type* ka = NULL;
    key_type* kb = NULL;
    int remove = 0;
    int copy = 0;

    if (!a || !b) {
       return TASK_NONE;
    }
    ods_log_assert(a);
    ods_log_assert(b);

    /* keys deleted? */
    if (a->keys) {
        walk = a->keys->first_key;
    }
    while (walk && walk->locator) {
        remove = 0;
        copy = 0;

        kb = keylist_lookup(b->keys, walk->locator);
        if (!kb) {
            remove = 1; /* [DEL] key removed from signconf */
        } else {
            if (duration_compare(a->dnskey_ttl, b->dnskey_ttl) != 0) {
                remove = 1; /* [DEL] consider to be different key */
            } else if (walk->flags != kb->flags) {
                remove = 1; /* [DEL] consider to be different key */
            } else if (walk->algorithm != kb->algorithm) {
                remove = 1; /* [DEL] consider to be different key */
            } else if (walk->publish != kb->publish) {
                if (walk->publish) {
                    remove = 1; /* [DEL] withdraw dnskey from zone */
                } else {
                    new_task = TASK_READ; /* [ADD] introduce key to zone */
                }
            } else if (walk->ksk != kb->ksk) {
                copy = 1; /* [UNCHANGED] same key, different role */
            } else if (walk->zsk != kb->zsk) {
                copy = 1; /* [UNCHANGED] same key, different role */
            } else {
                /* [UNCHANGED] identical key credentials */
                copy = 1;
            }
        }

        if (remove) {
            new_task = TASK_READ;
            if (del && walk->dnskey) {
                if (!ldns_rr_list_push_rr(del, walk->dnskey)) {
                    ods_log_error("[%s] del key failed", sc_str);
                    new_task = TASK_SIGNCONF;
                    break;
                }
            }
        } else if (copy) {
            if (walk->dnskey && !kb->dnskey) {
                kb->dnskey = walk->dnskey;
                kb->hsmkey = walk->hsmkey;
                status = lhsm_get_key(NULL, ldns_rr_owner(walk->dnskey), kb);
                walk->hsmkey = NULL;
                walk->dnskey = NULL;
            }
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] copy key failed", sc_str);
                new_task = TASK_SIGNCONF;
                break;
            }
        }
        walk = walk->next;
    }

    if (new_task == TASK_NONE) {
        /* no error and no keys were deleted, perhaps keys were added */
        walk = NULL;
        if (b->keys) {
            walk = b->keys->first_key;
        }
        while (walk) {
            ka = keylist_lookup(a->keys, walk->locator);
            if (!ka) {
                new_task = TASK_READ; /* [ADD] key added to signconf */
                break;
            }
            /**
             * Keys in ka and kb with the same locator, have been
             * compared when checking for deleted keys.
             */
            walk = walk->next;
        }
    }
   return new_task;
}


/**
 * Compare signer configurations.
 *
 */
task_id
signconf_compare(signconf_type* a, signconf_type* b)
{
    task_id new_task = TASK_NONE;
    task_id tmp_task = TASK_NONE;

    new_task = signconf_compare_denial(a, b);
    tmp_task = signconf_compare_keys(a, b, NULL);
    if (tmp_task != TASK_NONE) {
        new_task = tmp_task;
    }
    /* not like python: reschedule if resign/refresh differs */
    /* this needs review, tasks correct on signconf changes? */
    return new_task;
}


/**
 * Clean up signer configuration.
 *
 */
void
signconf_cleanup(signconf_type* sc)
{
    allocator_type* allocator;
    if (!sc) {
        return;
    }
    duration_cleanup(sc->sig_resign_interval);
    duration_cleanup(sc->sig_refresh_interval);
    duration_cleanup(sc->sig_validity_default);
    duration_cleanup(sc->sig_validity_denial);
    duration_cleanup(sc->sig_jitter);
    duration_cleanup(sc->sig_inception_offset);
    duration_cleanup(sc->dnskey_ttl);
    duration_cleanup(sc->soa_ttl);
    duration_cleanup(sc->soa_min);
    keylist_cleanup(sc->keys);

    allocator = sc->allocator;
    allocator_deallocate(allocator, (void*) sc->filename);
    allocator_deallocate(allocator, (void*) sc->nsec3_salt);
    allocator_deallocate(allocator, (void*) sc->soa_serial);
    allocator_deallocate(allocator, (void*) sc);
    allocator_cleanup(allocator);
    return;
}


/**
 * Print sign configuration.
 *
 */
void
signconf_print(FILE* out, signconf_type* sc, const char* name)
{
    char* s = NULL;

    fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

    if (sc) {
        fprintf(out, "<SignerConfiguration>\n");
        fprintf(out, "\t<Zone name=\"%s\">\n", name?name:"(null)");

        /* Signatures */
        fprintf(out, "\t\t<Signatures>\n");
        s = duration2string(sc->sig_resign_interval);
        fprintf(out, "\t\t\t<Resign>%s</Resign>\n", s?s:"(null)");
        free((void*)s);

        s = duration2string(sc->sig_refresh_interval);
        fprintf(out, "\t\t\t<Refresh>%s</Refresh>\n", s?s:"(null)");
        free((void*)s);

        fprintf(out, "\t\t\t<Validity>\n");

        s = duration2string(sc->sig_validity_default);
        fprintf(out, "\t\t\t\t<Default>%s</Default>\n", s?s:"(null)");
        free((void*)s);

        s = duration2string(sc->sig_validity_denial);
        fprintf(out, "\t\t\t\t<Denial>%s</Denial>\n", s?s:"(null)");
        free((void*)s);

        fprintf(out, "\t\t\t</Validity>\n");

        s = duration2string(sc->sig_jitter);
        fprintf(out, "\t\t\t<Jitter>%s</Jitter>\n", s?s:"(null)");
        free((void*)s);

        s = duration2string(sc->sig_inception_offset);
        fprintf(out, "\t\t\t<InceptionOffset>%s</InceptionOffset>\n",
            s?s:"(null)");
        free((void*)s);

        fprintf(out, "\t\t</Signatures>\n");
        fprintf(out, "\n");

        /* Denial */
        fprintf(out, "\t\t<Denial>\n");
        if (sc->nsec_type == LDNS_RR_TYPE_NSEC) {
            fprintf(out, "\t\t\t<NSEC />\n");
        } else if (sc->nsec_type == LDNS_RR_TYPE_NSEC3) {
            fprintf(out, "\t\t\t<NSEC3>\n");
            if (sc->nsec3_optout) {
                fprintf(out, "\t\t\t\t<OptOut />\n");
            }
            fprintf(out, "\t\t\t\t<Hash>\n");
            fprintf(out, "\t\t\t\t\t<Algorithm>%i</Algorithm>\n",
                sc->nsec3_algo);
            fprintf(out, "\t\t\t\t\t<Iterations>%i</Iterations>\n",
                sc->nsec3_iterations);
            fprintf(out, "\t\t\t\t\t<Salt>%s</Salt>\n",
                sc->nsec3_salt?sc->nsec3_salt:"(null)");
            fprintf(out, "\t\t\t\t</Hash>\n");
            fprintf(out, "\t\t\t</NSEC3>\n");
        }
        fprintf(out, "\t\t</Denial>\n");
        fprintf(out, "\n");

        /* Keys */
        fprintf(out, "\t\t<Keys>\n");
        s = duration2string(sc->dnskey_ttl);
        fprintf(out, "\t\t\t<TTL>%s</TTL>\n", s?s:"(null)");
        free((void*)s);
        fprintf(out, "\n");
        keylist_print(out, sc->keys);
        fprintf(out, "\t\t</Keys>\n");
        fprintf(out, "\n");

        /* SOA */
        fprintf(out, "\t\t<SOA>\n");
        s = duration2string(sc->soa_ttl);
        fprintf(out, "\t\t\t<TTL>%s</TTL>\n", s?s:"(null)");
        free((void*)s);

        s = duration2string(sc->soa_min);
        fprintf(out, "\t\t\t<Minimum>%s</Minimum>\n", s?s:"(null)");
        free((void*)s);

        fprintf(out, "\t\t\t<Serial>%s</Serial>\n",
            sc->soa_serial?sc->soa_serial:"(null)");
        fprintf(out, "\t\t</SOA>\n");
        fprintf(out, "\n");

        /* Audit */
        if (sc->audit) {
            fprintf(out, "\t\t<Audit />\n");
            fprintf(out, "\n");
        }

        fprintf(out, "\t</Zone>\n");
        fprintf(out, "</SignerConfiguration>\n");
    }
    return;
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
    char* jitter = NULL;
    char* offset = NULL;
    char* dnskeyttl = NULL;
    char* soattl = NULL;
    char* soamin = NULL;

    if (sc) {
        resign = duration2string(sc->sig_resign_interval);
        refresh = duration2string(sc->sig_refresh_interval);
        validity = duration2string(sc->sig_validity_default);
        denial = duration2string(sc->sig_validity_denial);
        jitter = duration2string(sc->sig_jitter);
        offset = duration2string(sc->sig_inception_offset);
        dnskeyttl = duration2string(sc->dnskey_ttl);
        soattl = duration2string(sc->soa_ttl);
        soamin = duration2string(sc->soa_min);

        ods_log_info("[%s] zone %s signconf: RESIGN[%s] REFRESH[%s] "
            "VALIDITY[%s] DENIAL[%s] JITTER[%s] OFFSET[%s] NSEC[%i] "
            "DNSKEYTTL[%s] SOATTL[%s] MINIMUM[%s] SERIAL[%s] AUDIT[%i]",
            sc_str, name?name:"(null)", resign, refresh, validity, denial,
            jitter, offset, (int) sc->nsec_type, dnskeyttl, soattl,
            soamin, sc->soa_serial?sc->soa_serial:"(null)",
            (int) sc->audit);

        if (sc->nsec_type == LDNS_RR_TYPE_NSEC3) {
            ods_log_debug("[%s] zone %s nsec3: OPTOUT[%i] ALGORITHM[%u] "
                "ITERATIONS[%u] SALT[%s]", sc_str, name, sc->nsec3_optout,
                sc->nsec3_algo, sc->nsec3_iterations,
                sc->nsec3_salt?sc->nsec3_salt:"(null)");
        }

        /* Keys */
        keylist_log(sc->keys, name);

        free((void*)resign);
        free((void*)refresh);
        free((void*)validity);
        free((void*)denial);
        free((void*)jitter);
        free((void*)offset);
        free((void*)dnskeyttl);
        free((void*)soattl);
        free((void*)soamin);
    }
    return;
}
