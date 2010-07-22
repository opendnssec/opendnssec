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
#include "signer/se_key.h"
#include "signer/signconf.h"
#include "util/duration.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"

/**
 * Create a new signer configuration with the 'empty' settings.
 *
 */
signconf_type*
signconf_create(void)
{
    signconf_type* sc = (signconf_type*) se_malloc(sizeof(signconf_type));

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
 * Read a signer configuration.
 *
 */
signconf_type*
signconf_read(const char* filename, time_t last_modified)
{
    signconf_type* signconf;
    const char* rngfile = ODS_SE_RNGDIR "/signconf.rng";
    FILE* scfd = NULL;
    time_t st_mtime = 0;

    st_mtime = se_file_lastmodified(filename);
    if (st_mtime <= last_modified) {
        se_log_debug("signconf file %s is unchanged", filename);
        return NULL;
    }

    if (parse_file_check(filename, rngfile) != 0) {
        se_log_error("unable to parse signconf file %s", filename);
        return NULL;
    }

    scfd = se_fopen(filename, NULL, "r");
    if (scfd) {
        signconf = signconf_create();
        signconf->filename = se_strdup(filename);
        signconf->sig_resign_interval = parse_sc_sig_resign_interval(filename);
        signconf->sig_refresh_interval = parse_sc_sig_refresh_interval(filename);
        signconf->sig_validity_default = parse_sc_sig_validity_default(filename);
        signconf->sig_validity_denial = parse_sc_sig_validity_denial(filename);
        signconf->sig_jitter = parse_sc_sig_jitter(filename);
        signconf->sig_inception_offset = parse_sc_sig_inception_offset(filename);
        signconf->nsec_type = parse_sc_nsec_type(filename);
        if (signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
            signconf->nsec3_optout = parse_sc_nsec3_optout(filename);
            signconf->nsec3_algo = parse_sc_nsec3_algorithm(filename);
            signconf->nsec3_iterations = parse_sc_nsec3_iterations(filename);
            signconf->nsec3_salt = parse_sc_nsec3_salt(filename);
        }
        signconf->keys = parse_sc_keys(filename);
        signconf->dnskey_ttl = parse_sc_dnskey_ttl(filename);
        signconf->soa_ttl = parse_sc_soa_ttl(filename);
        signconf->soa_min = parse_sc_soa_min(filename);
        signconf->soa_serial = parse_sc_soa_serial(filename);
        signconf->audit = parse_sc_audit(filename);
        signconf->last_modified = st_mtime;

        se_fclose(scfd);
        return signconf;
    }

    se_log_error("unable to read signconf file %s", filename);
    return NULL;
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
int
signconf_check(signconf_type* sc)
{
    int ret = 0;

    if (!sc->sig_resign_interval) {
        se_log_error("signconf-check: no signature resign interval found");
        ret = 1;
    }
    if (!sc->sig_refresh_interval) {
        se_log_error("signconf-check: no signature resign interval found");
        ret = 1;
    }
    if (!sc->sig_validity_default) {
        se_log_error("signconf-check: no signature default validity found");
        ret = 1;
    }
    if (!sc->sig_validity_denial) {
        se_log_error("signconf-check: no signature denial validity found");
        ret = 1;
    }
    if (!sc->sig_jitter) {
        se_log_error("signconf-check: no signature jitter found");
        ret = 1;
    }
    if (!sc->sig_inception_offset) {
        se_log_error("signconf-check: no signature inception offset found");
        ret = 1;
    }
    if (sc->nsec_type == LDNS_RR_TYPE_NSEC3) {
        if (sc->nsec3_algo == 0) {
            se_log_error("signconf-check: no nsec3 algorithm found");
            ret = 1;
        }
        /* iterations */
        /* salt */
        /* optout */
    } else if (sc->nsec_type != LDNS_RR_TYPE_NSEC) {
        se_log_error("signconf-check: wrong nsec type %i", sc->nsec_type);
        ret = 1;
    }
    if (!sc->keys || sc->keys->count == 0) {
        se_log_error("signconf-check: no keys found");
        ret = 1;
    }
    if (!sc->dnskey_ttl) {
        se_log_error("signconf-check: no dnskey ttl found");
        ret = 1;
    }
    if (!sc->soa_ttl) {
        se_log_error("signconf-check: no soa ttl found");
        ret = 1;
    }
    if (!sc->soa_min) {
        se_log_error("signconf-check: no soa minimum found");
        ret = 1;
    }
    if (signconf_soa_serial_check(sc->soa_serial) != 0) {
        se_log_error("signconf-check: wrong soa serial type '%s'",
            sc->soa_serial);
        ret = 1;
    }

    if (!ret) {
        se_log_debug("signer configuration settings ok");
    }
    return ret;

}


#define TASK_ADDKEYS 1
#define TASK_NSECIFY 2
#define TASK_SIGN 2


/**
 * Compare two signer configurations.
 *
 */
int
signconf_compare(signconf_type* a, signconf_type* b)
{
   se_log_assert(a);
   se_log_assert(b);

   if (keylist_compare(a->keys, b->keys) != 0) {
       return TASK_ADDKEYS;
   }

   if (a->nsec_type != b->nsec_type) {
       return TASK_NSECIFY;
   } else if (a->nsec_type == LDNS_RR_TYPE_NSEC3) {
       if (strlen(a->nsec3_salt) != strlen(b->nsec3_salt)) {
           return TASK_NSECIFY;
       } else if (strncmp(a->nsec3_salt, b->nsec3_salt,
           strlen(a->nsec3_salt)) != 0) {
           return TASK_NSECIFY;
       } else if (a->nsec3_algo != b->nsec3_algo) {
           return TASK_NSECIFY;
       } else if (a->nsec3_iterations != b->nsec3_iterations) {
           return TASK_NSECIFY;
       } else if (a->nsec3_optout != b->nsec3_optout) {
           return TASK_NSECIFY;
       }
   }

   /* not like python: reschedule if resign/refresh differs */
   /* this needs review, tasks correct on signconf changes? */

   /* ok, just re-sign */
   return TASK_SIGN;
}

/**
 * Clean up signer configuration.
 *
 */
void
signconf_cleanup(signconf_type* sc)
{
    if (sc) {
        if (sc->sig_resign_interval) {
            duration_cleanup(sc->sig_resign_interval);
            sc->sig_resign_interval = NULL;
        }
        if (sc->sig_refresh_interval) {
            duration_cleanup(sc->sig_refresh_interval);
            sc->sig_refresh_interval = NULL;
        }
        if (sc->sig_validity_default) {
            duration_cleanup(sc->sig_validity_default);
            sc->sig_validity_default = NULL;
        }
        if (sc->sig_validity_denial) {
            duration_cleanup(sc->sig_validity_denial);
            sc->sig_validity_denial = NULL;
        }
        if (sc->sig_jitter) {
            duration_cleanup(sc->sig_jitter);
            sc->sig_jitter = NULL;
        }
        if (sc->sig_inception_offset) {
            duration_cleanup(sc->sig_inception_offset);
            sc->sig_inception_offset = NULL;
        }
        if (sc->dnskey_ttl) {
            duration_cleanup(sc->dnskey_ttl);
            sc->dnskey_ttl = NULL;
        }
        if (sc->soa_ttl) {
            duration_cleanup(sc->soa_ttl);
            sc->soa_ttl = NULL;
        }
        if (sc->soa_min) {
            duration_cleanup(sc->soa_min);
            sc->soa_min = NULL;
        }
        if (sc->keys) {
            keylist_cleanup(sc->keys);
            sc->keys = NULL;
        }
        if (sc->nsec3_salt) {
            se_free((void*)sc->nsec3_salt);
            sc->nsec3_salt = NULL;
        }
        if (sc->soa_serial) {
            se_free((void*)sc->soa_serial);
            sc->soa_serial = NULL;
        }
        if (sc->filename) {
            se_free((void*)sc->filename);
            sc->filename = NULL;
        }
        se_free((void*)sc);
    } else {
        se_log_warning("cleanup empty signconf");
    }
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
        fprintf(out, "\t<Zone name=\"%s\">\n", name);

        /* Signatures */
        fprintf(out, "\t\t<Signatures>\n");
        s = duration2string(sc->sig_resign_interval);
        fprintf(out, "\t\t\t<Resign>%s</Resign>\n", s);
        se_free((void*)s);

        s = duration2string(sc->sig_refresh_interval);
        fprintf(out, "\t\t\t<Refresh>%s</Refresh>\n", s);
        se_free((void*)s);

        fprintf(out, "\t\t\t<Validity>\n");

        s = duration2string(sc->sig_validity_default);
        fprintf(out, "\t\t\t\t<Default>%s</Default>\n", s);
        se_free((void*)s);

        s = duration2string(sc->sig_validity_denial);
        fprintf(out, "\t\t\t\t<Denial>%s</Denial>\n", s);
        se_free((void*)s);

        fprintf(out, "\t\t\t</Validity>\n");

        s = duration2string(sc->sig_jitter);
        fprintf(out, "\t\t\t<Jitter>%s</Jitter>\n", s);
        se_free((void*)s);

        s = duration2string(sc->sig_inception_offset);
        fprintf(out, "\t\t\t<InceptionOffset>%s</InceptionOffset>\n", s);
        se_free((void*)s);

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
            fprintf(out, "\t\t\t\t\t<Salt>%s</Salt>\n", sc->nsec3_salt);
            fprintf(out, "\t\t\t\t</Hash>\n");
            fprintf(out, "\t\t\t</NSEC3>\n");
        }
        fprintf(out, "\t\t</Denial>\n");
        fprintf(out, "\n");

        /* Keys */
        fprintf(out, "\t\t<Keys>\n");
        s = duration2string(sc->dnskey_ttl);
        fprintf(out, "\t\t\t<TTL>%s</TTL>\n", s);
        se_free((void*)s);
        fprintf(out, "\n");
        keylist_print(out, sc->keys);
        fprintf(out, "\t\t</Keys>\n");
        fprintf(out, "\n");

        /* SOA */
        fprintf(out, "\t\t<SOA>\n");
        s = duration2string(sc->soa_ttl);
        fprintf(out, "\t\t\t<TTL>%s</TTL>\n", s);
        se_free((void*)s);

        s = duration2string(sc->soa_min);
        fprintf(out, "\t\t\t<Minimum>%s</Minimum>\n", s);
        se_free((void*)s);

        fprintf(out, "\t\t\t<Serial>%s</Serial>\n", sc->soa_serial);
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
