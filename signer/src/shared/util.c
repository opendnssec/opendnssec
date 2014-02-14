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
 *
 * Utility tools.
 */

#include "config.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/util.h"

#include <fcntl.h>
#include <ldns/ldns.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char* util_str = "util";


/**
 * Check if a RR is a DNSSEC RR (RRSIG, NSEC, NSEC3 or NSEC3PARAMS).
 *
 */
int
util_is_dnssec_rr(ldns_rr* rr)
{
    ldns_rr_type type = 0;
    if (!rr) {
        return 0;
    }
    type = ldns_rr_get_type(rr);
    return (type == LDNS_RR_TYPE_RRSIG ||
            type == LDNS_RR_TYPE_NSEC ||
            type == LDNS_RR_TYPE_NSEC3 ||
            type == LDNS_RR_TYPE_NSEC3PARAMS);
}


/**
 * Compare SERIALs.
 *
 */
int
util_serial_gt(uint32_t serial_new, uint32_t serial_old)
{
    return DNS_SERIAL_GT(serial_new, serial_old);
}


/**
 * Compare SOA RDATAs.
 *
 */
int
util_soa_compare_rdata(ldns_rr* rr1, ldns_rr* rr2)
{
    size_t i = 0;
    size_t rdata_count = SE_SOA_RDATA_MINIMUM;
    for (i = 0; i <= rdata_count; i++) {
        if (i != SE_SOA_RDATA_SERIAL &&
            ldns_rdf_compare(ldns_rr_rdf(rr1, i), ldns_rr_rdf(rr2, i)) != 0) {
                return 1;
        }
    }
    return 0;
}


/**
 * Compare SOA RRs.
 *
 */
int
util_soa_compare(ldns_rr* rr1, ldns_rr* rr2)
{
    size_t rr1_len = 0;
    size_t rr2_len = 0;
    size_t offset = 0;
    if (!rr1 || !rr2) {
        return 1;
    }
    rr1_len = ldns_rr_uncompressed_size(rr1);
    rr2_len = ldns_rr_uncompressed_size(rr2);
    if (ldns_dname_compare(ldns_rr_owner(rr1), ldns_rr_owner(rr2)) != 0) {
        return 1;
    }
    if (ldns_rr_get_class(rr1) != ldns_rr_get_class(rr2)) {
        return 1;
    }
    if (ldns_rr_get_type(rr1) != LDNS_RR_TYPE_SOA) {
        return 1;
    }
    if (ldns_rr_get_type(rr1) != ldns_rr_get_type(rr2)) {
        return 1;
    }
    if (offset > rr1_len || offset > rr2_len) {
        if (rr1_len == rr2_len) {
            return util_soa_compare_rdata(rr1, rr2);
        }
        return 1;
    }
    return util_soa_compare_rdata(rr1, rr2);
}



/**
 * Compare RRs only on RDATA.
 *
 */
ldns_status
util_dnssec_rrs_compare(ldns_rr* rr1, ldns_rr* rr2, int* cmp)
{
    ldns_status status = LDNS_STATUS_OK;
    size_t rr1_len;
    size_t rr2_len;
    ldns_buffer* rr1_buf;
    ldns_buffer* rr2_buf;

    if (!rr1 || !rr2) {
        return LDNS_STATUS_ERR;
    }
    rr1_len = ldns_rr_uncompressed_size(rr1);
    rr2_len = ldns_rr_uncompressed_size(rr2);
    rr1_buf = ldns_buffer_new(rr1_len);
    rr2_buf = ldns_buffer_new(rr2_len);
    /* name, class and type should already be equal */
    status = ldns_rr2buffer_wire_canonical(rr1_buf, rr1, LDNS_SECTION_ANY);
    if (status != LDNS_STATUS_OK) {
        ldns_buffer_free(rr1_buf);
        ldns_buffer_free(rr2_buf);
        /* critical */
        return status;
    }
    status = ldns_rr2buffer_wire_canonical(rr2_buf, rr2, LDNS_SECTION_ANY);
    if (status != LDNS_STATUS_OK) {
        ldns_buffer_free(rr1_buf);
        ldns_buffer_free(rr2_buf);
        /* critical */
        return status;
    }
    *cmp = ldns_rr_compare_wire(rr1_buf, rr2_buf);
    ldns_buffer_free(rr1_buf);
    ldns_buffer_free(rr2_buf);
    return LDNS_STATUS_OK;
}


/**
 * A more efficient ldns_dnssec_rrs_add_rr(), get rid of ldns_rr_compare().
 *
 */
ldns_status
util_dnssec_rrs_add_rr(ldns_dnssec_rrs *rrs, ldns_rr *rr)
{
    int cmp = 0;
    ldns_dnssec_rrs *new_rrs = NULL;
    ldns_status status = LDNS_STATUS_OK;
    uint32_t rr_ttl = 0;
    uint32_t default_ttl = 0;

    if (!rrs || !rrs->rr || !rr) {
        return LDNS_STATUS_ERR;
    }

    rr_ttl = ldns_rr_ttl(rr);
    status = util_dnssec_rrs_compare(rrs->rr, rr, &cmp);
    if (status != LDNS_STATUS_OK) {
        /* critical */
        return status;
    }

    if (cmp < 0) {
        if (rrs->next) {
            return util_dnssec_rrs_add_rr(rrs->next, rr);
        } else {
            new_rrs = ldns_dnssec_rrs_new();
            new_rrs->rr = rr;
            rrs->next = new_rrs;
            default_ttl = ldns_rr_ttl(rrs->rr);
            if (rr_ttl < default_ttl) {
                ldns_rr_set_ttl(rrs->rr, rr_ttl);
            } else {
                ldns_rr_set_ttl(new_rrs->rr, default_ttl);
            }
            return LDNS_STATUS_OK;
        }
    } else if (cmp > 0) {
        /* put the current old rr in the new next, put the new
           rr in the current container */
        new_rrs = ldns_dnssec_rrs_new();
        new_rrs->rr = rrs->rr;
        new_rrs->next = rrs->next;

        rrs->rr = rr;
        rrs->next = new_rrs;

        default_ttl = ldns_rr_ttl(new_rrs->rr);
        if (rr_ttl < default_ttl) {
            ldns_rr_set_ttl(new_rrs->rr, rr_ttl);
        } else {
            ldns_rr_set_ttl(rrs->rr, default_ttl);
        }

        return LDNS_STATUS_OK;
    } else {
        /* should we error on equal? or free memory of rr */
        ods_log_warning("[%s] adding duplicate RR?", util_str);
        return LDNS_STATUS_NO_DATA;
    }
    return LDNS_STATUS_OK;
}


/**
 * Read process id from file.
 *
 */
static pid_t
util_read_pidfile(const char* file)
{
    int fd;
    pid_t pid;
    char pidbuf[32];
    char *t;
    int l;

    if ((fd = open(file, O_RDONLY)) == -1) {
        return -1;
    }
    if (((l = read(fd, pidbuf, sizeof(pidbuf)))) == -1) {
        close(fd);
        return -1;
    }
    close(fd);
    /* Empty pidfile means no pidfile... */
    if (l == 0) {
        errno = ENOENT;
        return -1;
    }
    pid = (pid_t) strtol(pidbuf, &t, 10);

    if (*t && *t != '\n') {
        return -1;
    }
    return pid;
}


/**
 * Check process id file.
 *
 */
int
util_check_pidfile(const char* pidfile)
{
    pid_t oldpid;
    struct stat stat_ret;
    /**
     * If the file exists then either we didn't shutdown cleanly or
     * a signer daemon is already running: in either case shutdown.
     */
    if (stat(pidfile, &stat_ret) != 0) {
        if (errno != ENOENT) {
            ods_log_error("[%s] cannot stat pidfile %s: %s", util_str, pidfile,
                strerror(errno));
        } /* else: file does not exist: carry on */
    } else {
          if (S_ISREG(stat_ret.st_mode)) {
            /** The pidfile exists already */
            if ((oldpid = util_read_pidfile(pidfile)) == -1) {
                /** Consider stale pidfile */
                if (errno != ENOENT) {
                    ods_log_error("[%s] cannot read pidfile %s: %s", util_str,
                        pidfile, strerror(errno));
                }
            } else {
                if (kill(oldpid, 0) == 0 || errno == EPERM) {
                    ods_log_crit("[%s] pidfile %s already exists, "
                        "a process with pid %u is already running. "
                        "If no ods-signerd process is running, a previous "
                        "instance didn't shutdown cleanly, please remove this "
                        "file and try again.", util_str, pidfile, oldpid);
                    return 0;
                } else {
                    /** Consider state pidfile */
                    ods_log_warning("[%s] pidfile %s already exists, "
                        "but no process with pid %u is running. "
                        "A previous instance didn't shutdown cleanly, this "
                        "pidfile is stale.", util_str, pidfile, oldpid);
                }
            }
        }
    }
    /** All good, carry on */
    return 1;
}


/**
 * Write process id to file.
 *
 */
int
util_write_pidfile(const char* pidfile, pid_t pid)
{
    FILE* fd;
    char pidbuf[32];
    size_t result = 0, size = 0;

    ods_log_assert(pidfile);
    ods_log_assert(pid);

    ods_log_debug("[%s] writing pid %lu to pidfile %s", util_str,
        (unsigned long) pid, pidfile);
    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) pid);
    fd = ods_fopen(pidfile, NULL, "w");
    if (!fd) {
        return -1;
    }
    size = strlen(pidbuf);
    if (size == 0) {
        result = 1;
    } else {
        result = fwrite((const void*) pidbuf, 1, size, fd);
    }
    if (result == 0) {
        ods_log_error("[%s] write to pidfile %s failed: %s", util_str,
            pidfile, strerror(errno));
    } else if (result < size) {
        ods_log_error("[%s] short write to pidfile %s: disk full?", util_str,
            pidfile);
        result = 0;
    } else {
        result = 1;
    }
    ods_fclose(fd);
    if (!result) {
        return -1;
    }
    return 0;
}


/**
 * Print an LDNS RR, check status.
 *
 */
ods_status
util_rr_print(FILE* fd, const ldns_rr* rr)
{
    char* result = NULL;
    ldns_buffer* tmp_buffer = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!fd || !rr) {
        return ODS_STATUS_ASSERT_ERR;
    }

    tmp_buffer = ldns_buffer_new(LDNS_MAX_PACKETLEN);
    if (!tmp_buffer) {
            return ODS_STATUS_MALLOC_ERR;
    }
    if (ldns_rr2buffer_str_fmt(tmp_buffer, NULL, rr)
                    == LDNS_STATUS_OK) {
            /* export and return string, destroy rest */
            result = ldns_buffer2str(tmp_buffer);
            if (result) {
                fprintf(fd, "%s", result);
                status = ODS_STATUS_OK;
                LDNS_FREE(result);
            } else {
                fprintf(fd, "; Unable to convert rr to string\n");
                status = ODS_STATUS_FWRITE_ERR;
            }
    } else {
            status = ODS_STATUS_FWRITE_ERR;
    }
    ldns_buffer_free(tmp_buffer);
    return status;
}

/**
 * Calculates the size needed to store the result of b64_pton.
 *
 */
size_t
util_b64_pton_calculate_size(size_t srcsize)
{
    return (((((srcsize + 3) / 4) * 3)) + 1);
}

