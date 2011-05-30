/*
 * $Id: addns.c -1   $
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
 * File Adapters.
 *
 */

#include "config.h"
#include "adapter/adapi.h"
#include "adapter/addns.h"
#include "adapter/adutil.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/zone.h"

#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>

static const char* adapter_str = "adapter";


/**
 * Initialize DNS adapters.
 *
 */
ods_status
addns_init(const char* str)
{
    ods_log_assert(str);
    ods_log_info("[%s] I am going to initialize the DNS adapter, using %s",
        adapter_str, str);
    return ODS_STATUS_OK;
}


/**
 * Read the next RR from zone file.
 *
 */
static ldns_rr*
addns_read_rr(FILE* fd, char* line, ldns_rdf** orig,
    ldns_rdf** prev, uint32_t* ttl, ldns_status* status, unsigned int* l)
{
    ldns_rr* rr = NULL;
    int len = 0;
    uint32_t new_ttl = 0;

addns_read_line:
    if (ttl) {
        new_ttl = *ttl;
    }

    len = adutil_readline_frm_file(fd, line, l);
    adutil_rtrim_line(line, &len);

    if (len >= 0) {
        switch (line[0]) {
            /* directives not allowed */

            /* comments, empty lines */
            case ';':
            case '\n':
                goto addns_read_line; /* perhaps next line is rr */
                break;
            /* let's hope its a RR */
            default:
                if (adutil_whitespace_line(line, len)) {
                    goto addns_read_line; /* perhaps next line is rr */
                    break;
                }

                *status = ldns_rr_new_frm_str(&rr, line, new_ttl, *orig, prev);
                if (*status == LDNS_STATUS_OK) {
                    ldns_rr2canonical(rr); /* TODO: canonicalize or not? */
                    return rr;
                } else if (*status == LDNS_STATUS_SYNTAX_EMPTY) {
                    if (rr) {
                        ldns_rr_free(rr);
                        rr = NULL;
                    }
                    *status = LDNS_STATUS_OK;
                    goto addns_read_line; /* perhaps next line is rr */
                    break;
                } else {
                    ods_log_error("[%s] error parsing rr at line %i (%s): %s",
                        adapter_str, l&&*l?*l:0,
                        ldns_get_errorstr_by_id(*status), line);
                    while (len >= 0) {
                        len = adutil_readline_frm_file(fd, line, l);
                    }
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
 * Read IXFR from file.
 *
 */
static ods_status
addns_read_ixfr(FILE* fd, zone_type* zone)
{
    ldns_rr* soa = NULL;
    ldns_rr* rr = NULL;
    uint32_t tmp_serial = 0;
    uint32_t old_serial = 0;
    uint32_t new_serial = 0;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    ldns_rdf* dname = NULL;
    uint32_t ttl = 0;
    size_t rr_count = 0;
    size_t soa_count = 0;
    int is_axfr = 0;
    int del_rr = 0;
    ods_status result = ODS_STATUS_OK;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    unsigned int line_update_interval = 100000;
    unsigned int line_update = line_update_interval;
    unsigned int l = 0;

    ods_log_assert(fd);
    ods_log_assert(zone);

    /* zone name */
    dname = adapi_get_origin(zone);
    if (!dname) {
        ods_log_error("[%s] error getting default value for $ORIGIN",
            adapter_str);
        return ODS_STATUS_ERR;
    }

    /* first SOA RR */
    old_serial = adapi_get_serial(zone);
    soa = adutil_lookup_soa_rr(fd);
    if (soa) {
        new_serial =
            ldns_rdf2native_int32(ldns_rr_rdf(soa, SE_SOA_RDATA_SERIAL));
    } else {
        ods_log_error("[%s] error reading soa rr from xfr", adapter_str);
        return ODS_STATUS_ERR;
    }

    if (ldns_dname_compare(ldns_rr_owner(soa), dname) != 0) {
        ods_log_error("[%s] dname soa rr not equal to zone dname",
            adapter_str);
        ldns_rr_free(soa);
        return ODS_STATUS_ERR;
    }
    if (adapi_get_class(zone) != ldns_rr_get_class(soa)) {
        ods_log_error("[%s] class soa rr not equal to zone class",
            adapter_str);
        ldns_rr_free(soa);
        return ODS_STATUS_ERR;
    }

    /* SOA SERIAL */
    if (!DNS_SERIAL_GT(new_serial, old_serial)) {
        ods_log_error("[%s] xfr serial %u is not incrementing current "
            "inbound serial %u", adapter_str, new_serial, old_serial);
        ldns_rr_free(soa);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_info("[%s] zone xfr from serial %u to serial %u",
        adapter_str, old_serial, new_serial);

    /* $ORIGIN <zone name> */
    orig = ldns_rdf_clone(dname);
    if (!orig) {
        ods_log_error("[%s] unable to read xfr: error setting default value "
            "for $ORIGIN", adapter_str);
        return ODS_STATUS_ERR;
    }

    /* $TTL <default ttl> */
    ttl = adapi_get_ttl(zone);

    /* read RRs */
    while ((rr = addns_read_rr(fd, line, &orig, &prev, &ttl,
        &status, &l)) != NULL) {

        if (status != LDNS_STATUS_OK) {
            ods_log_error("[%s] unable to read xfr: error reading rr at "
                "line %i (%s): %s", adapter_str, l,
                ldns_get_errorstr_by_id(status), line);
            result = ODS_STATUS_ERR;
            break;
        }

        /* IXFR or AXFR? */
        if (rr_count == 0) {
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
                is_axfr = 1;
/*
            } else {
                tmp_serial =
                    ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
                if (tmp_serial == new_serial) {
                    is_axfr = 1;
                }
*/
            }
        }
        rr_count++;

        if (l > line_update) {
            ods_log_debug("[%s] ...at line %i: %s", adapter_str, l, line);
            line_update += line_update_interval;
        }

        /* filter out DNSSEC RRs (except DNSKEY) from the Input File Adapter */
        if (util_is_dnssec_rr(rr)) {
            ldns_rr_free(rr);
            rr = NULL;
            continue;
        }
        /* ignore pseudo RRs */
        if(ldns_rr_get_type(rr) == LDNS_RR_TYPE_TSIG ||
           ldns_rr_get_type(rr) == LDNS_RR_TYPE_OPT) {
            ldns_rr_free(rr);
            rr = NULL;
            continue;
        }

        /* if SOA, switch */
        if (!is_axfr && ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
            tmp_serial =
                ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
            if (rr_count == 1 && tmp_serial != old_serial) {
                ods_log_error("[%s] unable to read ixfr: rr #%u: "
                    "soa serial mismatch", adapter_str, rr_count);
                result = ODS_STATUS_ERR;
                break;
            }
            if (rr_count > 1 && tmp_serial < old_serial) {
                ods_log_error("[%s] unable to read ixfr: rr #%u: "
                    "soa serial mismatch", adapter_str, rr_count);
                result = ODS_STATUS_ERR;
                break;
            }

            del_rr = !del_rr;
            soa_count++;

            if (rr_count > 1) {
                ldns_rr_free(rr);
                rr = NULL;
            }
            continue;
        }

        /* add to the zonedata */
        if (del_rr) {
            result = adapi_del_rr(zone, rr);
        } else {
            result = adapi_add_rr(zone, rr);
        }
        if (result != ODS_STATUS_OK) {
            ods_log_error("[%s] error %s rr at line %i: %s",
                adapter_str, del_rr?"deleting":"adding", l, line);
            break;
        }
    }

    /* add the final SOA RR... */
    if (!is_axfr) {
        if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
            ods_log_error("[%s] unable to read ixfr: missing final soa rr",
                adapter_str);
            result = ODS_STATUS_ERR;
        } else {
            result = adapi_add_rr(zone, soa);
            if (result != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to read ixfr: error adding final "
                    "soa rr", adapter_str);
            }
        }
    }

    /* and done */
    if (orig) {
        ldns_rdf_deep_free(orig);
        orig = NULL;
    }
    if (prev) {
        ldns_rdf_deep_free(prev);
        prev = NULL;
    }

    if (result == ODS_STATUS_OK && status != LDNS_STATUS_OK) {
        ods_log_error("[%s] error reading rr at line %i (%s): %s",
            adapter_str, l, ldns_get_errorstr_by_id(status), line);
        result = ODS_STATUS_ERR;
    }
    if (result != ODS_STATUS_OK) {
        return result;
    }

    /* [start] transaction */
    if (is_axfr) {
        result = adapi_trans_full(zone);
    } else {
        result = adapi_trans_diff(zone);
    }
    if (result != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read xfr: start transaction failed",
            adapter_str);
        return result;
    }
    /* [end] transaction */

    /* [start] validate updates */
    result = zone_examine(zone);
    if (result != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read xfr: zone contains errors",
            adapter_str);
        return result;
    }
    /* [end] validate updates */

    adapi_set_serial(zone, new_serial);
    return ODS_STATUS_OK;
}


/**
 * Read zone from DNS Input Adapter.
 *
 */
ods_status
addns_read(struct zone_struct* zone, const char* str)
{
    FILE* fd = NULL;
    zone_type* adzone = (zone_type*) zone;
    ods_status status = ODS_STATUS_OK;

    /* [start] sanity parameter checking */
    if (!adzone) {
        ods_log_error("[%s] unable to read xfr: no zone (or no name given)",
            adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone);
    if (!str) {
        ods_log_error("[%s] unable to read xfr: no configstr given",
            adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(str);
    /* [end] sanity parameter checking */

    /* [start] read zone */
    fd = ods_fopen(str, NULL, "r");
    if (!fd) {
        ods_log_error("[%s] unable to read xfr: fopen failed", adapter_str);
        return ODS_STATUS_FOPEN_ERR;
    }
    status = addns_read_ixfr(fd, zone);
    ods_fclose(fd);
    fd = NULL;
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read xfr: %s", adapter_str,
            ods_status2str(status));
        return status;
    }
    /* [end] read zone */

    return ODS_STATUS_OK;
}


/**
 * Write to DNS Output Adapter.
 *
 */
ods_status
addns_write(struct zone_struct* zone, const char* str)
{
    FILE* fd = NULL;
    zone_type* adzone = (zone_type*) zone;
    ods_status status = ODS_STATUS_OK;

    /* [start] sanity parameter checking */
    if (!adzone) {
        ods_log_error("[%s] unable to write xfr: no zone (or no "
            "name given)", adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone);
    if (!str) {
        ods_log_error("[%s] unable to write xfr: no filename given",
            adapter_str);
        return ODS_STATUS_ERR;
    }
    ods_log_assert(str);
    /* [end] sanity parameter checking */

    /* [start] write zone */
    fd = ods_fopen(str, NULL, "a");
    if (fd) {
        zone_print(fd, adzone);
        ods_fclose(fd);
    } else {
        status = ODS_STATUS_FOPEN_ERR;
    }
    /* [end] write zone */

    return status;
}
