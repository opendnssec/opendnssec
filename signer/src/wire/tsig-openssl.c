/*
 * Copyright (c) 2011-2018 NLNet Labs.
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

/**
 * Interface to OpenSSL for TSIG support.
 *
 */

#include "config.h"

#ifdef HAVE_SSL
#include "log.h"
#include "wire/tsig.h"
#include "wire/tsig-openssl.h"

static const char* tsig_str = "tsig-ssl";
/** helper funcgtions */
static void *create_context();
static void init_context(void *context,
                         tsig_algo_type *algorithm,
                         tsig_key_type *key);
static void update(void *context, const void *data, size_t size);
static void final(void *context, uint8_t *digest, size_t *size);

typedef struct tsig_cleanup_table_struct tsig_cleanup_table_type;
struct tsig_cleanup_table_struct {
    tsig_cleanup_table_type* next;
    void* cleanup;
};
static tsig_cleanup_table_type* tsig_cleanup_table = NULL;


/**
 * Initiallize algorithm.
 *
 */
static int
tsig_openssl_init_algorithm(const char* digest, const char* name, const char* wireformat)
{
    tsig_algo_type* algorithm = NULL;
    const EVP_MD *hmac_algorithm = NULL;
    ods_log_assert(digest);
    ods_log_assert(name);
    ods_log_assert(wireformat);
    hmac_algorithm = EVP_get_digestbyname(digest);
    if (!hmac_algorithm) {
        ods_log_error("[%s] %s digest not available", tsig_str, digest);
        return 0;
    }
    CHECKALLOC(algorithm = (tsig_algo_type *) malloc(sizeof(tsig_algo_type)));
    algorithm->txt_name = name;
    algorithm->wf_name = ldns_dname_new_frm_str(wireformat);
    if (!algorithm->wf_name) {
        ods_log_error("[%s] unable to parse %s algorithm", tsig_str,
            wireformat);
	free(algorithm);
        return 0;
    }
    algorithm->max_digest_size = EVP_MAX_MD_SIZE;
    algorithm->data = hmac_algorithm;
    algorithm->hmac_create = create_context;
    algorithm->hmac_init = init_context;
    algorithm->hmac_update = update;
    algorithm->hmac_final = final;
    tsig_handler_add_algo(algorithm);
    return 1;
}


/**
 * Initialize OpenSSL support for TSIG.
 *
 */
ods_status
tsig_handler_openssl_init()
{
    tsig_cleanup_table = NULL;
    OpenSSL_add_all_digests();
    ods_log_debug("[%s] add md5", tsig_str);
    if (!tsig_openssl_init_algorithm("md5", "hmac-md5",
        "hmac-md5.sig-alg.reg.int.")) {
        return ODS_STATUS_ERR;
    }
#ifdef HAVE_EVP_SHA1
    ods_log_debug("[%s] add sha1", tsig_str);
    if (!tsig_openssl_init_algorithm("sha1", "hmac-sha1",
        "hmac-sha1.")) {
        return ODS_STATUS_ERR;
    }
#endif /* HAVE_EVP_SHA1 */

#ifdef HAVE_EVP_SHA256
    ods_log_debug("[%s] add sha256", tsig_str);
    if (!tsig_openssl_init_algorithm("sha256", "hmac-sha256",
        "hmac-sha256.")) {
        return ODS_STATUS_ERR;
    }
#endif /* HAVE_EVP_SHA256 */
    return ODS_STATUS_OK;
}

static void
cleanup_context(void *data)
{
    HMAC_CTX* context = (HMAC_CTX*) data;
#ifdef HAVE_SSL_NEW_HMAC
    HMAC_CTX_free(context);
#else
    HMAC_CTX_cleanup(context);
#endif
}

static void
context_add_cleanup(void* context)
{
    tsig_cleanup_table_type* entry = NULL;
    if (!context) {
        return;
    }
    CHECKALLOC(entry = (tsig_cleanup_table_type *) malloc(sizeof(tsig_cleanup_table_type)));
    entry->cleanup = context;
    entry->next = tsig_cleanup_table;
    tsig_cleanup_table = entry;
}

static void*
create_context()
{
    HMAC_CTX* context;
#ifdef HAVE_SSL_NEW_HMAC
    CHECKALLOC(context = HMAC_CTX_new());
    HMAC_CTX_reset(context);
#else
    CHECKALLOC(context = (HMAC_CTX*) malloc(sizeof(HMAC_CTX)));
    HMAC_CTX_init(context);
#endif
    context_add_cleanup(context);
    return context;
}

static void
init_context(void* context, tsig_algo_type *algorithm, tsig_key_type *key)
{
    HMAC_CTX* ctx = (HMAC_CTX*) context;
    const EVP_MD* md = (const EVP_MD*) algorithm->data;
    HMAC_Init_ex(ctx, key->data, key->size, md, NULL);
}

static void
update(void* context, const void* data, size_t size)
{
    HMAC_CTX* ctx = (HMAC_CTX*) context;
    HMAC_Update(ctx, (unsigned char*) data, (int) size);
}

static void
final(void* context, uint8_t* digest, size_t* size)
{
    HMAC_CTX* ctx = (HMAC_CTX*) context;
    unsigned len = (unsigned) *size;
    HMAC_Final(ctx, digest, &len);
    *size = (size_t) len;
}


/**
 * Finalize OpenSSL support for TSIG.
 *
 */
void
tsig_handler_openssl_finalize(void)
{
    tsig_cleanup_table_type* entry = tsig_cleanup_table;

    while (entry) {
        cleanup_context(entry->cleanup);
        entry = entry->next;
    }
    EVP_cleanup();
}

#endif /* HAVE_SSL */
