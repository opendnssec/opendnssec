/*
 * $Id: license.txt 570 2009-05-04 08:52:38Z jakob $
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

#include "pkcs11/pkcs11_linux.h"
#include "pkcs11/pkcs11t.h"

/* we only need one function definition from pkcs11,
 * so we don't need to include f, but we need a placeholder
 * for this one */
#ifdef HAVE_PKCS11_MODULE
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);
#endif

struct ldns_pkcs11_ctx_struct {
	CK_FUNCTION_LIST_PTR function_list;
	CK_SESSION_HANDLE session;
};
typedef struct ldns_pkcs11_ctx_struct ldns_pkcs11_ctx;

struct pkcs_keypair_handle {
	ldns_pkcs11_ctx *pkcs11_ctx;
	CK_OBJECT_HANDLE private_key;
	CK_OBJECT_HANDLE public_key;
};

int ldns_keystr2algorithm(const char *key_id_str);
unsigned char *ldns_keystr2id(const char *key_id_str, int *key_id_len);


ldns_pkcs11_ctx *ldns_pkcs11_ctx_new();
void ldns_pkcs11_ctx_free(ldns_pkcs11_ctx *pkcs11_ctx);

struct pkcs_keypair_handle *pkcs_keypair_handle_new();
void pkcs_keypair_handle_free(struct pkcs_keypair_handle *pkh);

ldns_pkcs11_ctx *ldns_initialize_pkcs11(const char *dl_file,
                                        const char *token_name,
                                        const char *pin);
void ldns_finalize_pkcs11(ldns_pkcs11_ctx *pkcs11_ctx);

ldns_rr *ldns_key2rr_pkcs(ldns_pkcs11_ctx *pkcs11_ctx,
                          ldns_key *key);

ldns_status ldns_key_new_frm_pkcs11(ldns_pkcs11_ctx *pkcs11_ctx,
                                    ldns_key **key,
                                    ldns_algorithm algorithm,
                                    uint16_t flags,
                                    const unsigned char *key_id,
                                    size_t key_id_len);

ldns_rr_list *ldns_pkcs11_sign_rrset(ldns_rr_list *rrset,
                                     ldns_key_list *keys);
