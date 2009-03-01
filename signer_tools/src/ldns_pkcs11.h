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
char *ldns_keystr2id(const char *key_id_str, int *key_id_len);


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
                                    const char *key_id,
                                    size_t key_id_len);

ldns_rr_list *ldns_pkcs11_sign_rrset(ldns_rr_list *rrset,
                                     ldns_key_list *keys);
