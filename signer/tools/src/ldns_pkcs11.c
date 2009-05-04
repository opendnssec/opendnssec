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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <strings.h>

#include <ldns/ldns.h>

#include "config.h"
#include "ldns_pkcs11.h"

static void
xprintf_hex(FILE *out, const unsigned char *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		fprintf(out, "%02x", data[i]);
	}
	fprintf(out, "\n");
}

/*
 * Parses the null-terminated string key_id_str as hex values,
 * and returns an allocated array of the binary data the string
 * represents. *key_id_len will contain the size of that array
 */
unsigned char *
ldns_keystr2id(const char *key_id_str, int *key_id_len)
{
	unsigned char *key_id;
	/* length of the hex input */
	size_t hex_len;
	int i;
	
	hex_len = strlen(key_id_str);
	/* todo: make general hex2 function? */
	if (hex_len % 2 != 0) {
		fprintf(stderr,
		        "Error: bad hex data for key id: %s\n",
		        key_id_str);
		return NULL;
	}
	*key_id_len = hex_len / 2;
	key_id = malloc(*key_id_len);
	for (i = 0; i < *key_id_len; i++) {
		key_id[i] = ldns_hexdigit_to_int(key_id_str[2*i]) * 16 +
		            ldns_hexdigit_to_int(key_id_str[2*i+1]);
	}
	return key_id;
}

/*
 * ldns PKCS11 structure functions
 */
ldns_pkcs11_ctx *
ldns_pkcs11_ctx_new() {
	ldns_pkcs11_ctx *ctx = malloc(sizeof(ldns_pkcs11_ctx));
	ctx->function_list = NULL;
	ctx->session = 0;
	return ctx;
}

void
ldns_pkcs11_ctx_free(ldns_pkcs11_ctx *ctx) {
	if (ctx) {
		free(ctx);
	}
}

struct pkcs_keypair_handle *
pkcs_keypair_handle_new()
{
	struct pkcs_keypair_handle *pkh;
	pkh = malloc(sizeof(struct pkcs_keypair_handle));
	pkh->private_key = 0;
	pkh->public_key = 0;
	pkh->pkcs11_ctx = NULL;
	return pkh;
}

void
pkcs_keypair_handle_free(struct pkcs_keypair_handle *pkh)
{
	free(pkh);
}

/*
 * General PKCS11 helper functions
 */
static char *
ldns_pkcs11_rv_str(CK_RV rv)
{
	switch (rv)
		{
		case CKR_OK:
			return "CKR_OK";
		case CKR_CANCEL:
			return "CKR_CANCEL";
		case CKR_HOST_MEMORY:
			return "CKR_HOST_MEMORY";
		case CKR_GENERAL_ERROR:
			return "CKR_GENERAL_ERROR";
		case CKR_SLOT_ID_INVALID:
			return "CKR_SLOT_ID_INVALID";
		case CKR_ATTRIBUTE_READ_ONLY:
			return "CKR_ATTRIBUTE_READ_ONLY";
		case CKR_ATTRIBUTE_SENSITIVE:
			return "CKR_ATTRIBUTE_SENSITIVE";
		case CKR_ATTRIBUTE_TYPE_INVALID:
			return "CKR_ATTRIBUTE_TYPE_INVALID";
		case CKR_ATTRIBUTE_VALUE_INVALID:
			return "CKR_ATTRIBUTE_VALUE_INVALID";
		case CKR_DATA_INVALID:
			return "CKR_DATA_INVALID";
		case CKR_DATA_LEN_RANGE:
			return "CKR_DATA_LEN_RANGE";
		case CKR_DEVICE_ERROR:
			return "CKR_DEVICE_ERROR";
		case CKR_DEVICE_MEMORY:
			return "CKR_DEVICE_MEMORY";
		case CKR_DEVICE_REMOVED:
			return "CKR_DEVICE_REMOVED";
		case CKR_ENCRYPTED_DATA_INVALID:
			return "CKR_ENCRYPTED_DATA_INVALID";
		case CKR_ENCRYPTED_DATA_LEN_RANGE:
			return "CKR_ENCRYPTED_DATA_LEN_RANGE";
		case CKR_FUNCTION_CANCELED:
			return "CKR_FUNCTION_CANCELED";
		case CKR_FUNCTION_NOT_PARALLEL:
			return "CKR_FUNCTION_NOT_PARALLEL";
		case CKR_KEY_HANDLE_INVALID:
			return "CKR_KEY_HANDLE_INVALID";
		case CKR_KEY_SIZE_RANGE:
			return "CKR_KEY_SIZE_RANGE";
		case CKR_KEY_TYPE_INCONSISTENT:
			return "CKR_KEY_TYPE_INCONSISTENT";
		case CKR_MECHANISM_INVALID:
			return "CKR_MECHANISM_INVALID";
		case CKR_MECHANISM_PARAM_INVALID:
			return "CKR_MECHANISM_PARAM_INVALID";
		case CKR_OBJECT_HANDLE_INVALID:
			return "CKR_OBJECT_HANDLE_INVALID";
		case CKR_OPERATION_ACTIVE:
			return "CKR_OPERATION_ACTIVE";
		case CKR_OPERATION_NOT_INITIALIZED:
			return "CKR_OPERATION_NOT_INITIALIZED";
		case CKR_PIN_INCORRECT:
			return "CKR_PIN_INCORRECT";
		case CKR_PIN_INVALID:
			return "CKR_PIN_INVALID";
		case CKR_PIN_LEN_RANGE:
			return "CKR_PIN_LEN_RANGE";
		case CKR_SESSION_CLOSED:
			return "CKR_SESSION_CLOSED";
		case CKR_SESSION_COUNT:
			return "CKR_SESSION_COUNT";
		case CKR_SESSION_HANDLE_INVALID:
			return "CKR_SESSION_HANDLE_INVALID";
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
			return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		case CKR_SESSION_READ_ONLY:
			return "CKR_SESSION_READ_ONLY";
		case CKR_SESSION_EXISTS:
			return "CKR_SESSION_EXISTS";
		case CKR_SIGNATURE_INVALID:
			return "CKR_SIGNATURE_INVALID";
		case CKR_SIGNATURE_LEN_RANGE:
			return "CKR_SIGNATURE_LEN_RANGE";
		case CKR_TEMPLATE_INCOMPLETE:
			return "CKR_TEMPLATE_INCOMPLETE";
		case CKR_TEMPLATE_INCONSISTENT:
			return "CKR_TEMPLATE_INCONSISTENT";
		case CKR_TOKEN_NOT_PRESENT:
			return "CKR_TOKEN_NOT_PRESENT";
		case CKR_TOKEN_NOT_RECOGNIZED:
			return "CKR_TOKEN_NOT_RECOGNIZED";
		case CKR_TOKEN_WRITE_PROTECTED:
			return "CKR_TOKEN_WRITE_PROTECTED";
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
			return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
		case CKR_UNWRAPPING_KEY_SIZE_RANGE:
			return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
			return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_USER_ALREADY_LOGGED_IN:
			return "CKR_USER_ALREADY_LOGGED_IN";
		case CKR_USER_NOT_LOGGED_IN:
			return "CKR_USER_NOT_LOGGED_IN";
		case CKR_USER_PIN_NOT_INITIALIZED:
			return "CKR_USER_PIN_NOT_INITIALIZED";
		case CKR_USER_TYPE_INVALID:
			return "CKR_USER_TYPE_INVALID";
		case CKR_WRAPPED_KEY_INVALID:
			return "CKR_WRAPPED_KEY_INVALID";
		case CKR_WRAPPED_KEY_LEN_RANGE:
			return "CKR_WRAPPED_KEY_LEN_RANGE";
		case CKR_WRAPPING_KEY_HANDLE_INVALID:
			return "CKR_WRAPPING_KEY_HANDLE_INVALID";
		case CKR_WRAPPING_KEY_SIZE_RANGE:
			return "CKR_WRAPPING_KEY_SIZE_RANGE";
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
			return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_RANDOM_SEED_NOT_SUPPORTED:
			return "CKR_RANDOM_SEED_NOT_SUPPORTED";
		case CKR_VENDOR_DEFINED:
			return "CKR_VENDOR_DEFINED";
		case CKR_BUFFER_TOO_SMALL:
			return "CKR_BUFFER_TOO_SMALL";
		case CKR_SAVED_STATE_INVALID:
			return "CKR_SAVED_STATE_INVALID";
		case CKR_INFORMATION_SENSITIVE:
			return "CKR_INFORMATION_SENSITIVE";
		case CKR_STATE_UNSAVEABLE:
			return "CKR_STATE_UNSAVEABLE";
		case CKR_CRYPTOKI_NOT_INITIALIZED:
			return "CKR_CRYPTOKI_NOT_INITIALIZED";
		case CKR_CRYPTOKI_ALREADY_INITIALIZED:
			return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		case CKR_MUTEX_BAD:
			return "CKR_MUTEX_BAD";
		case CKR_MUTEX_NOT_LOCKED:
			return "CKR_MUTEX_NOT_LOCKED";
		default:
			return "Unknown error";
		}
}

static void
ldns_pkcs11_check_rv(CK_RV rv, const char *message)
{
	if (rv != CKR_OK) {
		fprintf(stderr,
		        "Error: %s (%s)\n",
		        message,
		        ldns_pkcs11_rv_str(rv));
		exit(EXIT_FAILURE);
	}
}

static CK_RV
ldns_pkcs11_load_functions(CK_FUNCTION_LIST_PTR_PTR pkcs11_functions,
                           const char *dl_file)
{
	CK_C_GetFunctionList pGetFunctionList = NULL;

	if (dl_file) {
		/* library provided by application or user */
#if defined(HAVE_LOADLIBRARY)
		// Load PKCS #11 library
		HINSTANCE hDLL = LoadLibrary(_T(dl_file));

		if (hDLL == NULL)
		{
			// Failed to load the PKCS #11 library
			return CKR_FUNCTION_FAILED;
		}

		// Retrieve the entry point for C_GetFunctionList
		pGetFunctionList = (CK_C_GetFunctionList)
			GetProcAddress(hDLL, _T("C_GetFunctionList"));
#elif defined(HAVE_DLOPEN)
		// Load PKCS #11 library
		void* pDynLib = dlopen(dl_file, RTLD_LAZY);

		if (pDynLib == NULL)
		{
			// Failed to load the PKCS #11 library
			fprintf(stderr, "dlopen() failed: %s\n", dlerror());
			return CKR_FUNCTION_FAILED;
		}

		// Retrieve the entry point for C_GetFunctionList
		pGetFunctionList = (CK_C_GetFunctionList)
			dlsym(pDynLib, "C_GetFunctionList");
#endif
	} else {
		/* no library provided, use the statically compiled softHSM */
#ifdef HAVE_PKCS11_MODULE
		return C_GetFunctionList(pkcs11_functions);
#else 
		fprintf(stderr, "Error, no pkcs11 module given, none compiled in\n");
#endif
	}

	if (pGetFunctionList == NULL)
	{
		// Failed to load the PKCS #11 library
		return CKR_FUNCTION_FAILED;
	}

	// Retrieve the function list
	(pGetFunctionList)(pkcs11_functions);

	return CKR_OK;
}

static int
ldns_pkcs11_check_token_name(CK_FUNCTION_LIST_PTR pkcs11_functions,
                             CK_SLOT_ID slotId,
                             const char *token_name)
{
	/* token label is always 32 bytes */
	char *token_name_bytes = malloc(32);
	int result = 0;
	CK_RV rv;
	CK_TOKEN_INFO token_info;
	
	rv = pkcs11_functions->C_GetTokenInfo(slotId, &token_info);
	ldns_pkcs11_check_rv(rv, "C_GetTokenInfo");
	
	memset(token_name_bytes, ' ', 32);
	memcpy(token_name_bytes, token_name, strlen(token_name));
	
	result = memcmp(token_info.label, token_name_bytes, 32) == 0;
	
	free(token_name_bytes);
	return result;
}

static CK_SLOT_ID
ldns_pkcs11_get_slot_id(CK_FUNCTION_LIST_PTR pkcs11_functions,
                        const char *token_name)
{
	CK_RV rv;
	CK_SLOT_ID slotId = 0;
	CK_ULONG slotCount = 10;
	CK_SLOT_ID cur_slot;
	CK_SLOT_ID *slotIds = malloc(sizeof(CK_SLOT_ID) * slotCount);
	int found = 0;
	
	rv = pkcs11_functions->C_GetSlotList(CK_TRUE, slotIds, &slotCount);
	ldns_pkcs11_check_rv(rv, "get slot list");

	if (slotCount < 1) {
		fprintf(stderr, "Error; could not find token with the name %s\n", token_name);
		exit(1);
	}

	for (cur_slot = 0; cur_slot < slotCount; cur_slot++) {
		if (ldns_pkcs11_check_token_name(pkcs11_functions,
		                                 slotIds[cur_slot],
		                                 token_name)) {
			slotId = slotIds[cur_slot];
			found = 1;
			break;
		}
	}
	free(slotIds);
	if (!found) {
		fprintf(stderr, "Error; could not find token with the name %s\n", token_name);
		exit(1);
	}

	return slotId;
}

static CK_SESSION_HANDLE
ldns_pkcs11_start_session(CK_FUNCTION_LIST_PTR pkcs11_functions,
                          CK_SLOT_ID slotId)
{
	CK_RV rv;
	CK_SESSION_HANDLE session;
	rv = pkcs11_functions->C_OpenSession(slotId,
	                                     CKF_SERIAL_SESSION,
	                                     NULL,
	                                     NULL,
	                                     &session);
	ldns_pkcs11_check_rv(rv, "open session");
	return session;
}

static void
ldns_pkcs11_login(CK_FUNCTION_LIST_PTR pkcs11_functions,
                  CK_SESSION_HANDLE session,
                  CK_BYTE *pin)
{
	CK_RV rv;
	if (pin) {
		rv = pkcs11_functions->C_Login(session,
		                               CKU_USER,
		                               pin,
		                               strlen((char *)pin));
		ldns_pkcs11_check_rv(rv, "log in");
		/*fprintf(stderr, "Logged in\n");*/
	} else {
		fprintf(stderr, "No pin\n");
		exit(3);
	}
}

ldns_pkcs11_ctx *
ldns_initialize_pkcs11(const char *dl_file,
                       const char *token_name,
                       const char *pin)
{
	CK_FUNCTION_LIST_PTR function_list;
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	
	ldns_pkcs11_ctx *pkcs11_ctx;

	pkcs11_ctx = ldns_pkcs11_ctx_new();
	if (!pkcs11_ctx) {
		fprintf(stderr, "Memory error creating pkcs11 context\n");
		return NULL;
	}
	
	if (ldns_pkcs11_load_functions(&function_list, dl_file) == CKR_OK) {
		function_list->C_Initialize(NULL);
		
		pkcs11_ctx->function_list = function_list;
		
		slot_id = ldns_pkcs11_get_slot_id(function_list, token_name);
		
		session = ldns_pkcs11_start_session(function_list, slot_id);
		
		pkcs11_ctx->session = session;
		
		ldns_pkcs11_login(function_list, session, (CK_BYTE_PTR) pin);
		return pkcs11_ctx;
	} else {
		fprintf(stderr, "Unable to load function_list\n");
		ldns_pkcs11_ctx_free(pkcs11_ctx);
		return NULL;
	}
}

void
ldns_finalize_pkcs11(ldns_pkcs11_ctx *pkcs11_ctx)
{
	CK_RV rv;
	if (!pkcs11_ctx || ! pkcs11_ctx->function_list) {
		return;
	}
	rv = pkcs11_ctx->function_list->C_Logout(pkcs11_ctx->session);
	rv = pkcs11_ctx->function_list->C_CloseSession(pkcs11_ctx->session);
	pkcs11_ctx->function_list->C_Finalize(NULL);

	ldns_pkcs11_ctx_free(pkcs11_ctx);
}

static CK_OBJECT_HANDLE
ldns_pkcs11_get_key(CK_FUNCTION_LIST_PTR pkcs11_functions,
        CK_SESSION_HANDLE session,
        CK_OBJECT_CLASS key_class,
        CK_BYTE *id,
        size_t id_len)
{
	CK_RV rv;
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_ID, id, id_len }
	};
	CK_ULONG objectCount;
	CK_OBJECT_HANDLE object;

	rv = pkcs11_functions->C_FindObjectsInit(session, template, 2);
	ldns_pkcs11_check_rv(rv, "Find objects init");
	
	rv = pkcs11_functions->C_FindObjects(session,
	                                     &object,
	                                     1,
	                                     &objectCount);
	ldns_pkcs11_check_rv(rv, "Find first object");

	rv = pkcs11_functions->C_FindObjectsFinal(session);
	if (objectCount > 0) {
		ldns_pkcs11_check_rv(rv, "Find objects final");
		return object;
	} else {
		return 0;
	}
}

static ldns_rdf *
ldns_key_pkcs11_rsa2rdf(ldns_pkcs11_ctx *pkcs11_ctx,
                        CK_OBJECT_HANDLE key_object)
{
	CK_RV rv;
	CK_BYTE_PTR public_exponent = NULL;
	CK_ULONG public_exponent_len = 0;
	CK_BYTE_PTR modulus = NULL;
	CK_ULONG modulus_len = 0;
	unsigned char *data = NULL;
	size_t data_size = 0;
	
	CK_ATTRIBUTE template[] = {
		{CKA_PUBLIC_EXPONENT, NULL, 0},
		{CKA_MODULUS, NULL, 0},
	};
	ldns_rdf *rdf;

	if (!pkcs11_ctx || ! pkcs11_ctx->function_list) {
		return NULL;
	}

	rv = pkcs11_ctx->function_list->C_GetAttributeValue(
	                                  pkcs11_ctx->session,
	                                  key_object,
	                                  template,
	                                  2);
	
	public_exponent_len = template[0].ulValueLen;
	modulus_len = template[1].ulValueLen;

	public_exponent = template[0].pValue = malloc(public_exponent_len);
	if (!public_exponent) {
		fprintf(stderr,
		        "Error allocating memory for public exponent\n");
		return NULL;
	}

	modulus = template[1].pValue = malloc(modulus_len);
	if (!modulus) {
		fprintf(stderr, "Error allocating memory for modulus\n");
		free(public_exponent);
		return NULL;
	}
	
	rv = pkcs11_ctx->function_list->C_GetAttributeValue(
	                                  pkcs11_ctx->session,
	                                  key_object,
	                                  template,
	                                  2);
	ldns_pkcs11_check_rv(rv, "get attribute value");

	data_size = public_exponent_len + modulus_len + 1;
	if (public_exponent_len <= 256) {
		data = malloc(data_size);
		if (!data) {
			fprintf(stderr,
			        "Error allocating memory for pub key rr data\n");
			free(public_exponent);
			free(modulus);
			return NULL;
		}
		data[0] = public_exponent_len;
		memcpy(&data[1], public_exponent, public_exponent_len);
		memcpy(&data[1 + public_exponent_len], modulus, modulus_len);
	} else if (public_exponent_len <= 65535) {
		data_size += 2;
		data = malloc(data_size);
		if (!data) {
			fprintf(stderr,
			        "Error allocating memory for pub key rr data\n");
			free(public_exponent);
			free(modulus);
			return NULL;
		}
		data[0] = 0;
		ldns_write_uint16(&data[1], (uint16_t) public_exponent_len); 
		memcpy(&data[3], public_exponent, public_exponent_len);
		memcpy(&data[3 + public_exponent_len], modulus, modulus_len);
	} else {
		fprintf(stderr, "error: public exponent too big\n");
		free(public_exponent);
		free(modulus);
		return NULL;
	}
	rdf = ldns_rdf_new(LDNS_RDF_TYPE_B64, data_size, data);
	free(public_exponent);
	free(modulus);

	return rdf;
}

/* performs the additional step of getting the public key part
 * from pkcs11 into an rr
 */
ldns_rr *
ldns_key2rr_pkcs(ldns_pkcs11_ctx *pkcs11_ctx,
                 ldns_key *key)
{
	ldns_rr *key_rr;
	ldns_rdf *key_data_rdf;
	struct pkcs_keypair_handle *key_handle;
	CK_OBJECT_HANDLE public_key;
	
	key_handle = (struct pkcs_keypair_handle*)ldns_key_external_key(key);
	public_key = key_handle->public_key;
	/* TODO: other algorithms */
	key_data_rdf = ldns_key_pkcs11_rsa2rdf(pkcs11_ctx,
	                                       public_key);
	key_rr = ldns_key2rr(key);
	ldns_rr_push_rdf(key_rr, key_data_rdf);
	return key_rr;
}

ldns_status
ldns_key_new_frm_pkcs11(ldns_pkcs11_ctx *pkcs11_ctx,
                        ldns_key **key,
                        ldns_algorithm algorithm,
                        uint16_t flags,
                        const unsigned char *key_id,
                        size_t key_id_len)
{
	ldns_key *k;
	ldns_rr *key_rr;
	struct pkcs_keypair_handle *key_object;
	
	k = ldns_key_new();
	if (!k) {
		return LDNS_STATUS_MEM_ERR;
	}

	ldns_key_set_algorithm(k, algorithm);
	
	key_object = pkcs_keypair_handle_new();
	key_object->pkcs11_ctx = pkcs11_ctx;
	key_object->private_key = ldns_pkcs11_get_key(
	                               pkcs11_ctx->function_list,
	                               pkcs11_ctx->session,
	                               CKO_PRIVATE_KEY,
	                               (CK_BYTE_PTR) key_id,
	                               key_id_len);
	if (!key_object->private_key) {
		fprintf(stderr, "; Private key not found for ");
		xprintf_hex(stderr, key_id, key_id_len);
		ldns_key_free(k);
		return LDNS_STATUS_ERR;
	}
	key_object->public_key = ldns_pkcs11_get_key(
	                              pkcs11_ctx->function_list,
	                              pkcs11_ctx->session,
	                              CKO_PUBLIC_KEY,
	                              (CK_BYTE_PTR) key_id,
	                              key_id_len);
	if (!key_object->public_key) {
		fprintf(stderr, "; Public key not found for ");
		xprintf_hex(stderr, key_id, key_id_len);
		ldns_key_free(k);
		return LDNS_STATUS_ERR;
	}
	ldns_key_set_external_key(k, key_object);
	ldns_key_set_flags(k, flags);

	key_rr = ldns_key2rr_pkcs(pkcs11_ctx,
	                          k);
	ldns_key_set_keytag(k, ldns_calc_keytag(key_rr));

	ldns_rr_free(key_rr);

	if (key) {
		*key = k;
		return LDNS_STATUS_OK;
	}
	return LDNS_STATUS_ERR;
}

static ldns_rdf *
ldns_sign_pkcs11_buffer(ldns_pkcs11_ctx *pkcs11_ctx,
                        ldns_buffer *sign_buf,
                        CK_OBJECT_HANDLE key_object)
{
	CK_RV rv;
	CK_ULONG signatureLen = 512;
	CK_BYTE *signature = malloc(signatureLen);
	CK_MECHANISM sign_mechanism;

	ldns_rdf *sig_rdf;

	sign_mechanism.mechanism = CKM_SHA1_RSA_PKCS;
	sign_mechanism.pParameter = NULL;
	sign_mechanism.ulParameterLen = 0;

	if (!pkcs11_ctx || !pkcs11_ctx->function_list) {
		return NULL;
	}

	rv = pkcs11_ctx->function_list->C_SignInit(
	                                  pkcs11_ctx->session,
	                                  &sign_mechanism,
	                                  key_object);
	ldns_pkcs11_check_rv(rv, "sign init new");
	
	rv = pkcs11_ctx->function_list->C_Sign(
	                                  pkcs11_ctx->session,
	                                  ldns_buffer_begin(sign_buf),
	                                  ldns_buffer_position(sign_buf),
	                                  signature,
	                                  &signatureLen);
	ldns_pkcs11_check_rv(rv, "sign final");

	sig_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64,
	                                signatureLen,
	                                signature);

	free(signature);
	return sig_rdf;
}


/* taken from sign_public */
ldns_rr_list *
ldns_pkcs11_sign_rrset(ldns_rr_list *rrset,
                       ldns_key_list *keys)
{
	ldns_rr_list *signatures;
	ldns_rr_list *rrset_clone;
	ldns_rr *current_sig;
	ldns_rdf *b64rdf;
	ldns_key *current_key;
	size_t key_count;
	uint16_t i;
	ldns_buffer *sign_buf;
	uint8_t label_count;
	ldns_rdf *new_owner;
	struct pkcs_keypair_handle *keypair_handle;
	
	if (!rrset || ldns_rr_list_rr_count(rrset) < 1 || !keys) {
		return NULL;
	}
	
	new_owner = NULL;

	key_count = 0;
	signatures = ldns_rr_list_new();

	/* prepare a signature and add all the know data
	 * prepare the rrset. Sign this together.  */
	rrset_clone = ldns_rr_list_clone(rrset);
	if (!rrset_clone) {
		return NULL;
	}

	/* make it canonical */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
		ldns_rr2canonical(ldns_rr_list_rr(rrset_clone, i));
	}
	/* sort */
	ldns_rr_list_sort(rrset_clone);
	
	/* check for label count and wildcard */
	label_count = ldns_dname_label_count(
	                   ldns_rr_owner(ldns_rr_list_rr(rrset, 0)));

	for (key_count = 0;
		key_count < ldns_key_list_key_count(keys);
		key_count++) {
		if (!ldns_key_use(ldns_key_list_key(keys, key_count))) {
			continue;
		}
		sign_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
		if (!sign_buf) {
			ldns_rr_list_free(rrset_clone);
			ldns_rr_list_free(signatures);
			ldns_rdf_free(new_owner);
			return NULL;
		}
		b64rdf = NULL;

		current_key = ldns_key_list_key(keys, key_count);
		/* sign all RRs with keys that have ZSKbit, !SEPbit.
		   sign DNSKEY RRs with keys that have ZSKbit&SEPbit */
		if (
		    ldns_key_flags(current_key) & LDNS_KEY_ZONE_KEY &&
		    (!(ldns_key_flags(current_key) & LDNS_KEY_SEP_KEY)
			|| ldns_rr_get_type(ldns_rr_list_rr(rrset, 0))
		        == LDNS_RR_TYPE_DNSKEY)
		    ) {
			current_sig = ldns_create_empty_rrsig(rrset_clone,
			                                      current_key);

			/* right now, we have: a key, a semi-sig and an rrset. For
			 * which we can create the sig and base64 encode that and
			 * add that to the signature */

			if (ldns_rrsig2buffer_wire(sign_buf, current_sig)
			    != LDNS_STATUS_OK) {
				ldns_buffer_free(sign_buf);
				/* ERROR */
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}

			/* add the rrset in sign_buf */
			if (ldns_rr_list2buffer_wire(sign_buf, rrset_clone)
			    != LDNS_STATUS_OK) {
				ldns_buffer_free(sign_buf);
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}

			keypair_handle = (struct pkcs_keypair_handle *)ldns_key_external_key(current_key);
			b64rdf = ldns_sign_pkcs11_buffer(keypair_handle->pkcs11_ctx,
			                                 sign_buf,
			                                 keypair_handle->private_key);

			if (!b64rdf) {
				/* signing went wrong */
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}

			ldns_rr_rrsig_set_sig(current_sig, b64rdf);

			/* push the signature to the signatures list */
			ldns_rr_list_push_rr(signatures, current_sig);
		}
		ldns_buffer_free(sign_buf); /* restart for the next key */
	}
	ldns_rr_list_deep_free(rrset_clone);

	return signatures;
}
