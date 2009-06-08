/* $Id$ */

/*
 * Copyright (c) 2009 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2009 NLNet Labs.
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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <uuid/uuid.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

#include "libhsm.h"
#include "libhsmdns.h"

#include <cryptoki.h>
#include <pkcs11.h>

/* fixed length from PKCS #11 specification */
#define HSM_TOKEN_LABEL_LENGTH 32

/* we need some globals, for session management, and for the initial
 * context
 */
static hsm_ctx_t *_hsm_ctx;

/* PKCS#11 specific functions */
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
        case CKR_FUNCTION_FAILED:
            return "CKR_FUNCTION_FAILED";
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
hsm_pkcs11_check_rv(CK_RV rv, const char *message)
{
    if (rv != CKR_OK) {
        fprintf(stderr,
                "Error in %s: %s (%d)\n",
                message,
                ldns_pkcs11_rv_str(rv),
                (int) rv);
        exit(EXIT_FAILURE);
    }
}

static void
hsm_pkcs11_unload_functions(void *handle)
{
    int result;
    if (handle) {
#if defined(HAVE_LOADLIBRARY)
        // no idea
#elif defined(HAVE_DLOPEN)
        result = dlclose(handle);
#endif
    }
}

static CK_RV
hsm_pkcs11_load_functions(hsm_module_t *module)
{
    CK_C_GetFunctionList pGetFunctionList = NULL;

    if (module && module->path) {
        /* library provided by application or user */
#if defined(HAVE_LOADLIBRARY)
fprintf(stderr, "have loadlibrary\n");
        /* Load PKCS #11 library */
        HINSTANCE hDLL = LoadLibrary(_T(module->path));

        if (hDLL == NULL)
        {
            /* Failed to load the PKCS #11 library */
            return CKR_FUNCTION_FAILED;
        }

        /* Retrieve the entry point for C_GetFunctionList */
        pGetFunctionList = (CK_C_GetFunctionList)
            GetProcAddress(hDLL, _T("C_GetFunctionList"));
#elif defined(HAVE_DLOPEN)
        /* Load PKCS #11 library */
        void* pDynLib = dlopen(module->path, RTLD_LAZY);

        if (pDynLib == NULL)
        {
            /* Failed to load the PKCS #11 library */
            fprintf(stderr, "dlopen() failed: %s\n", dlerror());
            return CKR_FUNCTION_FAILED;
        }

        /* Retrieve the entry point for C_GetFunctionList */
        pGetFunctionList = (CK_C_GetFunctionList) dlsym(pDynLib, "C_GetFunctionList");
        /* Store the handle so we can dlclose it later */
        module->handle = pDynLib;
#else
        fprintf(stderr, "dl given, no dynamic library support compiled in\n");
#endif
    } else {
        /* no library provided, use the statically compiled softHSM */
#ifdef HAVE_PKCS11_MODULE
fprintf(stderr, "have pkcs11_module\n");
        return C_GetFunctionList(pkcs11_functions);
#else
        fprintf(stderr, "Error, no pkcs11 module given, none compiled in\n");
#endif
    }

    if (pGetFunctionList == NULL)
    {
        fprintf(stderr, "no function list\n");
        /* Failed to load the PKCS #11 library */
        return CKR_FUNCTION_FAILED;
    }

    /* Retrieve the function list */
    (pGetFunctionList)((CK_FUNCTION_LIST_PTR)(&module->sym));
    return CKR_OK;
}

static int
hsm_pkcs11_check_token_name(CK_FUNCTION_LIST_PTR pkcs11_functions,
                             CK_SLOT_ID slotId,
                             const char *token_name)
{
    /* token label is always 32 bytes */
    char token_name_bytes[HSM_TOKEN_LABEL_LENGTH];
    int result = 0;
    CK_RV rv;
    CK_TOKEN_INFO token_info;

    rv = pkcs11_functions->C_GetTokenInfo(slotId, &token_info);
    hsm_pkcs11_check_rv(rv, "C_GetTokenInfo");

    memset(token_name_bytes, ' ', HSM_TOKEN_LABEL_LENGTH);
    if (strlen(token_name) < HSM_TOKEN_LABEL_LENGTH) {
        memcpy(token_name_bytes, token_name, strlen(token_name));
    } else {
        memcpy(token_name_bytes, token_name, HSM_TOKEN_LABEL_LENGTH);
    }

    result = memcmp(token_info.label,
                    token_name_bytes,
                    HSM_TOKEN_LABEL_LENGTH) == 0;

    return result;
}


static CK_SLOT_ID
ldns_hsm_get_slot_id(CK_FUNCTION_LIST_PTR pkcs11_functions,
                     const char *token_name)
{
    CK_RV rv;
    CK_SLOT_ID slotId = 0;
    CK_ULONG slotCount = 10;
    CK_SLOT_ID cur_slot;
    CK_SLOT_ID *slotIds = malloc(sizeof(CK_SLOT_ID) * slotCount);
    int found = 0;

    rv = pkcs11_functions->C_GetSlotList(CK_TRUE, slotIds, &slotCount);
    hsm_pkcs11_check_rv(rv, "get slot list");

    if (slotCount < 1) {
        fprintf(stderr, "Error; could not find token with the name %s\n", token_name);
        exit(1);
    }

    for (cur_slot = 0; cur_slot < slotCount; cur_slot++) {
        if (hsm_pkcs11_check_token_name(pkcs11_functions,
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

/* internal functions */
static hsm_module_t *
hsm_module_new(const char *repository,
               const char *token_label,
               const char *path)
{
    if (!repository || !path) return NULL;
    hsm_module_t *module;
    module = malloc(sizeof(hsm_module_t));
    module->id = 0; /*TODO i think we can remove this*/
    module->name = strdup(repository);
    module->token_label = strdup(token_label);
    module->path = strdup(path);
    module->handle = NULL;
    module->sym = NULL;
    return module;
}

static void
hsm_module_free(hsm_module_t *module)
{
    if (module) {
        if (module->name) free(module->name);
        if (module->token_label) free(module->token_label);
        if (module->path) free(module->path);

        free(module);
    }
}

static hsm_session_t *
hsm_session_new(hsm_module_t *module, CK_SESSION_HANDLE session_handle)
{
    hsm_session_t *session;
    session = malloc(sizeof(hsm_session_t));
    session->module = module;
    session->session = session_handle;
    return session;
}

static void
hsm_session_free(hsm_session_t *session) {
    if (session) {
        free(session);
    }
}

/* creates a session_t structure, and automatically adds and initializes
 * a module_t struct for it
 */
static int
hsm_session_init(hsm_session_t **session, char *repository,
                 char *token_label, char *module_path, char *pin)
{
    CK_RV rv;
    hsm_module_t *module;
    CK_SLOT_ID slot_id;
    CK_SESSION_HANDLE session_handle;

    module = hsm_module_new(repository, token_label, module_path);
    if (!module) return HSM_ERROR;
    rv = hsm_pkcs11_load_functions(module);
    hsm_pkcs11_check_rv(rv, "Load functions");
    rv = ((CK_FUNCTION_LIST_PTR) module->sym)->C_Initialize(NULL);
    hsm_pkcs11_check_rv(rv, "Initialization");
    slot_id = ldns_hsm_get_slot_id(module->sym, token_label);
    rv = ((CK_FUNCTION_LIST_PTR) module->sym)->C_OpenSession(slot_id,
                               CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL,
                               NULL,
                               &session_handle);
    hsm_pkcs11_check_rv(rv, "Open first session");
    rv = ((CK_FUNCTION_LIST_PTR) module->sym)->C_Login(session_handle,
                                   CKU_USER,
                                   (unsigned char *) pin,
                                   strlen((char *)pin));
    if (rv == CKR_OK) {
        *session = hsm_session_new(module, session_handle);
        return HSM_OK;
    } else {
        /* uninitialize the session again */
        if (session_handle) {
            rv = ((CK_FUNCTION_LIST_PTR) module->sym)->
                   C_CloseSession(session_handle);
            hsm_pkcs11_check_rv(rv, "finalize after failed login");
        }
        rv = ((CK_FUNCTION_LIST_PTR) module->sym)->C_Finalize(NULL);
        hsm_pkcs11_check_rv(rv, "finalize after failed login");
        hsm_module_free(module);
        *session = NULL;
        switch(rv) {
        case CKR_PIN_INCORRECT:
            return HSM_PIN_INCORRECT;
            break;
        default:
            return HSM_ERROR;
        }
    }
}

/* open a second session from the given one */
static hsm_session_t *
hsm_session_clone(hsm_session_t *session)
{
    CK_RV rv;
    CK_SLOT_ID slot_id;
    CK_SESSION_HANDLE session_handle;
    hsm_session_t *new_session;

    slot_id = ldns_hsm_get_slot_id(session->module->sym,
                                   session->module->token_label);
    rv = ((CK_FUNCTION_LIST_PTR) session->module->sym)->C_OpenSession(slot_id,
                                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                    NULL,
                                    NULL,
                                    &session_handle);

    hsm_pkcs11_check_rv(rv, "Clone session");
    new_session = hsm_session_new(session->module, session_handle);

    return new_session;
}

static hsm_ctx_t *
hsm_ctx_new()
{
    hsm_ctx_t *ctx;
    ctx = malloc(sizeof(hsm_ctx_t));
    memset(ctx->session, 0, HSM_MAX_SESSIONS);
    ctx->session_count = 0;
    return ctx;
}

/* ctx_free frees the structure */
static void
hsm_ctx_free(hsm_ctx_t *ctx)
{
    unsigned int i;
    if (ctx) {
        if (ctx->session) {
            for (i = 0; i < ctx->session_count; i++) {
                hsm_session_free(ctx->session[i]);
            }
        }
        free(ctx);
    }
}

/* close the session, and free the allocated data
 *
 * if unload is non-zero, C_Logout() is called,
 * the dlopen()d module is closed and unloaded
 * (only call this on the last session for each
 * module, ie. the one in the global ctx)
 */
static void
hsm_session_close(hsm_session_t *session, int unload)
{
    CK_RV rv;
    if (unload) {
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_Logout(session->session);
        hsm_pkcs11_check_rv(rv, "Logout");
    }
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_CloseSession(session->session);
    hsm_pkcs11_check_rv(rv, "Close session");
    if (unload) {
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_Finalize(NULL);
        hsm_pkcs11_check_rv(rv, "Finalize");
        hsm_pkcs11_unload_functions(session->module->handle);
        hsm_module_free(session->module);
        session->module = NULL;
    }
    hsm_session_free(session);
}

/* ctx_close closes all session, and free
 * the structures.
 *
 * if unload is non-zero, the associated dynamic libraries are unloaded
 * (hence only use that on the last, global, ctx)
 */
static void
hsm_ctx_close(hsm_ctx_t *ctx, int unload)
{
    unsigned int i;

    if (ctx) {
        for (i = 0; i < ctx->session_count; i++) {
            /* todo syslog? */
            /*printf("close session %u (unload: %d)\n", i, unload);*/
            /*hsm_print_ctx(ctx);*/
            hsm_session_close(ctx->session[i], unload);
            ctx->session[i] = NULL;
            /* if this was the last session in the array, decrease
             * the session counter of the context */
            if (i == _hsm_ctx->session_count) {
                while(ctx->session_count > 0 && !ctx->session[i]) {
                    ctx->session_count--;
                }
            }
        }
        free(ctx);
    }
}


/* adds a session to the context.
 * returns  0 on succes
 *          1 if one of the arguments is NULL
 *         -1 if the maximum number of sessions (HSM_MAX_SESSIONS) was
 *            reached
 */
static int
hsm_ctx_add_session(hsm_ctx_t *ctx, hsm_session_t *session)
{
    if (!ctx || !session) return -1;
    if (ctx->session_count >= HSM_MAX_SESSIONS) return 1;
    ctx->session[ctx->session_count] = session;
    ctx->session_count++;
    return 0;
}

static hsm_ctx_t *
hsm_ctx_clone(hsm_ctx_t *ctx)
{
    unsigned int i;
    hsm_ctx_t *new_ctx;
    hsm_session_t *new_session;

    new_ctx = NULL;
    if (ctx) {
        new_ctx = hsm_ctx_new();
        for (i = 0; i < ctx->session_count; i++) {
            new_session = hsm_session_clone(ctx->session[i]);
            hsm_ctx_add_session(new_ctx, new_session);
        }
    }
    return new_ctx;
}

static hsm_key_t *
hsm_key_new()
{
    hsm_key_t *key;
    key = malloc(sizeof(hsm_key_t));
    key->module = NULL;
    key->private_key = 0;
    key->public_key = 0;
    return key;
}

/* find the session belonging to a key, by iterating over the modules
 * in the context */
static hsm_session_t *
hsm_find_key_session(const hsm_ctx_t *ctx, const hsm_key_t *key)
{
    unsigned int i;
    if (!key || !key->module) return NULL;
    if (!ctx) ctx = _hsm_ctx;
    for (i = 0; i < ctx->session_count; i++) {
        if (ctx->session[i] && ctx->session[i]->module == key->module) {
            return ctx->session[i];
        }
    }
    return NULL;
}

static CK_OBJECT_HANDLE
hsm_find_object_handle_for_id(const hsm_session_t *session,
                              CK_OBJECT_CLASS key_class,
                              CK_BYTE *id,
                              CK_ULONG id_len)
{
    CK_ULONG objectCount;
    CK_OBJECT_HANDLE object;
    CK_RV rv;

    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_ID, id, id_len },
    };

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjectsInit(session->session,
                                                 template, 2);
    hsm_pkcs11_check_rv(rv, "Find objects init");

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjects(session->session,
                                         &object,
                                         1,
                                         &objectCount);
    hsm_pkcs11_check_rv(rv, "Find object");

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjectsFinal(session->session);
    hsm_pkcs11_check_rv(rv, "Find object final");
    if (objectCount > 0) {
        hsm_pkcs11_check_rv(rv, "Find objects final");
        return object;
    } else {
        return 0;
    }
}

/*
 * Parses the null-terminated string hex as hex values,
 * Returns allocated data that needs to be freed (or NULL on error)
 * len will contain the number of bytes allocated, or 0 on error
 */
static unsigned char *
hsm_hex_str2bytes(const char *hex, size_t *len)
{
    unsigned char *bytes;
    /* length of the hex input */
    size_t hex_len;
    size_t i;

    if (!len) return NULL;
    *len = 0;

    if (!hex) return NULL;
    hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        fprintf(stderr,
                "Error: bad hex data for key id: %s\n",
                hex);
        return NULL;
    }

    *len = hex_len / 2;
    bytes = malloc(*len);
    for (i = 0; i < *len; i++) {
        bytes[i] = ldns_hexdigit_to_int(hex[2*i]) * 16 +
                   ldns_hexdigit_to_int(hex[2*i+1]);
    }
    return bytes;
}


/* returns an allocated byte array with the CKA_ID for the given object
 * len will contain the result size
 * returns NULL and size zero if not found in this session
 */
static CK_BYTE *
hsm_get_id_for_object(const hsm_session_t *session,
                      CK_OBJECT_HANDLE object,
                      size_t *len)
{
    CK_RV rv;
    CK_BYTE *id = NULL;

    CK_ATTRIBUTE template[] = {
        {CKA_ID, id, 0}
    };

    /* find out the size of the id first */
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      object,
                                      template,
                                      1);
    hsm_pkcs11_check_rv(rv, "Get attr value\n");

    if ((CK_LONG)template[0].ulValueLen < 1) {
        *len = 0;
        return id;
    }
    
    template[0].pValue = malloc(template[0].ulValueLen);
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      object,
                                      template,
                                      1);
    hsm_pkcs11_check_rv(rv, "Get attr value 2\n");

    *len = template[0].ulValueLen;
    return template[0].pValue;
}


/* returns an hsm_key_t object for the given *private key* object handle
 * the module, private key, and public key handle are set
 * The session needs to be free to perform a search for the public key
 */
static hsm_key_t *
hsm_key_new_privkey_object_handle(const hsm_session_t *session,
                                  CK_OBJECT_HANDLE object)
{
    hsm_key_t *key;
    CK_BYTE *id;
    size_t len;

    id = hsm_get_id_for_object(session, object, &len);

    if (!id) return NULL;

    key = hsm_key_new();
    key->module = session->module;
    key->private_key = object;
    key->public_key = hsm_find_object_handle_for_id(
                          session,
                          CKO_PUBLIC_KEY,
                          id,
                          len);

    free(id);
    return key;
}

/* helper function to find both key counts or the keys themselves
 * if the argument store is 0, results are not returned; the
 * function will only set the count and return NULL
 * Otherwise, a newly allocated key array will be returned
 */
static hsm_key_t **
hsm_list_keys_session_internal(const hsm_session_t *session,
                               size_t *count,
                               int store)
{
    hsm_key_t **keys = NULL;
    hsm_key_t *key;
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
    };
    CK_ULONG total_count = 0;
    CK_ULONG objectCount = 1;
    /* find 100 keys at a time (and loop until there are none left) */
    CK_ULONG max_object_count = 100;
    CK_ULONG i, j;
    CK_OBJECT_HANDLE object[max_object_count];
    CK_OBJECT_HANDLE *key_handles = NULL;

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjectsInit(session->session,
                                                 template, 1);
    hsm_pkcs11_check_rv(rv, "Find objects init");
    j = 0;
    while (objectCount > 0) {
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjects(session->session,
                                                 object,
                                                 max_object_count,
                                                 &objectCount);
        hsm_pkcs11_check_rv(rv, "Find first object");

        if (objectCount > 0 && store) {
            key_handles = realloc(key_handles, total_count * sizeof(CK_OBJECT_HANDLE));
            
            for (i = 0; i < objectCount; i++) {
                key_handles[j] = object[i];
                j++;
            }
        }
        total_count += objectCount;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjectsFinal(session->session);
    hsm_pkcs11_check_rv(rv, "Find objects final");

    if (store) {
        keys = realloc(keys, total_count * sizeof(hsm_key_t *));
        for (i = 0; i < total_count; i++) {
            key = hsm_key_new_privkey_object_handle(session, key_handles[i]);
            keys[i] = key;
        }
    }
    free(key_handles);
    
    *count = total_count;
    return keys;
}


/* returns an array of all keys available to the given session
 *
 * \param session the session to find the keys in
 * \param count this value will contain the number of keys found
 *
 * \return the list of keys
 */
hsm_key_t **
hsm_list_keys_session(const hsm_session_t *session, size_t *count)
{
    return hsm_list_keys_session_internal(session, count, 1);
}

/* returns a count all keys available to the given session
 *
 * \param session the session to find the keys in
 *
 * \return the number of keys
 */
size_t
hsm_count_keys_session(const hsm_session_t *session)
{
    size_t count = 0;
    (void) hsm_list_keys_session_internal(session, &count, 0);
    return count;
}

/* returns a newly allocated key structure containing the key data
 * for the given CKA_ID available in the session. Returns NULL if not
 * found
 */
static hsm_key_t *
hsm_find_key_by_id_session(const hsm_session_t *session,
                           const unsigned char *id,
                           size_t len)
{
    hsm_key_t *key;
    CK_OBJECT_HANDLE private_key_handle;

    private_key_handle = hsm_find_object_handle_for_id(
                             session,
                             CKO_PRIVATE_KEY,
                             (CK_BYTE *) id,
                             (CK_ULONG) len);
    if (private_key_handle != 0) {
        key = hsm_key_new_privkey_object_handle(session,
                                                private_key_handle);
        return key;
    } else {
        return NULL;
    }
}

/* Find a key pair by CKA_ID (as byte array)

The returned key structure can be freed with hsm_key_free()

\param context HSM context
\param id CKA_ID of key to find (array of bytes)
\param len number of bytes in the id
\return key identifier or NULL if not found
*/
static hsm_key_t *
hsm_find_key_by_id_bin(const hsm_ctx_t *ctx,
                       const unsigned char *id,
                       size_t len)
{
    hsm_key_t *key;
    unsigned int i;

    if (!ctx) ctx = _hsm_ctx;
    if (!id) return NULL;

    for (i = 0; i < ctx->session_count; i++) {
        key = hsm_find_key_by_id_session(ctx->session[i], id, len);
        if (key) return key;
    }
    return NULL;
}


/**
 * returns the first session found if repository is null, otherwise
 * finds the session belonging to the repository with the given name
 * returns NULL if not found
 */
static hsm_session_t *
hsm_find_repository_session(const hsm_ctx_t *ctx, const char *repository)
{
    unsigned int i;
    if (!repository) {
        for (i = 0; i < ctx->session_count; i++) {
            if (ctx->session[i]) {
                return ctx->session[i];
            }
        }
    } else {
        for (i = 0; i < ctx->session_count; i++) {
            if (ctx->session[i] &&
                strcmp(repository, ctx->session[i]->module->name) == 0)
            {
                return ctx->session[i];
            }
        }
    }
    return NULL;
}

static ldns_rdf *
hsm_get_key_rdata(hsm_session_t *session, const hsm_key_t *key)
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

    if (!session || !session->module) {
        return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->public_key,
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

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->public_key,
                                      template,
                                      2);
    hsm_pkcs11_check_rv(rv, "get attribute value");

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

/* this function allocates memory for the mechanism ID and enough room
 * to leave the upcoming digest data. It fills in the mechanism id
 * use with care. The returned data must be free'd by the caller */
static CK_BYTE *
hsm_create_prefix(CK_ULONG digest_len,
                  ldns_algorithm algorithm,
                  CK_ULONG *data_size)
{
    CK_BYTE *data;
    const CK_BYTE RSA_MD5_ID[] = { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
    const CK_BYTE RSA_SHA1_ID[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };

    switch(algorithm) {
        case LDNS_SIGN_RSAMD5:
            *data_size = sizeof(RSA_MD5_ID) + digest_len;
            data = malloc(*data_size);
            memcpy(data, RSA_MD5_ID, sizeof(RSA_MD5_ID));
            break;
        case LDNS_SIGN_RSASHA1:
        case LDNS_SIGN_RSASHA1_NSEC3:
            *data_size = sizeof(RSA_SHA1_ID) + digest_len;
            data = malloc(*data_size);
            memcpy(data, RSA_SHA1_ID, sizeof(RSA_SHA1_ID));
            break;
        default:
            return NULL;
    }
    return data;
}

static ldns_rdf *
hsm_sign_buffer(const hsm_ctx_t *ctx,
                ldns_buffer *sign_buf,
                const hsm_key_t *key,
                ldns_algorithm algorithm)
{
    CK_RV rv;
    /* TODO: depends on type and key, or just leave it at current
     * maximum? */
    CK_ULONG signatureLen = 512;
    CK_BYTE *signature = malloc(signatureLen);
    CK_MECHANISM digest_mechanism;
    CK_MECHANISM sign_mechanism;

    ldns_rdf *sig_rdf;
    CK_BYTE *digest = NULL;
    CK_ULONG digest_len;

    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;

    hsm_session_t *session;

    session = hsm_find_key_session(ctx, key);
    if (!session) return NULL;

    /* some HSMs don't really handle CKM_SHA1_RSA_PKCS well, so
     * we'll do the hashing manually */
    /* When adding algorithms, remember there is another switch below */
    digest_mechanism.pParameter = NULL;
    digest_mechanism.ulParameterLen = 0;
    switch (algorithm) {
        case LDNS_SIGN_RSAMD5:
            digest_len = 16;
            digest_mechanism.mechanism = CKM_MD5;
            break;
        case LDNS_SIGN_RSASHA1:
        case LDNS_SIGN_RSASHA1_NSEC3:
            digest_len = 20;
            digest_mechanism.mechanism = CKM_SHA_1;
            break;
        default:
            /* log error? or should we not even get here for
             * unsupported algorithms? */
            return NULL;
    }

    digest = malloc(digest_len);

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_DigestInit(session->session,
                                                 &digest_mechanism);
    hsm_pkcs11_check_rv(rv, "digest init");

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_Digest(session->session,
                                        ldns_buffer_begin(sign_buf),
                                        ldns_buffer_position(sign_buf),
                                        digest,
                                        &digest_len);
    hsm_pkcs11_check_rv(rv, "digest");

    /* CKM_RSA_PKCS does the padding, but cannot know the identifier
     * prefix, so we need to add that ourselves */
    data = hsm_create_prefix(digest_len, algorithm, &data_len);
    memcpy(data + data_len - digest_len, digest, digest_len);

    sign_mechanism.pParameter = NULL;
    sign_mechanism.ulParameterLen = 0;
    switch(algorithm) {
        case LDNS_SIGN_RSAMD5:
        case LDNS_SIGN_RSASHA1:
        case LDNS_SIGN_RSASHA1_NSEC3:
            sign_mechanism.mechanism = CKM_RSA_PKCS;
            break;
        default:
            /* log error? or should we not even get here for
             * unsupported algorithms? */
            return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_SignInit(
                                      session->session,
                                      &sign_mechanism,
                                      key->private_key);
    hsm_pkcs11_check_rv(rv, "sign init");

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_Sign(session->session, data, data_len,
                                      signature,
                                      &signatureLen);
    hsm_pkcs11_check_rv(rv, "sign final");

    sig_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64,
                                    signatureLen,
                                    signature);

    free(data);
    free(digest);
    free(signature);

    return sig_rdf;

}

static ldns_rr *
hsm_create_empty_rrsig(const ldns_rr_list *rrset,
                       const hsm_sign_params_t *sign_params)
{
    ldns_rr *rrsig;
    uint32_t orig_ttl;
    time_t now;
    uint8_t label_count;

    label_count = ldns_dname_label_count(
                       ldns_rr_owner(ldns_rr_list_rr(rrset, 0)));

    rrsig = ldns_rr_new_frm_type(LDNS_RR_TYPE_RRSIG);

    /* set the type on the new signature */
    orig_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrset, 0));

    ldns_rr_set_ttl(rrsig, orig_ttl);
    ldns_rr_set_owner(rrsig,
              ldns_rdf_clone(
                   ldns_rr_owner(
                    ldns_rr_list_rr(rrset,
                            0))));

    /* fill in what we know of the signature */

    /* set the orig_ttl */
    (void)ldns_rr_rrsig_set_origttl(
           rrsig,
           ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
                     orig_ttl));
    /* the signers name */
    (void)ldns_rr_rrsig_set_signame(
               rrsig,
               ldns_rdf_clone(sign_params->owner));
    /* label count - get it from the first rr in the rr_list */
    (void)ldns_rr_rrsig_set_labels(
            rrsig,
            ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8,
                                 label_count));
    /* inception, expiration */
    now = time(NULL);
    if (sign_params->inception != 0) {
        (void)ldns_rr_rrsig_set_inception(
                rrsig,
                ldns_native2rdf_int32(
                    LDNS_RDF_TYPE_TIME,
                    sign_params->inception));
    } else {
        (void)ldns_rr_rrsig_set_inception(
                rrsig,
                ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, now));
    }
    if (sign_params->expiration != 0) {
        (void)ldns_rr_rrsig_set_expiration(
                rrsig,
                ldns_native2rdf_int32(
                    LDNS_RDF_TYPE_TIME,
                    sign_params->expiration));
    } else {
        (void)ldns_rr_rrsig_set_expiration(
                 rrsig,
                ldns_native2rdf_int32(
                    LDNS_RDF_TYPE_TIME,
                    now + LDNS_DEFAULT_EXP_TIME));
    }

    (void)ldns_rr_rrsig_set_keytag(
           rrsig,
           ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16,
                                 sign_params->keytag));

    (void)ldns_rr_rrsig_set_algorithm(
            rrsig,
            ldns_native2rdf_int8(
                LDNS_RDF_TYPE_ALG,
                sign_params->algorithm));

    (void)ldns_rr_rrsig_set_typecovered(
            rrsig,
            ldns_native2rdf_int16(
                LDNS_RDF_TYPE_TYPE,
                ldns_rr_get_type(ldns_rr_list_rr(rrset,
                                                 0))));

    return rrsig;
}


/*
 *  API functions
 */

int
hsm_open(const char *config,
         char *(pin_callback)(const char *repository, void *),
         void *data)
{
    xmlDocPtr doc;
    xmlXPathContextPtr xpath_ctx;
    xmlXPathObjectPtr xpath_obj;
    xmlNode *curNode;
    xmlChar *xexpr;

    int i;
    char *repository;
    char *token_label;
    char *module_path;
    char *module_pin;
    int result;
    int tries;

    /* create an internal context with an attached session for each
     * configured HSM. */
    _hsm_ctx = hsm_ctx_new();

    if (!config) return 0;

    /* Load XML document */
    doc = xmlParseFile(config);
    if (doc == NULL) {
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", config);
        return HSM_CONFIG_FILE_ERROR;
    }

    /* Create xpath evaluation context */
    xpath_ctx = xmlXPathNewContext(doc);
    if(xpath_ctx == NULL) {
        fprintf(stderr,"Error: unable to create new XPath context\n");
        xmlFreeDoc(doc);
        hsm_ctx_free(_hsm_ctx);
        _hsm_ctx = NULL;
        return -1;
    }

    /* Evaluate xpath expression */
    xexpr = (xmlChar *)"//Configuration/RepositoryList/Repository";
    xpath_obj = xmlXPathEvalExpression(xexpr, xpath_ctx);
    if(xpath_obj == NULL) {
        fprintf(stderr,"Error: unable to evaluate xpath expression\n");
        xmlXPathFreeContext(xpath_ctx);
        xmlFreeDoc(doc);
        hsm_ctx_free(_hsm_ctx);
        _hsm_ctx = NULL;
        return -1;
    }

    if (xpath_obj->nodesetval) {
        for (i = 0; i < xpath_obj->nodesetval->nodeNr; i++) {
            /*module = hsm_module_new();*/
            token_label = NULL;
            module_path = NULL;
            module_pin = NULL;
            curNode = xpath_obj->nodesetval->nodeTab[i]->xmlChildrenNode;
            repository = (char *) xmlGetProp(xpath_obj->nodesetval->nodeTab[i],
                                             (const xmlChar *)"name");
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"TokenLabel"))
                    token_label = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Module"))
                    module_path = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"PIN"))
                    module_pin = (char *) xmlNodeGetContent(curNode);
                curNode = curNode->next;
            }
            if (repository && token_label && module_path) {
                if (module_pin) {
                    result = hsm_attach(repository,
                                        token_label,
                                        module_path,
                                        module_pin);
                    free(module_pin);
                } else {
                    if (pin_callback) {
                        result = HSM_PIN_INCORRECT;
                        tries = 0;
                        while (result == HSM_PIN_INCORRECT &&
                               tries < 3) {
                            module_pin = pin_callback(repository,
                                                      data);
                            result = hsm_attach(repository,
                                                token_label,
                                                module_path,
                                                module_pin);
                            memset(module_pin, 0, strlen(module_pin));
                            tries++;
                        }
                    } else {
                        /* no pin, no callback, ignore
                         * module and token */
                        result = HSM_OK;
                    }
                }
                if (result == HSM_OK) {
                    /* TODO: syslog error/succes? */
                    /*fprintf(stdout,
                            "repository '%s' added\n",
                            repository);*/
                } else {
                    fprintf(stderr, "error adding module\n");
                }
                free(repository);
                free(token_label);
                free(module_path);
            }
else { printf("missing data?\n"); exit(0); }
        }
    }

    xmlXPathFreeObject(xpath_obj);
    xmlXPathFreeContext(xpath_ctx);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}

char *
hsm_prompt_pin(const char *repository, void *data)
{
    char *prompt;
    char *r;
    (void) data;
    prompt = malloc(64);
    snprintf(prompt, 64, "Enter PIN for token %s:", repository);
#ifdef HAVE_GETPASSPHRASE
    r = getpassphrase("Enter PIN:");
#else
    r = getpass("Enter PIN:");
#endif
    free(prompt);
    return r;
}

int
hsm_close()
{
    hsm_ctx_close(_hsm_ctx, 1);
    return 0;
}

hsm_ctx_t *
hsm_create_context()
{
    return hsm_ctx_clone(_hsm_ctx);
}

void
hsm_destroy_context(hsm_ctx_t *ctx)
{
    hsm_ctx_close(ctx, 0);
}

/**
 * Returns an allocated hsm_sign_params_t with some defaults
 */
hsm_sign_params_t *
hsm_sign_params_new()
{
    hsm_sign_params_t *params;
    params = malloc(sizeof(hsm_sign_params_t));
    params->algorithm = LDNS_SIGN_RSASHA1;
    params->flags = LDNS_KEY_ZONE_KEY;
    params->inception = 0;
    params->expiration = 0;
    params->keytag = 0;
    params->owner = NULL;
    return params;
}

void
hsm_sign_params_free(hsm_sign_params_t *params)
{
    if (params) {
        if (params->owner) ldns_rdf_deep_free(params->owner);
        free(params);
    }
}

hsm_key_t **
hsm_list_keys(const hsm_ctx_t *ctx, size_t *count)
{
    hsm_key_t **keys = NULL;
    size_t key_count = 0;
    size_t cur_key_count;
    hsm_key_t **session_keys;
    unsigned int i, j;

    if (!ctx) {
        ctx = _hsm_ctx;
    }

    for (i = 0; i < ctx->session_count; i++) {
        session_keys = hsm_list_keys_session(ctx->session[i],
                                             &cur_key_count);
        keys = realloc(keys,
                       key_count + cur_key_count * sizeof(hsm_key_t *));
        for (j = 0; j < cur_key_count; j++) {
            keys[key_count + j] = session_keys[j];
        }
        key_count += cur_key_count;
        free(session_keys);
    }
    if (count) {
        *count = key_count;
    }
    return keys;
}

hsm_key_t **
hsm_list_keys_repository(const hsm_ctx_t *ctx,
                         size_t *count,
                         const char *repository)
{
    hsm_session_t *session;
    
    if (!repository) return NULL;
    if (!ctx) ctx = _hsm_ctx;
    
    session = hsm_find_repository_session(ctx, repository);
    if (!session) {
        *count = 0;
        return NULL;
    }
    return hsm_list_keys_session(session, count);
}

size_t
hsm_count_keys(const hsm_ctx_t *ctx)
{
    size_t count = 0;
    unsigned int i;
    
    if (!ctx) ctx = _hsm_ctx;
    for (i = 0; i < ctx->session_count; i++) {
        count += hsm_count_keys_session(ctx->session[i]);
    }
    return count;
}

size_t
hsm_count_keys_repository(const hsm_ctx_t *ctx,
                          const char *repository)
{
    hsm_session_t *session;
    
    if (!repository) return 0;
    if (!ctx) ctx = _hsm_ctx;
    
    session = hsm_find_repository_session(ctx, repository);
    if (!session) {
        return 0;
    }
    return hsm_count_keys_session(session);
}

hsm_key_t *
hsm_find_key_by_id(const hsm_ctx_t *ctx, const char *id)
{
    unsigned char *id_bytes;
    size_t len;
    hsm_key_t *key;
    
    id_bytes = hsm_hex_str2bytes(id, &len);

    if (!id_bytes) return NULL;
    
    key = hsm_find_key_by_id_bin(ctx, id_bytes, len);
    free(id_bytes);
    return key;
}

hsm_key_t *
hsm_generate_rsa_key(const hsm_ctx_t *ctx,
                     const char *repository,
                     unsigned long keysize)
{
    hsm_key_t *new_key;
    hsm_session_t *session;
    /*unsigned int i;*/
    uuid_t *uuid;
    char uuid_str[37];
    CK_RV rv;
    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_MECHANISM mechanism = {
        CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };
    CK_BYTE publicExponent[] = { 1, 0, 1 };
    CK_BBOOL ctrue = CK_TRUE;
    CK_BBOOL cfalse = CK_FALSE;

    if (!ctx) ctx = _hsm_ctx;
    session = hsm_find_repository_session(ctx, repository);
    if (!session) return NULL;

    uuid = malloc(sizeof(uuid_t));
    uuid_generate(*uuid);
    /* check whether this key doesn't happen to exist already */
    while (hsm_find_key_by_id_bin(ctx, (const unsigned char *)uuid,
                                  sizeof(uuid_t))) {
        uuid_generate(*uuid);
    }
    uuid_unparse(*uuid, uuid_str);

    CK_ATTRIBUTE publicKeyTemplate[] = {
        { CKA_LABEL,(CK_UTF8CHAR*) uuid_str, strlen(uuid_str) },
        { CKA_ID,                  uuid,     sizeof(uuid_t)   },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType)  },
        { CKA_VERIFY,              &ctrue,   sizeof(ctrue)    },
        { CKA_ENCRYPT,             &cfalse,  sizeof(cfalse)   },
        { CKA_WRAP,                &cfalse,  sizeof(cfalse)   },
        { CKA_TOKEN,               &ctrue,   sizeof(ctrue)    },
        { CKA_MODULUS_BITS,        &keysize, sizeof(keysize)  },
        { CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent)}
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
        { CKA_LABEL,(CK_UTF8CHAR *) uuid_str, strlen (uuid_str) },
        { CKA_ID,          uuid,     sizeof(uuid_t) },
        { CKA_KEY_TYPE,    &keyType, sizeof(keyType) },
        { CKA_SIGN,        &ctrue,   sizeof (ctrue) },
        { CKA_DECRYPT,     &cfalse,  sizeof (cfalse) },
        { CKA_UNWRAP,      &cfalse,  sizeof (cfalse) },
        { CKA_SENSITIVE,   &ctrue,   sizeof (ctrue) },
        { CKA_TOKEN,       &ctrue,   sizeof (ctrue)  },
        { CKA_PRIVATE,     &ctrue,   sizeof (ctrue)  },
        { CKA_EXTRACTABLE, &cfalse,  sizeof (cfalse) }
    };

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GenerateKeyPair(session->session,
                                                 &mechanism,
                                                 publicKeyTemplate, 9,
                                                 privateKeyTemplate, 10,
                                                 &publicKey,
                                                 &privateKey);
    hsm_pkcs11_check_rv(rv, "generate key pair");

    new_key = hsm_key_new();
    new_key->module = session->module;
    new_key->public_key = publicKey;
    new_key->private_key = privateKey;
    return new_key;
}

int
hsm_remove_key(const hsm_ctx_t *ctx, hsm_key_t *key)
{
    CK_RV rv;
    hsm_session_t *session;
    if (!ctx) ctx = _hsm_ctx;
    if (!key) return -1;

    session = hsm_find_key_session(ctx, key);
    if (!session) return -2;

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_DestroyObject(session->session,
                                               key->private_key);
    hsm_pkcs11_check_rv(rv, "Destroy private key");
    key->private_key = 0;
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_DestroyObject(session->session,
                                               key->public_key);
    hsm_pkcs11_check_rv(rv, "Destroy public key");
    key->public_key = 0;

    return 0;
}

void
hsm_key_free(hsm_key_t *key)
{
    if (key) {
        free(key);
    }
}

void
hsm_key_list_free(hsm_key_t **key_list, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++) {
        hsm_key_free(key_list[i]);
    }
}

char *
hsm_get_key_id(const hsm_ctx_t *ctx, const hsm_key_t *key)
{
    unsigned char *id;
    char *id_str;
    size_t len, i;
    hsm_session_t *session;
    
    if (!ctx) ctx = _hsm_ctx;
    if (!key) return NULL;

    session = hsm_find_key_session(ctx, key);
    if (!session) return NULL;
    
    id = hsm_get_id_for_object(session, key->public_key, &len);
    if (!id) return NULL;
    
    /* this is plain binary data, we need to convert it to hex */
    id_str = malloc(len * 2 + 1);
    for (i = 0; i < len; i++) {
        sprintf(id_str, "%02x", id[i]);
    }

    free(id);

    return id_str;
}

ldns_rr*
hsm_sign_rrset(const hsm_ctx_t *ctx,
               const ldns_rr_list* rrset,
               const hsm_key_t *key,
               const hsm_sign_params_t *sign_params)
{
    ldns_rr *signature;
    ldns_buffer *sign_buf;
    ldns_rdf *b64_rdf;
    (void) ctx;

    if (!key) return NULL;
    if (!sign_params) return NULL;

    signature = hsm_create_empty_rrsig((ldns_rr_list *)rrset,
                                       sign_params);

    /* right now, we have: a key, a semi-sig and an rrset. For
     * which we can create the sig and base64 encode that and
     * add that to the signature */
    sign_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);

    if (ldns_rrsig2buffer_wire(sign_buf, signature)
        != LDNS_STATUS_OK) {
        ldns_buffer_free(sign_buf);
        /* ERROR */
        return NULL;
    }

    /* add the rrset in sign_buf */
    if (ldns_rr_list2buffer_wire(sign_buf, rrset)
        != LDNS_STATUS_OK) {
        ldns_buffer_free(sign_buf);
        return NULL;
    }

    b64_rdf = hsm_sign_buffer(ctx, sign_buf, key, sign_params->algorithm);

    ldns_buffer_free(sign_buf);
    if (!b64_rdf) {
        /* signing went wrong */
        return NULL;
    }

    ldns_rr_rrsig_set_sig(signature, b64_rdf);

    return signature;
}

/* returns a newly allocated (not null-terminated!) string containing
 * the message digest of the given source string
 * digest length contains the length of the result
 * caller must free returned data with free()
 */
static CK_BYTE *
hsm_digest(hsm_session_t *session,
           CK_MECHANISM digest_mechanism,
           char *source,
           size_t length,
           size_t *digest_length)
{
    CK_RV rv;
    CK_BYTE *digest;
    CK_ULONG d = 0;

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_DigestInit(session->session,
                                                 &digest_mechanism);
    hsm_pkcs11_check_rv(rv, "digest init");

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_Digest(session->session,
                                        (CK_BYTE *)source,
                                        length,
                                        NULL,
                                        &d);

    digest = malloc(d);
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_Digest(session->session,
                                        (CK_BYTE *)source,
                                        length,
                                        digest,
                                        &d);
    hsm_pkcs11_check_rv(rv, "digest");
    *digest_length = d;
    return digest;
}

ldns_rdf *
hsm_nsec3_hash_name(const hsm_ctx_t *ctx,
                    ldns_rdf *name,
                    uint8_t algorithm,
                    uint16_t iterations,
                    uint8_t salt_length,
                    uint8_t *salt)
{
    char *orig_owner_str;
    size_t hashed_owner_str_len;
    ldns_rdf *hashed_owner;
    char *hashed_owner_str;
    char *hashed_owner_b32;
    int hashed_owner_b32_len;
    uint32_t cur_it;
    char *hash = NULL;
    size_t hash_length;
    ldns_status status;
    CK_MECHANISM mechanism;
    unsigned int i;
    hsm_session_t *session = NULL;

    switch(algorithm) {
    case 1:
        mechanism.mechanism = CKM_SHA_1;
        mechanism.pParameter = NULL;
        mechanism.ulParameterLen = 0;
        break;
    default:
        printf("unknown algo: %u\n", (unsigned int)algorithm);
        return NULL;
        break;
    }

    /* just use the first available session */
    if (!ctx) ctx = _hsm_ctx;
    for (i = 0; i < ctx->session_count; i++) {
        if (ctx->session[i]) session = ctx->session[i];
    }
    if (!session) {
        return NULL;
    }

    /* prepare the owner name according to the draft section bla */
    orig_owner_str = ldns_rdf2str(name);

    hashed_owner_str_len = salt_length + ldns_rdf_size(name);
    hashed_owner_str = LDNS_XMALLOC(char, hashed_owner_str_len);
    memcpy(hashed_owner_str, ldns_rdf_data(name), ldns_rdf_size(name));
    memcpy(hashed_owner_str + ldns_rdf_size(name), salt, salt_length);

    for (cur_it = iterations + 1; cur_it > 0; cur_it--) {
        free(hash);
        hash = (char *) hsm_digest(session,
                                   mechanism,
                                   hashed_owner_str,
                                   hashed_owner_str_len,
                                   &hash_length);

        LDNS_FREE(hashed_owner_str);
        hashed_owner_str_len = salt_length + hash_length;
        hashed_owner_str = LDNS_XMALLOC(char, hashed_owner_str_len);
        if (!hashed_owner_str) {
            fprintf(stderr, "Memory error\n");
            abort();
        }
        memcpy(hashed_owner_str, hash, hash_length);
        memcpy(hashed_owner_str + hash_length, salt, salt_length);
    }

    LDNS_FREE(hashed_owner_str);
    hashed_owner_str = hash;
    hashed_owner_str_len = hash_length;
    hashed_owner_b32 = LDNS_XMALLOC(char,
                              ldns_b32_ntop_calculate_size(
                                   hashed_owner_str_len) + 1);
    LDNS_FREE(orig_owner_str);
    hashed_owner_b32_len =
        (size_t) ldns_b32_ntop_extended_hex((uint8_t *) hashed_owner_str,
                                     hashed_owner_str_len,
                                     hashed_owner_b32,
                                     ldns_b32_ntop_calculate_size(
                                         hashed_owner_str_len));
    if (hashed_owner_b32_len < 1) {
        fprintf(stderr, "Error in base32 extended hex encoding ");
        fprintf(stderr, "of hashed owner name (name: ");
        ldns_rdf_print(stderr, name);
        fprintf(stderr, ", return code: %d)\n", hashed_owner_b32_len);
        LDNS_FREE(hashed_owner_b32);
        return NULL;
    }
    hashed_owner_str_len = hashed_owner_b32_len;
    hashed_owner_b32[hashed_owner_b32_len] = '\0';

    status = ldns_str2rdf_dname(&hashed_owner, hashed_owner_b32);
    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "Error creating rdf from %s\n", hashed_owner_b32);
        LDNS_FREE(hashed_owner_b32);
        return NULL;
    }

    free(hash);
    LDNS_FREE(hashed_owner_b32);
    return hashed_owner;
}

ldns_rr *
hsm_get_dnskey(const hsm_ctx_t *ctx,
               const hsm_key_t *key,
               const hsm_sign_params_t *sign_params)
{
    //CK_RV rv;
    ldns_rr *dnskey;
    hsm_session_t *session;

    if (!sign_params) return NULL;
    if (!ctx) ctx = _hsm_ctx;
    session = hsm_find_key_session(ctx, key);
    if (!session) return NULL;

    dnskey = ldns_rr_new();
    ldns_rr_set_type(dnskey, LDNS_RR_TYPE_DNSKEY);

    ldns_rr_set_owner(dnskey, ldns_rdf_clone(sign_params->owner));

    ldns_rr_push_rdf(dnskey,
            ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16,
                sign_params->flags));
    ldns_rr_push_rdf(dnskey,
                     ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8,
                                          LDNS_DNSSEC_KEYPROTO));
    ldns_rr_push_rdf(dnskey,
                     ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG,
                                          sign_params->algorithm));

    ldns_rr_push_rdf(dnskey, hsm_get_key_rdata(session, key));

    return dnskey;
}

int
hsm_random_buffer(const hsm_ctx_t *ctx,
                  unsigned char *buffer,
                  unsigned long length)
{
    CK_RV rv;
    unsigned int i;
    hsm_session_t *session;
    if (!buffer) return -1;
    if (!ctx) ctx = _hsm_ctx;

    /* just try every attached token. If one errors (be it NO_RNG, or
     * any other error, simply try the next */
    for (i = 0; i < ctx->session_count; i++) {
        session = ctx->session[i];
        if (session) {
            rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GenerateRandom(
                                         session->session,
                                         buffer,
                                         length);
            if (rv == CKR_OK) {
                return 0;
            }
        }
    }
    return 1;
}

uint32_t
hsm_random32(const hsm_ctx_t *ctx)
{
    uint32_t rnd;
    int result;
    unsigned char rnd_buf[4];
    result = hsm_random_buffer(ctx, rnd_buf, 4);
    if (result == 0) {
        memcpy(&rnd, rnd_buf, 4);
        return rnd;
    } else {
        return 0;
    }
}

uint64_t
hsm_random64(const hsm_ctx_t *ctx)
{
    uint64_t rnd;
    int result;
    unsigned char rnd_buf[8];
    result = hsm_random_buffer(ctx, rnd_buf, 8);
    if (result == 0) {
        memcpy(&rnd, rnd_buf, 8);
        return rnd;
    } else {
        return 0;
    }
}


/*
 * Additional functions
 */

int hsm_attach(char *repository,
               char *token_label,
               char *path,
               char *pin)
{
    hsm_session_t *session;
    int result;

    result = hsm_session_init(&session,
                              repository,
                              token_label,
                              path,
                              pin);
    if (result == HSM_OK) {
        return hsm_ctx_add_session(_hsm_ctx, session);
    } else {
        return result;
    }
}

/*! Detach a named HSM */
int hsm_detach(const char *repository)
{
    unsigned int i;
    for (i = 0; i < _hsm_ctx->session_count; i++) {
        if (_hsm_ctx->session[i] &&
            strcmp(_hsm_ctx->session[i]->module->name,
                   repository) == 0) {
            hsm_session_close(_hsm_ctx->session[i], 1);
            _hsm_ctx->session[i] = NULL;
            /* if this was the last session in the list, decrease the
             * session count */
            if (i == _hsm_ctx->session_count) {
                while(_hsm_ctx->session_count > 0 &&
                      !_hsm_ctx->session[i]) {
                    _hsm_ctx->session_count--;
                }
            }
            return 0;
        }
    }
    return -1;
}

int
hsm_token_attached(const hsm_ctx_t *ctx, const char *repository)
{
    unsigned int i;
    if (!ctx) ctx = _hsm_ctx;
    for (i = 0; i < ctx->session_count; i++) {
        if (ctx->session[i] &&
            strcmp(ctx->session[i]->module->name, repository) == 0) {
                return 1;
        }
    }
    return 0;
}

void
hsm_print_session(hsm_session_t *session)
{
    printf("\t\tmodule at %p (sym %p)\n", (void *) session->module, (void *) session->module->sym);
    printf("\t\trepository name: %s\n", session->module->name);
    printf("\t\ttoken label: %s\n", session->module->token_label);
    printf("\t\tsess handle: %u\n", (unsigned int) session->session);
}

void
hsm_print_ctx(hsm_ctx_t *gctx) {
    hsm_ctx_t *ctx;
    unsigned int i;
    if (!gctx) {
        ctx = _hsm_ctx;
    } else {
        ctx = gctx;
    }
    printf("CTX Sessions: %u\n", ctx->session_count);
    for (i = 0; i < ctx->session_count; i++) {
        printf("\tSession at %p\n", (void *) ctx->session[i]);
        hsm_print_session(ctx->session[i]);
    }
}

void
hsm_print_key(hsm_key_t *key) {
    char *id;
    if (key) {
        id = hsm_get_key_id(NULL, key);
        printf("key:\n");
        printf("\tmodule: %p\n", (void *) key->module);
        printf("\tprivkey handle: %u\n", (unsigned int) key->private_key);
        printf("\tpubkey handle: %u\n", (unsigned int) key->public_key);
        printf("\tid: %s\n", id);
	if (id) free(id);
    } else {
        printf("key: <void>\n");
    }
}

