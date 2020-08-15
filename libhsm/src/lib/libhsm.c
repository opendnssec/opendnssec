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
#include <ldns/ldns.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

#include "libhsm.h"
#include "libhsmdns.h"
#include "compat.h"
#include "duration.h"

#include <pkcs11.h>
#include <pthread.h>

/*! Fixed length from PKCS#11 specification */
#define HSM_TOKEN_LABEL_LENGTH 32

/*! Global (initial) context, with mutex to serialize access to it */
hsm_ctx_t *_hsm_ctx;
pthread_mutex_t _hsm_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

/*! General PKCS11 helper functions */
static char const *
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
        case CKR_FUNCTION_NOT_SUPPORTED:
            return "CKR_FUNCTION_NOT_SUPPORTED";
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
        /*CKR_VENDOR_DEFINED is not a constant but a macro which expands in to an */
        /*expression. Which we are not allowed to use in a switch.*/
        /*case CKR_VENDOR_DEFINED:*/
        case 0x80000000:
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

void
hsm_ctx_set_error(hsm_ctx_t *ctx, int error, const char *action,
                 const char *message, ...)
{
    va_list args;

    if (ctx && ctx->error == 0) {
        ctx->error = error;
        ctx->error_action = action;

        va_start(args, message);
        vsnprintf(ctx->error_message, sizeof(ctx->error_message),
            message, args);
        va_end(args);
    }
}

/*! Check HSM Context for Error

If the rv is not CKR_OK, and there is not previous error registered in
the context, to set the context error based on PKCS#11 return value.

\param ctx      HSM context
\param rv       PKCS#11 return value
\param action   action for which the error occured
\param message  error message format string
\return         0 if rv == CKR_OK, otherwise 1
*/
static int
hsm_pkcs11_check_error(hsm_ctx_t *ctx, CK_RV rv, const char *action)
{
    if (rv != CKR_OK) {
        if (ctx && ctx->error == 0) {
            ctx->error = (int) rv;
            ctx->error_action = action;
            strlcpy(ctx->error_message, ldns_pkcs11_rv_str(rv), sizeof(ctx->error_message));
        }
        return 1;
    }
    return 0;
}

/*! Unload PKCS#11 provider */
static void
hsm_pkcs11_unload_functions(void *handle)
{
    if (handle) {
#if defined(HAVE_LOADLIBRARY)
        /* no idea */
#elif defined(HAVE_DLOPEN)
        (void) dlclose(handle);
#endif
    }
}

/*! Load PKCS#11 provider */
static CK_RV
hsm_pkcs11_load_functions(hsm_module_t *module)
{
    CK_C_GetFunctionList pGetFunctionList = NULL;

    if (module && module->path) {
        /* library provided by application or user */

#if defined(HAVE_LOADLIBRARY)
        /* Load PKCS #11 library */
        HINSTANCE hDLL = LoadLibrary(_T(module->path));

        if (hDLL == NULL) {
            /* Failed to load the PKCS #11 library */
            return CKR_FUNCTION_FAILED;
        }

        /* Retrieve the entry point for C_GetFunctionList */
        pGetFunctionList = (CK_C_GetFunctionList)
            GetProcAddress(hDLL, _T("C_GetFunctionList"));

#elif defined(HAVE_DLOPEN)
        /* Load PKCS #11 library */
        void* pDynLib = dlopen(module->path, RTLD_NOW | RTLD_LOCAL);

        if (pDynLib == NULL) {
            /* Failed to load the PKCS #11 library */
            return CKR_FUNCTION_FAILED;
        }

        /* Retrieve the entry point for C_GetFunctionList */
        pGetFunctionList = (CK_C_GetFunctionList) dlsym(pDynLib, "C_GetFunctionList");
        /* Store the handle so we can dlclose it later */
        module->handle = pDynLib;

#else
        return CKR_FUNCTION_FAILED;
#endif
    } else {
        /* No library provided, use the statically compiled softHSM */
#ifdef HAVE_PKCS11_MODULE
        return C_GetFunctionList(pkcs11_functions);
#else
        return CKR_FUNCTION_FAILED;
#endif
    }

    if (pGetFunctionList == NULL) {
        /* Failed to load the PKCS #11 library */
        return CKR_FUNCTION_FAILED;
    }

    /* Retrieve the function list */
    (pGetFunctionList)((CK_FUNCTION_LIST_PTR_PTR)(&module->sym));
    return CKR_OK;
}

static void
hsm_remove_leading_zeroes(CK_BYTE_PTR data, CK_ULONG *len)
{
    CK_BYTE_PTR p = data;
    CK_ULONG l;

    if (data == NULL || len == NULL) return;

    l = *len;

    while ((unsigned short int)(*p) == 0 && l > 1) {
        p++;
        l--;
    }

    if (p != data) {
        memmove(data, p, l);
        *len = l;
    }
}

static int
hsm_pkcs11_check_token_name(hsm_ctx_t *ctx,
                            CK_FUNCTION_LIST_PTR pkcs11_functions,
                            CK_SLOT_ID slotId,
                            const char *token_name)
{
    /* token label is always 32 bytes */
    char token_name_bytes[HSM_TOKEN_LABEL_LENGTH];
    int result = 0;
    CK_RV rv;
    CK_TOKEN_INFO token_info;

    rv = pkcs11_functions->C_GetTokenInfo(slotId, &token_info);
    if (hsm_pkcs11_check_error(ctx, rv, "C_GetTokenInfo")) {
        return 0;
    }

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

hsm_repository_t *
hsm_repository_new(char* name, char* module, char* tokenlabel, char* pin,
    uint8_t use_pubkey, uint8_t allowextract, uint8_t require_backup)
{
    hsm_repository_t* r;

    if (!name || !module || !tokenlabel) return NULL;

    r = malloc(sizeof(hsm_repository_t));
    if (!r) return NULL;

    r->next = NULL;
    r->pin = NULL;
    r->name = strdup(name);
    r->module = strdup(module);
    r->tokenlabel = strdup(tokenlabel);
    if (!r->name || !r->module || !r->tokenlabel) {
        hsm_repository_free(r);
        return NULL;
    }
    if (pin) {
        r->pin = strdup(pin);
        if (!r->pin) {
            hsm_repository_free(r);
            return NULL;
        }
    }
    r->use_pubkey = use_pubkey;
    r->allow_extract = allowextract; 
    r->require_backup = require_backup;
    return r;
}

void
hsm_repository_free(hsm_repository_t *r)
{
    if (r) {
        if (r->next) hsm_repository_free(r->next);
        if (r->name) free(r->name);
        if (r->module) free(r->module);
        if (r->tokenlabel) free(r->tokenlabel);
        if (r->pin) free(r->pin);
    }
    free(r);
}

static int
hsm_get_slot_id(hsm_ctx_t *ctx,
                CK_FUNCTION_LIST_PTR pkcs11_functions,
                const char *token_name, CK_SLOT_ID *slotId)
{
    CK_RV rv;
    CK_ULONG slotCount;
    CK_SLOT_ID cur_slot;
    CK_SLOT_ID *slotIds;
    int found = 0;

    if (token_name == NULL || slotId == NULL) return HSM_ERROR;

    rv = pkcs11_functions->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
    if (hsm_pkcs11_check_error(ctx, rv, "get slot list")) {
        return HSM_ERROR;
    }

    if (slotCount < 1) {
        hsm_ctx_set_error(ctx, HSM_ERROR, "hsm_get_slot_id()",
                          "No slots found in HSM");
        return HSM_ERROR;
    } else if (slotCount > (SIZE_MAX / sizeof(CK_SLOT_ID))) {
        hsm_ctx_set_error(ctx, HSM_ERROR, "hsm_get_slot_id()",
                          "Too many slots found in HSM");
        return HSM_ERROR;
    }

    slotIds = malloc(sizeof(CK_SLOT_ID) * slotCount);
    if(slotIds == NULL) {
        hsm_ctx_set_error(ctx, HSM_ERROR, "hsm_get_slot_id()",
                          "Could not allocate slot ID table");
        return HSM_ERROR;
    }

    rv = pkcs11_functions->C_GetSlotList(CK_TRUE, slotIds, &slotCount);
    if (hsm_pkcs11_check_error(ctx, rv, "get slot list")) {
        return HSM_ERROR;
    }

    for (cur_slot = 0; cur_slot < slotCount; cur_slot++) {
        if (hsm_pkcs11_check_token_name(ctx,
                                        pkcs11_functions,
                                        slotIds[cur_slot],
                                        token_name)) {
            *slotId = slotIds[cur_slot];
            found = 1;
            break;
        }
    }
    free(slotIds);
    if (!found) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_slot_id()",
            "could not find token with the name %s", token_name);
        return HSM_ERROR;
    }

    return HSM_OK;
}

/* internal functions */
static hsm_module_t *
hsm_module_new(const char *repository,
               const char *token_label,
               const char *path,
               const hsm_config_t *config)
{
    hsm_module_t *module;

    if (!repository || !path) return NULL;

    
    module = malloc(sizeof(hsm_module_t));
    if (!module) return NULL;

    if (config) {
        module->config = malloc(sizeof(hsm_config_t));
        if (!module->config) {
            free(module);
            return NULL;
        }
        memcpy(module->config, config, sizeof(hsm_config_t));
    } else {
        module->config = NULL;
    }

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
        if (module->config) free(module->config);

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

/*! Set default HSM configuration */
static void
hsm_config_default(hsm_config_t *config)
{
    config->use_pubkey = 1;
    config->allow_extract = 0;
}

/* creates a session_t structure, and automatically adds and initializes
 * a module_t struct for it
 */
static int
hsm_session_init(hsm_ctx_t *ctx, hsm_session_t **session,
                 const char *repository, const char *token_label,
                 const char *module_path, const char *pin,
                 const hsm_config_t *config)
{
    CK_RV rv;
    CK_RV rv_login;
    hsm_module_t *module;
    CK_SLOT_ID slot_id;
    CK_SESSION_HANDLE session_handle;
    int first = 1, result;

    CK_C_INITIALIZE_ARGS InitArgs = {NULL, NULL, NULL, NULL,
                                     CKF_OS_LOCKING_OK, NULL };

    if (pin == NULL) return HSM_ERROR;

    module = hsm_module_new(repository, token_label, module_path, config);
    if (!module) return HSM_ERROR;
    rv = hsm_pkcs11_load_functions(module);
    if (rv != CKR_OK) {
        hsm_ctx_set_error(ctx, HSM_MODULE_NOT_FOUND,
	    "hsm_session_init()",
	    "PKCS#11 module load failed: %s", module_path);
        hsm_module_free(module);
        return HSM_MODULE_NOT_FOUND;
    }
    rv = ((CK_FUNCTION_LIST_PTR) module->sym)->C_Initialize((CK_VOID_PTR) &InitArgs);
    /* ALREADY_INITIALIZED is ok, apparently we are using a second
     * device with the same library */
    if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        if (hsm_pkcs11_check_error(ctx, rv, "Initialization")) {
            hsm_module_free(module);
            return HSM_ERROR;
        }
    } else {
        first = 0;
    }
    result = hsm_get_slot_id(ctx, module->sym, token_label, &slot_id);
    if (result != HSM_OK) {
        hsm_module_free(module);
        return HSM_ERROR;
    }
    rv = ((CK_FUNCTION_LIST_PTR) module->sym)->C_OpenSession(slot_id,
                               CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL,
                               NULL,
                               &session_handle);
    if (hsm_pkcs11_check_error(ctx, rv, "Open first session")) {
        hsm_module_free(module);
        return HSM_ERROR;
    }
    rv_login = ((CK_FUNCTION_LIST_PTR) module->sym)->C_Login(session_handle,
                                   CKU_USER,
                                   (unsigned char *) pin,
                                   strlen((char *)pin));

    if (rv_login == CKR_OK) {
        *session = hsm_session_new(module, session_handle);
        return HSM_OK;
    } else {
        /* uninitialize the session again */
        if (session_handle) {
            rv = ((CK_FUNCTION_LIST_PTR) module->sym)->
                   C_CloseSession(session_handle);
            if (hsm_pkcs11_check_error(ctx, rv,
                "finalize after failed login")) {
                hsm_module_free(module);
                return HSM_ERROR;
            }
        }
        /* if this was not the first, don't close the library for
         * the rest of us */
        if (first) {
            rv = ((CK_FUNCTION_LIST_PTR) module->sym)->C_Finalize(NULL);
            if (hsm_pkcs11_check_error(ctx, rv, "finalize after failed login")) {
                hsm_module_free(module);
                return HSM_ERROR;
            }
        }
        hsm_module_free(module);
        *session = NULL;
        switch(rv_login) {
        case CKR_PIN_INCORRECT:
            hsm_ctx_set_error(ctx, HSM_PIN_INCORRECT,
	            "hsm_session_init()",
		    "Incorrect PIN for repository %s", repository);
            return HSM_PIN_INCORRECT;
        default:
            return HSM_ERROR;
        }
    }
}

/* open a second session from the given one */
static hsm_session_t *
hsm_session_clone(hsm_ctx_t *ctx, hsm_session_t *session)
{
    CK_RV rv;
    CK_SLOT_ID slot_id;
    CK_SESSION_HANDLE session_handle;
    hsm_session_t *new_session;
    int result;

    result = hsm_get_slot_id(ctx,
                              session->module->sym,
                              session->module->token_label,
                              &slot_id);
    if (result != HSM_OK) return NULL;
    rv = ((CK_FUNCTION_LIST_PTR) session->module->sym)->C_OpenSession(slot_id,
                                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                    NULL,
                                    NULL,
                                    &session_handle);

    if (hsm_pkcs11_check_error(ctx, rv, "Clone session")) {
        return NULL;
    }
    new_session = hsm_session_new(session->module, session_handle);

    return new_session;
}

static hsm_ctx_t *
hsm_ctx_new()
{
    hsm_ctx_t *ctx;
    ctx = malloc(sizeof(hsm_ctx_t));
    if (ctx) {
        memset(ctx->session, 0, sizeof(ctx->session));
        ctx->session_count = 0;
        ctx->error = 0;
    }
    return ctx;
}

/* ctx_free frees the structure */
static void
hsm_ctx_free(hsm_ctx_t *ctx)
{
    unsigned int i;

    if (ctx) {
        for (i = 0; i < ctx->session_count; i++) {
            hsm_session_free(ctx->session[i]);
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
hsm_session_close(hsm_ctx_t *ctx, hsm_session_t *session, int unload)
{
    /* If we loaded this library more than once, we may have
     * already finalized it before, so we can safely ignore
     * NOT_INITIALIZED */
    CK_RV rv;
    if (unload) {
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_Logout(session->session);
        if (rv != CKR_CRYPTOKI_NOT_INITIALIZED) {
            (void) hsm_pkcs11_check_error(ctx, rv, "Logout");
        }
    }
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_CloseSession(session->session);
    if (rv != CKR_CRYPTOKI_NOT_INITIALIZED) {
        (void) hsm_pkcs11_check_error(ctx, rv, "Close session");
    }
    if (unload) {
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_Finalize(NULL);
        if (rv != CKR_CRYPTOKI_NOT_INITIALIZED) {
            (void) hsm_pkcs11_check_error(ctx, rv, "Finalize");
            hsm_pkcs11_unload_functions(session->module->handle);
        }
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
    size_t i;

    if (!ctx) return;
    for (i = 0; i < ctx->session_count; i++) {
        hsm_session_close(ctx, ctx->session[i], unload);
        ctx->session[i] = NULL;
    }
    hsm_ctx_free(ctx);

}


/* adds a session to the context.
 * returns  0 on success
 *          1 if the maximum number of sessions (HSM_MAX_SESSIONS) was
 *            reached
 *          -1 if one of the arguments is NULL
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
            new_session = hsm_session_clone(ctx, ctx->session[i]);
            if (!new_session) {
                /* one of the sessions failed to clone. Clear the
                 * new ctx and return NULL */
                hsm_ctx_close(new_ctx, 0);
                return NULL;
            }
            hsm_ctx_add_session(new_ctx, new_session);
        }
        new_ctx->keycache = ctx->keycache;
        new_ctx->keycache_lock = ctx->keycache_lock;
    }
    return new_ctx;
}

static libhsm_key_t *
libhsm_key_new()
{
    libhsm_key_t *key;
    key = malloc(sizeof(libhsm_key_t));
    key->modulename = NULL;
    key->private_key = 0;
    key->public_key = 0;
    return key;
}

/* find the session belonging to a key, by iterating over the modules
 * in the context */
static hsm_session_t *
hsm_find_key_session(hsm_ctx_t *ctx, const libhsm_key_t *key)
{
    unsigned int i;
    if (!key || !key->modulename) return NULL;
    for (i = 0; i < ctx->session_count; i++) {
        if (ctx->session[i] && !strcmp(ctx->session[i]->module->name, key->modulename)) {
            return ctx->session[i];
        }
    }
    return NULL;
}

/* Returns the key type (algorithm) of the given key */
static CK_KEY_TYPE
hsm_get_key_algorithm(hsm_ctx_t *ctx, const hsm_session_t *session,
                      const libhsm_key_t *key)
{
    CK_RV rv;
    CK_KEY_TYPE key_type;

    CK_ATTRIBUTE template[] = {
        {CKA_KEY_TYPE, &key_type, sizeof(CK_KEY_TYPE)}
    };

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->private_key,
                                      template,
                                      1);
    if (hsm_pkcs11_check_error(ctx, rv,
                               "Get attr value algorithm type")) {
        /* this is actually not a good return value;
         * CKK_RSA is also 0. But we can't return a negative
         * value. Should we #define a specific 'key type' that
         * indicates an error? (TODO) */
        return 0;
    }

    if ((CK_LONG)template[0].ulValueLen < 1) {
        /* this is actually not a good return value;
         * CKK_RSA is also 0. But we can't return a negative
         * value. Should we #define a specific 'key type' that
         * indicates an error? (TODO) */
        return 0;
    }

    return key_type;
}

/* returns a CK_ULONG with the key size of the given RSA key. The
 * key is not checked for type. For RSA, the number of bits in the
 * modulus is the key size (CKA_MODULUS_BITS)
 */
static CK_ULONG
hsm_get_key_size_rsa(hsm_ctx_t *ctx, const hsm_session_t *session,
                     const libhsm_key_t *key)
{
    CK_RV rv;
    CK_ULONG modulus_bits;

    /* Template for public keys */
    CK_ATTRIBUTE template[] = {
        {CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_KEY_TYPE)}
    };

    /* Template for private keys */
    CK_BYTE_PTR modulus = NULL;
    int mask;
    CK_ATTRIBUTE template2[] = {
        {CKA_MODULUS, NULL, 0}
    };

    if (key->public_key) {
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                          session->session,
                                          key->public_key,
                                          template,
                                          1);
        if (hsm_pkcs11_check_error(ctx, rv,
                                   "Get attr value algorithm type")) {
            return 0;
        }

        if ((CK_ULONG)template[0].ulValueLen < 1) {
            return 0;
        }
    } else {
        // Get buffer size
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                          session->session,
                                          key->private_key,
                                          template2,
                                          1);
        if (hsm_pkcs11_check_error(ctx, rv, "Could not get the size of the modulus of the private key")) {
            return 0;
        }

        // Allocate memory
        modulus = (CK_BYTE_PTR)malloc(template2[0].ulValueLen);
        template2[0].pValue = modulus;
        if (modulus == NULL) {
            hsm_ctx_set_error(ctx, -1, "hsm_get_key_size_rsa()",
                "Error allocating memory for modulus");
            return 0;
        }

        // Get attribute
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                          session->session,
                                          key->private_key,
                                          template2,
                                          1);
        if (hsm_pkcs11_check_error(ctx, rv, "Could not get the modulus of the private key")) {
            free(modulus);
            return 0;
        }

	// Calculate size
        modulus_bits = template2[0].ulValueLen * 8;
        mask = 0x80;
        for (int i = 0; modulus_bits && (modulus[i] & mask) == 0; modulus_bits--) {
            mask >>= 1;
            if (mask == 0) {
                i++;
                mask = 0x80;
            }
        }
        free(modulus);
    }

    return modulus_bits;
}

/* returns a CK_ULONG with the key size of the given DSA key. The
 * key is not checked for type. For DSA, the number of bits in the
 * prime is the key size (CKA_PRIME)
 */
static CK_ULONG
hsm_get_key_size_dsa(hsm_ctx_t *ctx, const hsm_session_t *session,
                     const libhsm_key_t *key)
{
    CK_RV rv;

    /* Template */
    CK_ATTRIBUTE template2[] = {
        {CKA_PRIME, NULL, 0}
    };

    // Get buffer size
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->private_key,
                                      template2,
                                      1);
    if (hsm_pkcs11_check_error(ctx, rv, "Could not get the size of the prime of the private key")) {
        return 0;
    }

    return template2[0].ulValueLen * 8;
}

/* Returns the DER decoded value of Q for ECDSA key
 * Byte string with uncompressed form of a curve point, "x | y"
 */
static unsigned char *
hsm_get_key_ecdsa_value(hsm_ctx_t *ctx, const hsm_session_t *session,
                     const libhsm_key_t *key, CK_ULONG *data_len)
{
    CK_RV rv;
    CK_BYTE_PTR value = NULL;
    CK_BYTE_PTR data = NULL;
    CK_ULONG value_len = 0;
    CK_ULONG header_len = 0;

    CK_ATTRIBUTE template[] = {
        {CKA_EC_POINT, NULL, 0},
    };

    if (!session || !session->module || !key || !data_len) {
        return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->public_key,
                                      template,
                                      1);
    if (hsm_pkcs11_check_error(ctx, rv, "C_GetAttributeValue")) {
        return NULL;
    }
    value_len = template[0].ulValueLen;

    value = template[0].pValue = malloc(value_len);
    if (!value) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_ecdsa_value()",
            "Error allocating memory for value");
        return NULL;
    }
    memset(value, 0, value_len);

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->public_key,
                                      template,
                                      1);
    if (hsm_pkcs11_check_error(ctx, rv, "get attribute value")) {
        free(value);
        return NULL;
    }

    if(value_len != template[0].ulValueLen) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_ecdsa_value()",
           "HSM returned two different length for a same CKA_EC_POINT. " \
            "Abnormal behaviour detected.");
        free(value);
        return NULL;
    }

    /* Check that we have the first two octets */
    if (value_len < 2) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_ecdsa_value()",
            "The DER value is too short");
        free(value);
        return NULL;
    }

    /* Check the identifier octet, PKCS#11 requires octet string */
    if (value[0] != 0x04) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_ecdsa_value()",
            "Invalid identifier octet in the DER value");
        free(value);
        return NULL;
    }
    header_len++;

    /* Check the length octets, but we do not validate the length */
    if (value[1] <= 0x7F) {
        header_len++;
    } else if (value[1] == 0x80) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_ecdsa_value()",
            "Indefinite length is not supported in DER values");
        free(value);
        return NULL;
    } else {
        header_len++;
        header_len += value[1] & 0x80;
    }

    /* Check that we have more data than the header */
    if (value_len - header_len < 2) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_ecdsa_value()",
            "The value is too short");
        free(value);
        return NULL;
    }

    /* Check that we have uncompressed data */
    /* TODO: Not supporting compressed data */
    if (value[header_len] != 0x04) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_ecdsa_value()",
            "The value is not uncompressed");
        free(value);
        return NULL;
    }
    header_len++;

    *data_len = value_len - header_len;
    data = malloc(*data_len);
    if (data == NULL) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_ecdsa_value()",
            "Error allocating memory for data");
        free(value);
        return NULL;
    }

    memcpy(data, value + header_len, *data_len);
    free(value);

    return data;
}

/* returns a CK_ULONG with the key size of the given ECDSA key. The
 * key is not checked for type. For ECDSA, the number of bits in the
 * value X is the key size
 */
static CK_ULONG
hsm_get_key_size_ecdsa(hsm_ctx_t *ctx, const hsm_session_t *session,
                     const libhsm_key_t *key)
{
    CK_ULONG value_len;
    unsigned char* value = hsm_get_key_ecdsa_value(ctx, session, key, &value_len);
    CK_ULONG bits = 0;

    if (value == NULL) return 0;

    if( ((CK_ULONG) - 1) / (8/2) < value_len) {
	    free(value);
	    return 0;
    }

    /* value = x | y */
    bits = value_len * 8 / 2;
    free(value);

    return bits;
}

/* Returns the DER decoded value of the EDDSA public key
 * Byte string with b-bit public key in little endian order
 */
static unsigned char *
hsm_get_key_eddsa_value(hsm_ctx_t *ctx, const hsm_session_t *session,
                     const libhsm_key_t *key, CK_ULONG *data_len)
{
    CK_RV rv;
    CK_BYTE_PTR value = NULL;
    CK_BYTE_PTR data = NULL;
    CK_ULONG value_len = 0;
    CK_ULONG header_len = 0;

    CK_ATTRIBUTE template[] = {
        {CKA_EC_POINT, NULL, 0},
    };

    if (!session || !session->module || !key || !data_len) {
        return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->public_key,
                                      template,
                                      1);
    if (hsm_pkcs11_check_error(ctx, rv, "C_GetAttributeValue")) {
        return NULL;
    }
    value_len = template[0].ulValueLen;

    value = template[0].pValue = malloc(value_len);
    if (!value) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_eddsa_value()",
            "Error allocating memory for value");
        return NULL;
    }
    memset(value, 0, value_len);

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->public_key,
                                      template,
                                      1);
    if (hsm_pkcs11_check_error(ctx, rv, "get attribute value")) {
        free(value);
        return NULL;
    }

    if(value_len != template[0].ulValueLen) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_eddsa_value()",
           "HSM returned two different length for the same CKA_EC_POINT. " \
            "Abnormal behaviour detected.");
        free(value);
        return NULL;
    }

    /* Check that we have the first two octets */
    if (value_len < 2) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_eddsa_value()",
            "The DER value is too short");
        free(value);
        return NULL;
    }

    /* Check the identifier octet, PKCS#11 requires octet string */
    if (value[0] != 0x04) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_eddsa_value()",
            "Invalid identifier octet in the DER value");
        free(value);
        return NULL;
    }
    header_len++;

    /* Check the length octets, but we do not validate the length */
    if (value[1] <= 0x7F) {
        header_len++;
    } else if (value[1] == 0x80) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_eddsa_value()",
            "Indefinite length is not supported in DER values");
        free(value);
        return NULL;
    } else {
        header_len++;
        header_len += value[1] & 0x80;
    }

    /* Check that we have more data than the header */
    if (value_len - header_len < 2) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_eddsa_value()",
            "The value is too short");
        free(value);
        return NULL;
    }

    *data_len = value_len - header_len;
    data = malloc(*data_len);
    if (data == NULL) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_eddsa_value()",
            "Error allocating memory for data");
        free(value);
        return NULL;
    }

    memcpy(data, value + header_len, *data_len);
    free(value);

    return data;
}

/* returns a CK_ULONG with the key size of the given EDDSA key. The
 * key is not checked for type. For EDDSA, the key size is the number
 * of bits in the curve not the size of the public key representation,
 * which is larger.
 */
static CK_ULONG
hsm_get_key_size_eddsa(hsm_ctx_t *ctx, const hsm_session_t *session,
                     const libhsm_key_t *key)
{
    CK_ULONG value_len;
    unsigned char* value = hsm_get_key_eddsa_value(ctx, session, key, &value_len);
    CK_ULONG bits = 0;

    if (value == NULL) return 0;

    if( ((CK_ULONG) - 1) / 8 < value_len) {
        free(value);
        return 0;
    }

    bits = value_len * 8;
    free(value);

    switch (bits) {
        // ED25519 keys are 255 bits represented as 256 bits (RFC8080 section 3)
        case 256:
            bits = 255;
            break;
        // ED448 keys are 448 bits represented as 456 bits (RFC8080 section 3)
        case 456:
            bits = 448;
            break;
        default:
            bits = 0;
            break;
    }

    return bits;
}

/* Wrapper for specific key size functions */
static CK_ULONG
hsm_get_key_size(hsm_ctx_t *ctx, const hsm_session_t *session,
                 const libhsm_key_t *key, const unsigned long algorithm)
{
    switch (algorithm) {
        case CKK_RSA:
            return hsm_get_key_size_rsa(ctx, session, key);
            break;
        case CKK_DSA:
            return hsm_get_key_size_dsa(ctx, session, key);
            break;
        case CKK_GOSTR3410:
            /* GOST public keys always have a size of 512 bits */
            return 512;
        case CKK_EC:
            return hsm_get_key_size_ecdsa(ctx, session, key);
        case CKK_EC_EDWARDS:
            return hsm_get_key_size_eddsa(ctx, session, key);
        default:
            return 0;
    }
}

static CK_OBJECT_HANDLE
hsm_find_object_handle_for_id(hsm_ctx_t *ctx,
                              const hsm_session_t *session,
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
    if (hsm_pkcs11_check_error(ctx, rv, "Find objects init")) {
        return 0;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjects(session->session,
                                         &object,
                                         1,
                                         &objectCount);
    if (hsm_pkcs11_check_error(ctx, rv, "Find object")) {
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjectsFinal(session->session);
        hsm_pkcs11_check_error(ctx, rv, "Find objects cleanup");
        return 0;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjectsFinal(session->session);
    if (hsm_pkcs11_check_error(ctx, rv, "Find object final")) {
        return 0;
    }

    if (objectCount > 0) {
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
hsm_hex_parse(const char *hex, size_t *len)
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

/* put a hexadecimal representation of the data from src into dst
 * len is the number of bytes to read from src
 * dst must have allocated enough space (len*2 + 1)
 */
static void
hsm_hex_unparse(char *dst, const unsigned char *src, size_t len)
{
    size_t dst_len = len*2 + 1;
    size_t i;

    for (i = 0; i < len; i++) {
        snprintf(dst + (2*i), dst_len, "%02x", src[i]);
    }
    dst[len*2] = '\0';
}

/* returns an allocated byte array with the CKA_ID for the given object
 * len will contain the result size
 * returns NULL and size zero if not found in this session
 */
static CK_BYTE *
hsm_get_id_for_object(hsm_ctx_t *ctx,
                      const hsm_session_t *session,
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
    if (hsm_pkcs11_check_error(ctx, rv, "Get attr value")) {
        *len = 0;
        return NULL;
    }

    if ((CK_LONG)template[0].ulValueLen < 1) {
        /* No CKA_ID found, return NULL */
        *len = 0;
        return NULL;
    }

    template[0].pValue = malloc(template[0].ulValueLen);
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      object,
                                      template,
                                      1);
    if (hsm_pkcs11_check_error(ctx, rv, "Get attr value 2")) {
        *len = 0;
        free(template[0].pValue);
        return NULL;
    }

    *len = template[0].ulValueLen;
    return template[0].pValue;
}

/* returns an libhsm_key_t object for the given *private key* object handle
 * the module, private key, and public key handle are set
 * The session needs to be free to perform a search for the public key
 */
static libhsm_key_t *
libhsm_key_new_privkey_object_handle(hsm_ctx_t *ctx,
                                  const hsm_session_t *session,
                                  CK_OBJECT_HANDLE object)
{
    libhsm_key_t *key;
    CK_BYTE *id;
    size_t len;

    id = hsm_get_id_for_object(ctx, session, object, &len);

    if (!id) return NULL;

    key = libhsm_key_new();
    key->modulename = strdup(session->module->name);
    key->private_key = object;

    key->public_key = hsm_find_object_handle_for_id(
                          ctx,
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
 * (on error, the count will also be zero and NULL returned)
 */
static libhsm_key_t **
hsm_list_keys_session_internal(hsm_ctx_t *ctx,
                               const hsm_session_t *session,
                               size_t *count,
                               int store)
{
    libhsm_key_t **keys = NULL;
    libhsm_key_t *key;
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
    CK_OBJECT_HANDLE *key_handles = NULL, *new_key_handles = NULL;
  

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjectsInit(session->session,
                                                 template, 1);
    if (hsm_pkcs11_check_error(ctx, rv, "Find objects init")) {
        goto err;
    }

    j = 0;
    while (objectCount > 0) {
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjects(session->session,
                                                 object,
                                                 max_object_count,
                                                 &objectCount);
        if (hsm_pkcs11_check_error(ctx, rv, "Find first object")) {
            rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjectsFinal(session->session);
            hsm_pkcs11_check_error(ctx, rv, "Find objects cleanup");
            goto err;
        }

        total_count += objectCount;
        if (objectCount > 0 && store) {
            if (SIZE_MAX / sizeof(CK_OBJECT_HANDLE) < total_count) {
                hsm_ctx_set_error(ctx, -1, "hsm_list_keys_session_internal",
                    "Too much object handle returned by HSM to allocate key_handles");
                goto err;
            }

            new_key_handles = realloc(key_handles, total_count * sizeof(CK_OBJECT_HANDLE));
            if (new_key_handles != NULL) {
                key_handles = new_key_handles;
            } else {
                hsm_ctx_set_error(ctx, -1, "hsm_list_keys_session_internal",
                    "Error allocating memory for object handle (OOM)");
                goto err;
            }

            for (i = 0; i < objectCount; i++) {
                key_handles[j] = object[i];
                j++;
            }
        }
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_FindObjectsFinal(session->session);
    if (hsm_pkcs11_check_error(ctx, rv, "Find objects final")) {
        goto err;
    }

    if (store) {
        if(SIZE_MAX / sizeof(libhsm_key_t *) < total_count) {
                hsm_ctx_set_error(ctx, -1, "hsm_list_keys_session_internal",
                    "Too much object handle returned by HSM to allocate keys");
                goto err;
        } 

        keys = malloc(total_count * sizeof(libhsm_key_t *));
        if(keys == NULL) {
                hsm_ctx_set_error(ctx, -1, "hsm_list_keys_session_internal",
                    "Error allocating memory for keys table (OOM)");
                goto err;
        }

        for (i = 0; i < total_count; i++) {
            key = libhsm_key_new_privkey_object_handle(ctx, session,
                                                    key_handles[i]);
            if(!key) {
		    libhsm_key_list_free(keys, i);
		    goto err;
	    }
            keys[i] = key;
        }
    }
    free(key_handles);

    *count = total_count;
    return keys;

err:
    free(key_handles);
    *count = 0;
    return NULL;
}


/* returns an array of all keys available to the given session
 *
 * \param session the session to find the keys in
 * \param count this value will contain the number of keys found
 *
 * \return the list of keys
 */
static libhsm_key_t **
hsm_list_keys_session(hsm_ctx_t *ctx, const hsm_session_t *session,
                      size_t *count)
{
    return hsm_list_keys_session_internal(ctx, session, count, 1);
}

/* returns a newly allocated key structure containing the key data
 * for the given CKA_ID available in the session. Returns NULL if not
 * found
 */
static libhsm_key_t *
hsm_find_key_by_id_session(hsm_ctx_t *ctx, const hsm_session_t *session,
                           const unsigned char *id, size_t len)
{
    libhsm_key_t *key;
    CK_OBJECT_HANDLE private_key_handle;

    private_key_handle = hsm_find_object_handle_for_id(
                             ctx,
                             session,
                             CKO_PRIVATE_KEY,
                             (CK_BYTE *) id,
                             (CK_ULONG) len);
    if (private_key_handle != 0) {
        key = libhsm_key_new_privkey_object_handle(ctx, session,
                                                private_key_handle);
        return key;
    } else {
        return NULL;
    }
}

/* Find a key pair by CKA_ID (as byte array)

The returned key structure can be freed with free()

\param context HSM context
\param id CKA_ID of key to find (array of bytes)
\param len number of bytes in the id
\return key identifier or NULL if not found
*/
static libhsm_key_t *
hsm_find_key_by_id_bin(hsm_ctx_t *ctx,
                       const unsigned char *id,
                       size_t len)
{
    libhsm_key_t *key;
    unsigned int i;

    if (!id) return NULL;

    for (i = 0; i < ctx->session_count; i++) {
        key = hsm_find_key_by_id_session(ctx, ctx->session[i], id, len);
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
hsm_find_repository_session(hsm_ctx_t *ctx, const char *repository)
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

    hsm_ctx_set_error(ctx, HSM_REPOSITORY_NOT_FOUND,
                    "hsm_find_repository_session()",
                    "Can't find repository: %s", repository);

    return NULL;
}

static ldns_rdf *
hsm_get_key_rdata_rsa(hsm_ctx_t *ctx, hsm_session_t *session,
                  const libhsm_key_t *key)
{
    CK_RV rv;
    CK_BYTE_PTR public_exponent = NULL;
    CK_ULONG public_exponent_len = 0;
    CK_BYTE_PTR modulus = NULL;
    CK_ULONG modulus_len = 0;
    unsigned long hKey = 0;
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

    if (key->public_key) {
        hKey = key->public_key;
    } else {
        hKey = key->private_key;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      hKey,
                                      template,
                                      2);
    if (hsm_pkcs11_check_error(ctx, rv, "C_GetAttributeValue")) {
        return NULL;
    }
    public_exponent_len = template[0].ulValueLen;
    modulus_len = template[1].ulValueLen;

    public_exponent = template[0].pValue = malloc(public_exponent_len);
    if (!public_exponent) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_rsa()",
            "Error allocating memory for public exponent");
        return NULL;
    }

    modulus = template[1].pValue = malloc(modulus_len);
    if (!modulus) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_rsa()",
            "Error allocating memory for modulus");
        free(public_exponent);
        return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      hKey,
                                      template,
                                      2);
    if (hsm_pkcs11_check_error(ctx, rv, "get attribute value")) {
        free(template[0].pValue);
        free(template[1].pValue);
        return NULL;
    }

    // Remove leading zeroes
    hsm_remove_leading_zeroes(public_exponent, &public_exponent_len);
    hsm_remove_leading_zeroes(modulus, &modulus_len);

    data_size = public_exponent_len + modulus_len + 1;
    if (public_exponent_len <= 255) {
        data = malloc(data_size);
        if (!data) {
            hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_rsa()",
                "Error allocating memory for pub key rr data");
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
            hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_rsa()",
                "Error allocating memory for pub key rr data");
            free(public_exponent);
            free(modulus);
            return NULL;
        }
        data[0] = 0;
        ldns_write_uint16(&data[1], (uint16_t) public_exponent_len);
        memcpy(&data[3], public_exponent, public_exponent_len);
        memcpy(&data[3 + public_exponent_len], modulus, modulus_len);
    } else {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_rsa()",
            "Public exponent too big");
        free(public_exponent);
        free(modulus);
        return NULL;
    }
    rdf = ldns_rdf_new(LDNS_RDF_TYPE_B64, data_size, data);
    free(public_exponent);
    free(modulus);

    return rdf;
}

static ldns_rdf *
hsm_get_key_rdata_dsa(hsm_ctx_t *ctx, hsm_session_t *session,
                  const libhsm_key_t *key)
{
    CK_RV rv;
    CK_BYTE_PTR prime = NULL;
    CK_ULONG prime_len = 0;
    CK_BYTE_PTR subprime = NULL;
    CK_ULONG subprime_len = 0;
    CK_BYTE_PTR base = NULL;
    CK_ULONG base_len = 0;
    CK_BYTE_PTR value = NULL;
    CK_ULONG value_len = 0;
    unsigned char *data = NULL;
    size_t data_size = 0;

    CK_ATTRIBUTE template[] = {
        {CKA_PRIME, NULL, 0},
        {CKA_SUBPRIME, NULL, 0},
        {CKA_BASE, NULL, 0},
        {CKA_VALUE, NULL, 0},
    };
    ldns_rdf *rdf;

    if (!session || !session->module) {
        return NULL;
    }

    /* DSA needs the public key compared with RSA */
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->public_key,
                                      template,
                                      4);
    if (hsm_pkcs11_check_error(ctx, rv, "C_GetAttributeValue")) {
        return NULL;
    }
    prime_len = template[0].ulValueLen;
    subprime_len = template[1].ulValueLen;
    base_len = template[2].ulValueLen;
    value_len = template[3].ulValueLen;

    prime = template[0].pValue = malloc(prime_len);
    if (!prime) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_dsa()",
            "Error allocating memory for prime");
        return NULL;
    }

    subprime = template[1].pValue = malloc(subprime_len);
    if (!subprime) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_dsa()",
            "Error allocating memory for subprime");
        free(prime);
        return NULL;
    }

    base = template[2].pValue = malloc(base_len);
    if (!base) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_dsa()",
            "Error allocating memory for base");
        free(prime);
        free(subprime);
        return NULL;
    }

    value = template[3].pValue = malloc(value_len);
    if (!value) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_dsa()",
            "Error allocating memory for value");
        free(prime);
        free(subprime);
        free(base);
        return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->public_key,
                                      template,
                                      4);
    if (hsm_pkcs11_check_error(ctx, rv, "get attribute value")) {
        free(prime);
        free(subprime);
        free(base);
        free(value);
        return NULL;
    }

    data_size = prime_len + subprime_len + base_len + value_len + 1;
    data = malloc(data_size);
    if (!data) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_dsa()",
            "Error allocating memory for pub key rr data");
        free(prime);
        free(subprime);
        free(base);
        free(value);
        return NULL;
    }
    data[0] = (prime_len - 64) / 8;
    memcpy(&data[1], subprime, subprime_len);
    memcpy(&data[1 + subprime_len], prime, prime_len);
    memcpy(&data[1 + subprime_len + prime_len], base, base_len);
    memcpy(&data[1 + subprime_len + prime_len + base_len], value, value_len);

    rdf = ldns_rdf_new(LDNS_RDF_TYPE_B64, data_size, data);
    free(prime);
    free(subprime);
    free(base);
    free(value);

    return rdf;
}

static ldns_rdf *
hsm_get_key_rdata_gost(hsm_ctx_t *ctx, hsm_session_t *session,
                  const libhsm_key_t *key)
{
    CK_RV rv;
    CK_BYTE_PTR value = NULL;
    CK_ULONG value_len = 0;

    CK_ATTRIBUTE template[] = {
        {CKA_VALUE, NULL, 0},
    };
    ldns_rdf *rdf;

    if (!session || !session->module) {
        return NULL;
    }

    /* GOST needs the public key compared with RSA */
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->public_key,
                                      template,
                                      1);
    if (hsm_pkcs11_check_error(ctx, rv, "C_GetAttributeValue")) {
        return NULL;
    }
    value_len = template[0].ulValueLen;

    value = template[0].pValue = malloc(value_len);
    if (!value) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_key_rdata_gost()",
            "Error allocating memory for value");
        return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(
                                      session->session,
                                      key->public_key,
                                      template,
                                      1);
    if (hsm_pkcs11_check_error(ctx, rv, "get attribute value")) {
        free(value);
        return NULL;
    }

    rdf = ldns_rdf_new(LDNS_RDF_TYPE_B64, value_len, value);
    return rdf;
}

static ldns_rdf *
hsm_get_key_rdata_ecdsa(hsm_ctx_t *ctx, hsm_session_t *session,
                  const libhsm_key_t *key)
{
    CK_ULONG value_len;
    unsigned char* value = hsm_get_key_ecdsa_value(ctx, session, key, &value_len);

    if (value == NULL) return NULL;

    ldns_rdf *rdf = ldns_rdf_new(LDNS_RDF_TYPE_B64, value_len, value);

    return rdf;
}

static ldns_rdf *
hsm_get_key_rdata_eddsa(hsm_ctx_t *ctx, hsm_session_t *session,
                  const libhsm_key_t *key)
{
    CK_ULONG value_len;
    unsigned char* value = hsm_get_key_eddsa_value(ctx, session, key, &value_len);

    if (value == NULL) return NULL;

    ldns_rdf *rdf = ldns_rdf_new(LDNS_RDF_TYPE_B64, value_len, value);

    return rdf;
}

static ldns_rdf *
hsm_get_key_rdata(hsm_ctx_t *ctx, hsm_session_t *session,
                  const libhsm_key_t *key)
{
    switch (hsm_get_key_algorithm(ctx, session, key)) {
        case CKK_RSA:
            return hsm_get_key_rdata_rsa(ctx, session, key);
            break;
        case CKK_DSA:
            return hsm_get_key_rdata_dsa(ctx, session, key);
            break;
        case CKK_GOSTR3410:
            return hsm_get_key_rdata_gost(ctx, session, key);
            break;
        case CKK_EC:
            return hsm_get_key_rdata_ecdsa(ctx, session, key);
        case CKK_EC_EDWARDS:
            return hsm_get_key_rdata_eddsa(ctx, session, key);
        default:
            return 0;
    }
}

/* this function allocates memory for the mechanism ID and enough room
 * to leave the upcoming digest data. It fills in the mechanism id
 * use with care. The returned data must be free'd by the caller.
 * Only used by RSA PKCS. */
static CK_BYTE *
hsm_create_prefix(CK_ULONG digest_len,
                  ldns_algorithm algorithm,
                  CK_ULONG *data_size)
{
    CK_BYTE *data;
    const CK_BYTE RSA_MD5_ID[] = { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
    const CK_BYTE RSA_SHA1_ID[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };
    const CK_BYTE RSA_SHA256_ID[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
    const CK_BYTE RSA_SHA512_ID[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

    switch((ldns_signing_algorithm)algorithm) {
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
	case LDNS_SIGN_RSASHA256:
            *data_size = sizeof(RSA_SHA256_ID) + digest_len;
            data = malloc(*data_size);
            memcpy(data, RSA_SHA256_ID, sizeof(RSA_SHA256_ID));
            break;
	case LDNS_SIGN_RSASHA512:
            *data_size = sizeof(RSA_SHA512_ID) + digest_len;
            data = malloc(*data_size);
            memcpy(data, RSA_SHA512_ID, sizeof(RSA_SHA512_ID));
            break;
        case LDNS_SIGN_DSA:
        case LDNS_SIGN_DSA_NSEC3:
        case LDNS_SIGN_ECC_GOST:
        case LDNS_SIGN_ECDSAP256SHA256:
        case LDNS_SIGN_ECDSAP384SHA384:
            *data_size = digest_len;
            data = malloc(*data_size);
            break;
        default:
            return NULL;
    }
    return data;
}

static CK_BYTE *
hsm_digest_through_hsm(hsm_ctx_t *ctx,
                       hsm_session_t *session,
                       CK_MECHANISM_TYPE mechanism_type,
                       CK_ULONG digest_len,
                       ldns_buffer *sign_buf)
{
    CK_MECHANISM digest_mechanism;
    CK_BYTE *digest;
    CK_RV rv;

    digest_mechanism.pParameter = NULL;
    digest_mechanism.ulParameterLen = 0;
    digest_mechanism.mechanism = mechanism_type;
    digest = malloc(digest_len);
    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_DigestInit(session->session,
                                                 &digest_mechanism);
    if (hsm_pkcs11_check_error(ctx, rv, "HSM digest init")) {
        free(digest);
        return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_Digest(session->session,
                                        ldns_buffer_begin(sign_buf),
                                        ldns_buffer_position(sign_buf),
                                        digest,
                                        &digest_len);
    if (hsm_pkcs11_check_error(ctx, rv, "HSM digest")) {
        free(digest);
        return NULL;
    }
    return digest;
}

static ldns_rdf *
hsm_sign_buffer(hsm_ctx_t *ctx,
                ldns_buffer *sign_buf,
                const libhsm_key_t *key,
                ldns_algorithm algorithm)
{
    CK_RV rv;
    CK_ULONG signatureLen = HSM_MAX_SIGNATURE_LENGTH;
    CK_BYTE signature[HSM_MAX_SIGNATURE_LENGTH];
    CK_MECHANISM sign_mechanism;

    int data_direct = 0; // don't pre-create digest, use data directly

    ldns_rdf *sig_rdf;
    CK_BYTE *digest = NULL;
    CK_ULONG digest_len = 0;

    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;

    hsm_session_t *session;

    session = hsm_find_key_session(ctx, key);
    if (!session) return NULL;

    /* some HSMs don't really handle CKM_SHA1_RSA_PKCS well, so
     * we'll do the hashing manually */
    /* When adding algorithms, remember there is another switch below */
    switch ((ldns_signing_algorithm)algorithm) {
        case LDNS_SIGN_RSAMD5:
            digest_len = 16;
            digest = hsm_digest_through_hsm(ctx, session,
                                            CKM_MD5, digest_len,
                                            sign_buf);
            break;
        case LDNS_SIGN_RSASHA1:
        case LDNS_SIGN_RSASHA1_NSEC3:
        case LDNS_SIGN_DSA:
        case LDNS_SIGN_DSA_NSEC3:
            digest_len = LDNS_SHA1_DIGEST_LENGTH;
            digest = malloc(digest_len);
            digest = ldns_sha1(ldns_buffer_begin(sign_buf),
                               ldns_buffer_position(sign_buf),
                               digest);
            break;

        case LDNS_SIGN_RSASHA256:
        case LDNS_SIGN_ECDSAP256SHA256:
            digest_len = LDNS_SHA256_DIGEST_LENGTH;
            digest = malloc(digest_len);
            digest = ldns_sha256(ldns_buffer_begin(sign_buf),
                                 ldns_buffer_position(sign_buf),
                                 digest);
            break;
        case LDNS_SIGN_ECDSAP384SHA384:
            digest_len = LDNS_SHA384_DIGEST_LENGTH;
            digest = malloc(digest_len);
            digest = ldns_sha384(ldns_buffer_begin(sign_buf),
                                 ldns_buffer_position(sign_buf),
                                 digest);
            break;
        case LDNS_SIGN_RSASHA512:
            digest_len = LDNS_SHA512_DIGEST_LENGTH;
            digest = malloc(digest_len);
            digest = ldns_sha512(ldns_buffer_begin(sign_buf),
                                 ldns_buffer_position(sign_buf),
                                 digest);
            break;
        case LDNS_SIGN_ECC_GOST:
            digest_len = 32;
            digest = hsm_digest_through_hsm(ctx, session,
                                            CKM_GOSTR3411, digest_len,
                                            sign_buf);
            break;
        case LDNS_SIGN_ED25519:
            data_direct = 1;
            break;
        case LDNS_SIGN_ED448:
            data_direct = 1;
            break;
        default:
            /* log error? or should we not even get here for
             * unsupported algorithms? */
            return NULL;
    }

    if (!data_direct && !digest) {
        return NULL;
    }

    if (data_direct) {
        data = ldns_buffer_begin(sign_buf);
        data_len = ldns_buffer_position(sign_buf);
    } else {
        /* CKM_RSA_PKCS does the padding, but cannot know the identifier
         * prefix, so we need to add that ourselves.
         * The other algorithms will just get the digest buffer returned. */
        data = hsm_create_prefix(digest_len, algorithm, &data_len);
        memcpy(data + data_len - digest_len, digest, digest_len);
    }

    sign_mechanism.pParameter = NULL;
    sign_mechanism.ulParameterLen = 0;
    switch((ldns_signing_algorithm)algorithm) {
        case LDNS_SIGN_RSAMD5:
        case LDNS_SIGN_RSASHA1:
        case LDNS_SIGN_RSASHA1_NSEC3:
        case LDNS_SIGN_RSASHA256:
        case LDNS_SIGN_RSASHA512:
            sign_mechanism.mechanism = CKM_RSA_PKCS;
            break;
        case LDNS_SIGN_DSA:
        case LDNS_SIGN_DSA_NSEC3:
            sign_mechanism.mechanism = CKM_DSA;
            break;
        case LDNS_SIGN_ECC_GOST:
            sign_mechanism.mechanism = CKM_GOSTR3410;
            break;
        case LDNS_SIGN_ECDSAP256SHA256:
        case LDNS_SIGN_ECDSAP384SHA384:
            sign_mechanism.mechanism = CKM_ECDSA;
            break;
        case LDNS_SIGN_ED25519:
            sign_mechanism.mechanism = CKM_EDDSA;
            break;
        case LDNS_SIGN_ED448:
            sign_mechanism.mechanism = CKM_EDDSA;
            break;
        default:
            /* log error? or should we not even get here for
             * unsupported algorithms? */
            free(data);
            free(digest);
            return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_SignInit(
                                      session->session,
                                      &sign_mechanism,
                                      key->private_key);
    if (hsm_pkcs11_check_error(ctx, rv, "sign init")) {
        if (!data_direct) {
            free(data);
            free(digest);
        }
        return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_Sign(session->session, data, data_len,
                                      signature,
                                      &signatureLen);
    if (hsm_pkcs11_check_error(ctx, rv, "sign final")) {
        if (!data_direct) {
            free(data);
            free(digest);
        }
        return NULL;
    }

    sig_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64,
                                    signatureLen,
                                    signature);

    if (!data_direct) {
        free(data);
        free(digest);
    }

    return sig_rdf;

}

static int
hsm_dname_is_wildcard(const ldns_rdf* dname)
{
    return ( ldns_dname_label_count(dname) > 0 &&
             ldns_rdf_data(dname)[0] == 1 &&
             ldns_rdf_data(dname)[1] == '*');
}

static ldns_rr *
hsm_create_empty_rrsig(const ldns_rr_list *rrset,
                       const hsm_sign_params_t *sign_params)
{
    ldns_rr *rrsig;
    uint32_t orig_ttl;
    uint32_t orig_class;
    time_t now;
    uint8_t label_count;

    label_count = ldns_dname_label_count(
                       ldns_rr_owner(ldns_rr_list_rr(rrset, 0)));
    /* RFC 4035 section 2.2: dnssec label length and wildcards */
    if (hsm_dname_is_wildcard(ldns_rr_owner(ldns_rr_list_rr(rrset, 0)))) {
        label_count--;
    }

    rrsig = ldns_rr_new_frm_type(LDNS_RR_TYPE_RRSIG);

    /* set the type on the new signature */
    orig_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrset, 0));
    orig_class = ldns_rr_get_class(ldns_rr_list_rr(rrset, 0));

    ldns_rr_set_class(rrsig, orig_class);
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
    now = time_now();
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
hsm_open2(hsm_repository_t* rlist,
         char *(pin_callback)(unsigned int, const char *, unsigned int))
{
    hsm_config_t module_config;
    hsm_repository_t* repo = NULL;
    char* module_pin = NULL;
    int result = HSM_OK;
    int tries;
    int repositories = 0;

    pthread_mutex_lock(&_hsm_ctx_mutex);
    /* create an internal context with an attached session for each
     * configured HSM. */
    if ((_hsm_ctx = hsm_ctx_new())) {
        keycache_create(_hsm_ctx);
    }

    repo = rlist;
    while (repo) {
        hsm_config_default(&module_config);
        module_config.use_pubkey = repo->use_pubkey;
        module_config.allow_extract = repo->allow_extract;
        if (repo->name && repo->module && repo->tokenlabel) {
            if (repo->pin) {
                result = hsm_attach(repo->name, repo->tokenlabel,
                    repo->module, repo->pin, &module_config);
            } else {
                if (pin_callback) {
                    result = HSM_PIN_INCORRECT;
                    tries = 0;
                    while (result == HSM_PIN_INCORRECT && tries < 3) {
                        module_pin = pin_callback(_hsm_ctx->session_count,
                            repo->name, tries?HSM_PIN_RETRY:HSM_PIN_FIRST);
                        if (module_pin == NULL) break;
                        result = hsm_attach(repo->name, repo->tokenlabel,
                            repo->module, module_pin, &module_config);
                        if (result == HSM_OK) {
                            pin_callback(_hsm_ctx->session_count - 1,
                                repo->name, HSM_PIN_SAVE);
                        }
                        memset(module_pin, 0, strlen(module_pin));
                        tries++;
                    }
                } else {
                    /* no pin, no callback */
                    hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_open2()",
                        "No pin or callback function");
                    result = HSM_ERROR;
                }
            }
            if (result != HSM_OK) {
                break;
            }
            repositories++;
        }
        repo = repo->next;
    }
    if (result == HSM_OK && repositories == 0) {
        hsm_ctx_set_error(_hsm_ctx, HSM_NO_REPOSITORIES, "hsm_open2()",
            "No repositories found");
        result = HSM_NO_REPOSITORIES;
    }
    pthread_mutex_unlock(&_hsm_ctx_mutex);
    return result;
}

void
hsm_close()
{
    pthread_mutex_lock(&_hsm_ctx_mutex);
    keycache_destroy(_hsm_ctx);
    hsm_ctx_close(_hsm_ctx, 1);
    _hsm_ctx = NULL;
    pthread_mutex_unlock(&_hsm_ctx_mutex);
}

hsm_ctx_t *
hsm_create_context()
{
    hsm_ctx_t* newctx;
    pthread_mutex_lock(&_hsm_ctx_mutex);
    newctx = hsm_ctx_clone(_hsm_ctx);
    pthread_mutex_unlock(&_hsm_ctx_mutex);
    return newctx;
}

int
hsm_check_context()
{
    unsigned int i;
    hsm_session_t *session;
    CK_SESSION_INFO info;
    CK_RV rv;
    CK_SESSION_HANDLE session_handle;
    hsm_ctx_t *ctx;

    pthread_mutex_lock(&_hsm_ctx_mutex);
    ctx = _hsm_ctx;

    for (i = 0; i < ctx->session_count; i++) {
        session = ctx->session[i];
        if (session == NULL) continue;

        /* Get session info */
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetSessionInfo(
                                        session->session,
                                        &info);
        if (hsm_pkcs11_check_error(ctx, rv, "get session info")) {
            pthread_mutex_unlock(&_hsm_ctx_mutex);
            return HSM_ERROR;
        }

        /* Check session info */
        if (info.state != CKS_RW_USER_FUNCTIONS) {
            hsm_ctx_set_error(ctx, HSM_ERROR, "hsm_check_context()",
                              "Session not logged in");
            pthread_mutex_unlock(&_hsm_ctx_mutex);
            return HSM_ERROR;
        }

        /* Try open and close a session with the token */
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_OpenSession(info.slotID,
                                        CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                        NULL,
                                        NULL,
                                        &session_handle);
        if (hsm_pkcs11_check_error(ctx, rv, "test open session")) {
            pthread_mutex_unlock(&_hsm_ctx_mutex);
            return HSM_ERROR;
        }
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_CloseSession(session_handle);
        if (hsm_pkcs11_check_error(ctx, rv, "test close session")) {
            pthread_mutex_unlock(&_hsm_ctx_mutex);
            return HSM_ERROR;
        }
    }

    pthread_mutex_unlock(&_hsm_ctx_mutex);
    return HSM_OK;
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
    if (!params) {
        return NULL;
    }
    params->algorithm = LDNS_RSASHA256;
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

void
libhsm_key_free(libhsm_key_t *key)
{
    free(key->modulename);
    free(key);
}

libhsm_key_t **
hsm_list_keys(hsm_ctx_t *ctx, size_t *count)
{
    libhsm_key_t **keys = NULL;
    size_t key_count = 0;
    size_t cur_key_count;
    libhsm_key_t **session_keys;
    unsigned int i, j;

    for (i = 0; i < ctx->session_count; i++) {
        session_keys = hsm_list_keys_session(ctx, ctx->session[i],
                                             &cur_key_count);
        keys = realloc(keys,
                       (key_count + cur_key_count) * sizeof(libhsm_key_t *));
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

libhsm_key_t **
hsm_list_keys_repository(hsm_ctx_t *ctx,
                         size_t *count,
                         const char *repository)
{
    hsm_session_t *session;

    if (!repository) return NULL;

    session = hsm_find_repository_session(ctx, repository);
    if (!session) {
        *count = 0;
        return NULL;
    }
    return hsm_list_keys_session(ctx, session, count);
}

libhsm_key_t *
hsm_find_key_by_id(hsm_ctx_t *ctx, const char *id)
{
    unsigned char *id_bytes;
    size_t len;
    libhsm_key_t *key;

    id_bytes = hsm_hex_parse(id, &len);

    if (!id_bytes) return NULL;

    key = hsm_find_key_by_id_bin(ctx, id_bytes, len);
    free(id_bytes);
    return key;
}

static void
generate_unique_id(hsm_ctx_t *ctx, unsigned char *buf, size_t bufsize)
{
    libhsm_key_t *key;
    /* check whether this key doesn't happen to exist already */
    hsm_random_buffer(ctx, buf, bufsize);
    while ((key = hsm_find_key_by_id_bin(ctx, buf, bufsize))) {
	libhsm_key_free(key);
	hsm_random_buffer(ctx, buf, bufsize);
    }

}

libhsm_key_t *
hsm_generate_rsa_key(hsm_ctx_t *ctx,
                     const char *repository,
                     unsigned long keysize)
{
    libhsm_key_t *new_key;
    hsm_session_t *session;
    /* ids we create are 16 bytes of data */
    unsigned char id[16];
    /* that's 33 bytes in string (16*2 + 1 for \0) */
    char id_str[33];
    CK_RV rv;
    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_MECHANISM mechanism = {
        CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };
    CK_BYTE publicExponent[] = { 1, 0, 1 };
    CK_BBOOL ctrue = CK_TRUE;
    CK_BBOOL cfalse = CK_FALSE;
    CK_BBOOL ctoken = CK_TRUE;
    CK_BBOOL cextractable = CK_FALSE;

    session = hsm_find_repository_session(ctx, repository);
    if (!session) return NULL;
    cextractable = session->module->config->allow_extract ? CK_TRUE : CK_FALSE;

    generate_unique_id(ctx, id, 16);

    /* the CKA_LABEL will contain a hexadecimal string representation
     * of the id */
    hsm_hex_unparse(id_str, id, 16);

    if (! session->module->config->use_pubkey) {
        ctoken = CK_FALSE;
    }

    CK_ATTRIBUTE publicKeyTemplate[] = {
        { CKA_LABEL,(CK_UTF8CHAR*) id_str,   strlen(id_str)   },
        { CKA_ID,                  id,       16               },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType)  },
        { CKA_VERIFY,              &ctrue,   sizeof(ctrue)    },
        { CKA_ENCRYPT,             &cfalse,  sizeof(cfalse)   },
        { CKA_WRAP,                &cfalse,  sizeof(cfalse)   },
        { CKA_TOKEN,               &ctoken,  sizeof(ctoken)   },
        { CKA_MODULUS_BITS,        &keysize, sizeof(keysize)  },
        { CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent)}
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
        { CKA_LABEL,(CK_UTF8CHAR *) id_str, strlen (id_str) },
        { CKA_ID,          id,       16                     },
        { CKA_KEY_TYPE,    &keyType, sizeof(keyType) },
        { CKA_SIGN,        &ctrue,   sizeof (ctrue) },
        { CKA_DECRYPT,     &cfalse,  sizeof (cfalse) },
        { CKA_UNWRAP,      &cfalse,  sizeof (cfalse) },
        { CKA_SENSITIVE,   &ctrue,   sizeof (ctrue) },
        { CKA_TOKEN,       &ctrue,   sizeof (ctrue)  },
        { CKA_PRIVATE,     &ctrue,   sizeof (ctrue)  },
        { CKA_EXTRACTABLE, &cextractable,  sizeof (cextractable) }
    };

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GenerateKeyPair(session->session,
                                                 &mechanism,
                                                 publicKeyTemplate, 9,
                                                 privateKeyTemplate, 10,
                                                 &publicKey,
                                                 &privateKey);
    if (hsm_pkcs11_check_error(ctx, rv, "generate key pair")) {
        return NULL;
    }

    new_key = libhsm_key_new();
    new_key->modulename = strdup(session->module->name);

    if (session->module->config->use_pubkey) {
        new_key->public_key = publicKey;
    } else {
        /* Destroy the object directly in order to optimize storage in HSM */
        /* Ignore return value, it is just a session object and will be destroyed later */
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_DestroyObject(session->session, publicKey);
        new_key->public_key = 0;
    }

    new_key->private_key = privateKey;
    return new_key;
}

libhsm_key_t *
hsm_generate_dsa_key(hsm_ctx_t *ctx,
                     const char *repository,
                     unsigned long keysize)
{
    CK_RV rv;
    libhsm_key_t *new_key;
    hsm_session_t *session;
    CK_OBJECT_HANDLE domainPar, publicKey, privateKey;
    CK_BBOOL ctrue = CK_TRUE;
    CK_BBOOL cfalse = CK_FALSE;
    CK_BBOOL cextractable = CK_FALSE;

    /* ids we create are 16 bytes of data */
    unsigned char id[16];
    /* that's 33 bytes in string (16*2 + 1 for \0) */
    char id_str[33];

    session = hsm_find_repository_session(ctx, repository);
    if (!session) return NULL;
    cextractable = session->module->config->allow_extract ? CK_TRUE : CK_FALSE;

    generate_unique_id(ctx, id, 16);

    /* the CKA_LABEL will contain a hexadecimal string representation
     * of the id */
    hsm_hex_unparse(id_str, id, 16);

    CK_KEY_TYPE keyType = CKK_DSA;
    CK_MECHANISM mechanism1 = {
        CKM_DSA_PARAMETER_GEN, NULL_PTR, 0
    };
    CK_MECHANISM mechanism2 = {
        CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0
    };

    /* The maximum size for DSA in DNSSEC */
    CK_BYTE dsa_p[128];
    CK_BYTE dsa_q[20];
    CK_BYTE dsa_g[128];

    CK_ATTRIBUTE domainTemplate[] = {
        { CKA_PRIME_BITS,          &keysize, sizeof(keysize) }
    };

    CK_ATTRIBUTE publicKeyTemplate[] = {
        { CKA_PRIME,               dsa_p,    sizeof(dsa_p)   },
        { CKA_SUBPRIME,            dsa_q,    sizeof(dsa_q)   },
        { CKA_BASE,                dsa_g,    sizeof(dsa_g)   },
        { CKA_LABEL,(CK_UTF8CHAR*) id_str,   strlen(id_str)  },
        { CKA_ID,                  id,       16              },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType) },
        { CKA_VERIFY,              &ctrue,   sizeof(ctrue)   },
        { CKA_ENCRYPT,             &cfalse,  sizeof(cfalse)  },
        { CKA_WRAP,                &cfalse,  sizeof(cfalse)  },
        { CKA_TOKEN,               &ctrue,   sizeof(ctrue)   }
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
        { CKA_LABEL,(CK_UTF8CHAR*) id_str,   strlen (id_str) },
        { CKA_ID,                  id,       16              },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType) },
        { CKA_SIGN,                &ctrue,   sizeof(ctrue)   },
        { CKA_DECRYPT,             &cfalse,  sizeof(cfalse)  },
        { CKA_UNWRAP,              &cfalse,  sizeof(cfalse)  },
        { CKA_SENSITIVE,           &ctrue,   sizeof(ctrue)   },
        { CKA_TOKEN,               &ctrue,   sizeof(ctrue)   },
        { CKA_PRIVATE,             &ctrue,   sizeof(ctrue)   },
        { CKA_EXTRACTABLE, &cextractable,  sizeof (cextractable) }
    };

    cextractable = session->module->config->allow_extract ? CK_TRUE : CK_FALSE;

    /* Generate the domain parameters */

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GenerateKey(session->session,
                                                 &mechanism1,
                                                 domainTemplate, 1,
                                                 &domainPar);
    if (hsm_pkcs11_check_error(ctx, rv, "generate domain parameters")) {
        return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GetAttributeValue(session->session,
                                                 domainPar, publicKeyTemplate, 3);
    if (hsm_pkcs11_check_error(ctx, rv, "get domain parameters")) {
        return NULL;
    }

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_DestroyObject(session->session, domainPar);
    if (hsm_pkcs11_check_error(ctx, rv, "destroy domain parameters")) {
        return NULL;
    }

    /* Generate key pair */

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GenerateKeyPair(session->session,
                                                 &mechanism2,
                                                 publicKeyTemplate, 10,
                                                 privateKeyTemplate, 10,
                                                 &publicKey,
                                                 &privateKey);
    if (hsm_pkcs11_check_error(ctx, rv, "generate key pair")) {
        return NULL;
    }

    new_key = libhsm_key_new();
    new_key->modulename = strdup(session->module->name);
    new_key->public_key = publicKey;
    new_key->private_key = privateKey;

    return new_key;
}

libhsm_key_t *
hsm_generate_gost_key(hsm_ctx_t *ctx,
                     const char *repository)
{
    CK_RV rv;
    libhsm_key_t *new_key;
    hsm_session_t *session;
    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_BBOOL ctrue = CK_TRUE;
    CK_BBOOL cfalse = CK_FALSE;
    CK_BBOOL cextractable = CK_FALSE;

    /* ids we create are 16 bytes of data */
    unsigned char id[16];
    /* that's 33 bytes in string (16*2 + 1 for \0) */
    char id_str[33];

    session = hsm_find_repository_session(ctx, repository);
    if (!session) return NULL;
    cextractable = session->module->config->allow_extract ? CK_TRUE : CK_FALSE;

    generate_unique_id(ctx, id, 16);

    /* the CKA_LABEL will contain a hexadecimal string representation
     * of the id */
    hsm_hex_unparse(id_str, id, 16);

    CK_KEY_TYPE keyType = CKK_GOSTR3410;
    CK_MECHANISM mechanism = {
        CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0
    };

    CK_BYTE oid1[] = { 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
    CK_BYTE oid2[] = { 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1E, 0x01 };

    CK_ATTRIBUTE publicKeyTemplate[] = {
        { CKA_GOSTR3410PARAMS,     oid1,     sizeof(oid1)    },
        { CKA_GOSTR3411PARAMS,     oid2,     sizeof(oid2)    },
        { CKA_LABEL,(CK_UTF8CHAR*) id_str,   strlen(id_str)  },
        { CKA_ID,                  id,       16              },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType) },
        { CKA_VERIFY,              &ctrue,   sizeof(ctrue)   },
        { CKA_ENCRYPT,             &cfalse,  sizeof(cfalse)  },
        { CKA_WRAP,                &cfalse,  sizeof(cfalse)  },
        { CKA_TOKEN,               &ctrue,   sizeof(ctrue)   }
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
        { CKA_LABEL,(CK_UTF8CHAR*) id_str,   strlen (id_str) },
        { CKA_ID,                  id,       16              },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType) },
        { CKA_SIGN,                &ctrue,   sizeof(ctrue)   },
        { CKA_DECRYPT,             &cfalse,  sizeof(cfalse)  },
        { CKA_UNWRAP,              &cfalse,  sizeof(cfalse)  },
        { CKA_SENSITIVE,           &ctrue,   sizeof(ctrue)   },
        { CKA_TOKEN,               &ctrue,   sizeof(ctrue)   },
        { CKA_PRIVATE,             &ctrue,   sizeof(ctrue)   },
        { CKA_EXTRACTABLE,         &cextractable,  sizeof (cextractable) }
    };

    /* Generate key pair */

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GenerateKeyPair(session->session,
                                                 &mechanism,
                                                 publicKeyTemplate, 9,
                                                 privateKeyTemplate, 10,
                                                 &publicKey,
                                                 &privateKey);
    if (hsm_pkcs11_check_error(ctx, rv, "generate key pair")) {
        return NULL;
    }

    new_key = libhsm_key_new();
    new_key->modulename = strdup(session->module->name);
    new_key->public_key = publicKey;
    new_key->private_key = privateKey;

    return new_key;
}

libhsm_key_t *
hsm_generate_ecdsa_key(hsm_ctx_t *ctx,
                       const char *repository,
                       const char *curve)
{
    CK_RV rv;
    libhsm_key_t *new_key;
    hsm_session_t *session;
    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_BBOOL ctrue = CK_TRUE;
    CK_BBOOL cfalse = CK_FALSE;
    CK_BBOOL cextractable = CK_FALSE;

    /* ids we create are 16 bytes of data */
    unsigned char id[16];
    /* that's 33 bytes in string (16*2 + 1 for \0) */
    char id_str[33];

    session = hsm_find_repository_session(ctx, repository);
    if (!session) return NULL;
    cextractable = session->module->config->allow_extract ? CK_TRUE : CK_FALSE;

    generate_unique_id(ctx, id, 16);

    /* the CKA_LABEL will contain a hexadecimal string representation
     * of the id */
    hsm_hex_unparse(id_str, id, 16);

    CK_KEY_TYPE keyType = CKK_EC;
    CK_MECHANISM mechanism = {
        CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0
    };

    CK_BYTE oidP256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    CK_BYTE oidP384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };

    CK_ATTRIBUTE publicKeyTemplate[] = {
        { CKA_EC_PARAMS,           NULL,     0               },
        { CKA_LABEL,(CK_UTF8CHAR*) id_str,   strlen(id_str)  },
        { CKA_ID,                  id,       16              },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType) },
        { CKA_VERIFY,              &ctrue,   sizeof(ctrue)   },
        { CKA_ENCRYPT,             &cfalse,  sizeof(cfalse)  },
        { CKA_WRAP,                &cfalse,  sizeof(cfalse)  },
        { CKA_TOKEN,               &ctrue,   sizeof(ctrue)   }
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
        { CKA_LABEL,(CK_UTF8CHAR*) id_str,   strlen (id_str) },
        { CKA_ID,                  id,       16              },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType) },
        { CKA_SIGN,                &ctrue,   sizeof(ctrue)   },
        { CKA_DECRYPT,             &cfalse,  sizeof(cfalse)  },
        { CKA_UNWRAP,              &cfalse,  sizeof(cfalse)  },
        { CKA_SENSITIVE,           &ctrue,   sizeof(ctrue)   },
        { CKA_TOKEN,               &ctrue,   sizeof(ctrue)   },
        { CKA_PRIVATE,             &ctrue,   sizeof(ctrue)   },
        { CKA_EXTRACTABLE,         &cextractable,  sizeof (cextractable) }
    };

    /* Select the curve */
    if (strcmp(curve, "P-256") == 0)
    {
        publicKeyTemplate[0].pValue = oidP256;
        publicKeyTemplate[0].ulValueLen = sizeof(oidP256);
    }
    else if (strcmp(curve, "P-384") == 0)
    {
        publicKeyTemplate[0].pValue = oidP384;
        publicKeyTemplate[0].ulValueLen = sizeof(oidP384);
    }
    else
    {
        return NULL;
    }

    /* Generate key pair */

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GenerateKeyPair(session->session,
                                                 &mechanism,
                                                 publicKeyTemplate, 8,
                                                 privateKeyTemplate, 10,
                                                 &publicKey,
                                                 &privateKey);
    if (hsm_pkcs11_check_error(ctx, rv, "generate key pair")) {
        return NULL;
    }

    new_key = libhsm_key_new();
    new_key->modulename = strdup(session->module->name);
    new_key->public_key = publicKey;
    new_key->private_key = privateKey;

    return new_key;
}

libhsm_key_t *
hsm_generate_eddsa_key(hsm_ctx_t *ctx,
                       const char *repository,
                       const char *curve)
{
    CK_RV rv;
    libhsm_key_t *new_key;
    hsm_session_t *session;
    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_BBOOL ctrue = CK_TRUE;
    CK_BBOOL cfalse = CK_FALSE;
    CK_BBOOL cextractable = CK_FALSE;

    /* ids we create are 16 bytes of data */
    unsigned char id[16];
    /* that's 33 bytes in string (16*2 + 1 for \0) */
    char id_str[33];

    session = hsm_find_repository_session(ctx, repository);
    if (!session) return NULL;
    cextractable = session->module->config->allow_extract ? CK_TRUE : CK_FALSE;

    generate_unique_id(ctx, id, 16);

    /* the CKA_LABEL will contain a hexadecimal string representation
     * of the id */
    hsm_hex_unparse(id_str, id, 16);

    CK_KEY_TYPE keyType = CKK_EC_EDWARDS;
    CK_MECHANISM mechanism = {
        CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL_PTR, 0
    };

    CK_BYTE oid25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
    CK_BYTE oid448[] = { 0x06, 0x03, 0x2B, 0x65, 0x71 };

    CK_ATTRIBUTE publicKeyTemplate[] = {
        { CKA_EC_PARAMS,           NULL,     0               },
        { CKA_LABEL,(CK_UTF8CHAR*) id_str,   strlen(id_str)  },
        { CKA_ID,                  id,       16              },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType) },
        { CKA_VERIFY,              &ctrue,   sizeof(ctrue)   },
        { CKA_ENCRYPT,             &cfalse,  sizeof(cfalse)  },
        { CKA_WRAP,                &cfalse,  sizeof(cfalse)  },
        { CKA_TOKEN,               &ctrue,   sizeof(ctrue)   }
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
        { CKA_LABEL,(CK_UTF8CHAR*) id_str,   strlen (id_str) },
        { CKA_ID,                  id,       16              },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType) },
        { CKA_SIGN,                &ctrue,   sizeof(ctrue)   },
        { CKA_DECRYPT,             &cfalse,  sizeof(cfalse)  },
        { CKA_UNWRAP,              &cfalse,  sizeof(cfalse)  },
        { CKA_SENSITIVE,           &ctrue,   sizeof(ctrue)   },
        { CKA_TOKEN,               &ctrue,   sizeof(ctrue)   },
        { CKA_PRIVATE,             &ctrue,   sizeof(ctrue)   },
        { CKA_EXTRACTABLE,         &cextractable,  sizeof (cextractable) }
    };

    /* Select the curve */
    if (strcmp(curve, "edwards25519") == 0)
    {
        publicKeyTemplate[0].pValue = oid25519;
        publicKeyTemplate[0].ulValueLen = sizeof(oid25519);
    }
    else if (strcmp(curve, "edwards448") == 0)
    {
        publicKeyTemplate[0].pValue = oid448;
        publicKeyTemplate[0].ulValueLen = sizeof(oid448);
    }
    else
    {
        return NULL;
    }

    /* Generate key pair */

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_GenerateKeyPair(session->session,
                                                 &mechanism,
                                                 publicKeyTemplate, 8,
                                                 privateKeyTemplate, 10,
                                                 &publicKey,
                                                 &privateKey);
    if (hsm_pkcs11_check_error(ctx, rv, "generate key pair")) {
        return NULL;
    }

    new_key = libhsm_key_new();
    new_key->modulename = strdup(session->module->name);
    new_key->public_key = publicKey;
    new_key->private_key = privateKey;

    return new_key;
}

int
hsm_remove_key(hsm_ctx_t *ctx, libhsm_key_t *key)
{
    CK_RV rv;
    hsm_session_t *session;
    if (!key) return -1;

    session = hsm_find_key_session(ctx, key);
    if (!session) return -2;

    rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_DestroyObject(session->session,
                                               key->private_key);
    if (hsm_pkcs11_check_error(ctx, rv, "Destroy private key")) {
        return -3;
    }
    key->private_key = 0;

    if (key->public_key) {
        rv = ((CK_FUNCTION_LIST_PTR)session->module->sym)->C_DestroyObject(session->session,
                                                   key->public_key);
        if (hsm_pkcs11_check_error(ctx, rv, "Destroy public key")) {
            return -4;
        }
    }
    key->public_key = 0;

    return 0;
}

void
libhsm_key_list_free(libhsm_key_t **key_list, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++) {
        libhsm_key_free(key_list[i]);
    }
    free(key_list);
}

char *
hsm_get_key_id(hsm_ctx_t *ctx, const libhsm_key_t *key)
{
    unsigned char *id;
    char *id_str;
    size_t len;
    hsm_session_t *session;

    if (!key) return NULL;

    session = hsm_find_key_session(ctx, key);
    if (!session) return NULL;

    id = hsm_get_id_for_object(ctx, session, key->private_key, &len);
    if (!id) return NULL;

    /* this is plain binary data, we need to convert it to hex */
    id_str = malloc(len * 2 + 1);
    if (!id_str) {
        free(id);
        return NULL;
    }

    hsm_hex_unparse(id_str, id, len);

    free(id);

    return id_str;
}

libhsm_key_info_t *
hsm_get_key_info(hsm_ctx_t *ctx,
                 const libhsm_key_t *key)
{
    libhsm_key_info_t *key_info;
    hsm_session_t *session;

    session = hsm_find_key_session(ctx, key);
    if (!session) return NULL;

    key_info = malloc(sizeof(libhsm_key_info_t));

    key_info->id = hsm_get_key_id(ctx, key);
    if (key_info->id == NULL) {
        key_info->id = strdup("");
    }

    key_info->algorithm = (unsigned long) hsm_get_key_algorithm(ctx,
                                                                session,
                                                                key);
    key_info->keysize = (unsigned long) hsm_get_key_size(ctx,
                                                         session,
                                                         key,
                                                         key_info->algorithm);

    switch(key_info->algorithm) {
        case CKK_RSA:
            key_info->algorithm_name = strdup("RSA");
            break;
        case CKK_DSA:
            key_info->algorithm_name = strdup("DSA");
            break;
        case CKK_GOSTR3410:
            key_info->algorithm_name = strdup("GOST");
            break;
        case CKK_EC:
            key_info->algorithm_name = strdup("ECDSA");
            break;
        case CKK_EC_EDWARDS:
            key_info->algorithm_name = strdup("EDDSA");
            break;
        default:
            key_info->algorithm_name = malloc(HSM_MAX_ALGONAME);
            snprintf(key_info->algorithm_name, HSM_MAX_ALGONAME,
                "%lu", key_info->algorithm);
            break;
    }

    return key_info;
}

void
libhsm_key_info_free(libhsm_key_info_t *key_info)
{
    if (key_info) {
        if (key_info->id) {
            free(key_info->id);
        }
        if (key_info->algorithm_name) {
            free(key_info->algorithm_name);
        }
        free(key_info);
    }
}

ldns_rr*
hsm_sign_rrset(hsm_ctx_t *ctx,
               const ldns_rr_list* rrset,
               const libhsm_key_t *key,
               const hsm_sign_params_t *sign_params)
{
    ldns_rr *signature;
    ldns_buffer *sign_buf;
    ldns_rdf *b64_rdf;
    size_t i;

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
        ldns_rr_free(signature);
        return NULL;
    }

    /* make it canonical */
    for(i = 0; i < ldns_rr_list_rr_count(rrset); i++) {
        ldns_rr2canonical(ldns_rr_list_rr(rrset, i));
    }

    /* add the rrset in sign_buf */
    if (ldns_rr_list2buffer_wire(sign_buf, rrset)
        != LDNS_STATUS_OK) {
        ldns_buffer_free(sign_buf);
        ldns_rr_free(signature);
        return NULL;
    }

    b64_rdf = hsm_sign_buffer(ctx, sign_buf, key, sign_params->algorithm);

    ldns_buffer_free(sign_buf);
    if (!b64_rdf) {
        /* signing went wrong */
        ldns_rr_free(signature);
        return NULL;
    }

    ldns_rr_rrsig_set_sig(signature, b64_rdf);

    return signature;
}

int
hsm_keytag(const char* loc, int alg, int ksk, uint16_t* keytag)
{
	uint16_t tag;
	hsm_ctx_t *hsm_ctx;
	hsm_sign_params_t *sign_params;
	libhsm_key_t *hsmkey;
	ldns_rr *dnskey_rr;

	if (!loc) {
		return 1;
	}

	if (!(hsm_ctx = hsm_create_context())) {
		return 1;
	}
	if (!(sign_params = hsm_sign_params_new())) {
		hsm_destroy_context(hsm_ctx);
		return 1;
	}

	/* The owner name is not relevant for the keytag calculation.
	 * However, a ldns_rdf_clone down the path will trip over it. */
	sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "dummy");
	sign_params->algorithm = (ldns_algorithm) alg;
	sign_params->flags = LDNS_KEY_ZONE_KEY;
	if (ksk)
		sign_params->flags |= LDNS_KEY_SEP_KEY;

	hsmkey = hsm_find_key_by_id(hsm_ctx, loc);
	if (!hsmkey) {
		hsm_sign_params_free(sign_params);
		hsm_destroy_context(hsm_ctx);
		return 1;
	}

	dnskey_rr = hsm_get_dnskey(hsm_ctx, hsmkey, sign_params);
	if (!dnskey_rr) {
		libhsm_key_free(hsmkey);
		hsm_sign_params_free(sign_params);
		hsm_destroy_context(hsm_ctx);
		return 1;
	}

	tag = ldns_calc_keytag(dnskey_rr);

	ldns_rr_free(dnskey_rr);
	libhsm_key_free(hsmkey);
	hsm_sign_params_free(sign_params);
	hsm_destroy_context(hsm_ctx);

	if (keytag)
            *keytag = tag;
	return 0;
}

ldns_rr *
hsm_get_dnskey(hsm_ctx_t *ctx,
               const libhsm_key_t *key,
               const hsm_sign_params_t *sign_params)
{
    /* CK_RV rv; */
    ldns_rr *dnskey;
    hsm_session_t *session;
    ldns_rdf *rdata;

    if (!key) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_dnskey()", "Got NULL key");
        return NULL;
    }
    if (!sign_params) {
        hsm_ctx_set_error(ctx, -1, "hsm_get_dnskey()", "Got NULL sign_params");
        return NULL;
    }
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

    rdata = hsm_get_key_rdata(ctx, session, key);
    if (rdata == NULL) {
        ldns_rr_free(dnskey);
        return NULL;
    }
    ldns_rr_push_rdf(dnskey, rdata);

    return dnskey;
}

int
hsm_random_buffer(hsm_ctx_t *ctx,
                  unsigned char *buffer,
                  unsigned long length)
{
    CK_RV rv;
    unsigned int i;
    hsm_session_t *session;
    if (!buffer) return -1;

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
hsm_random32(hsm_ctx_t *ctx)
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
hsm_random64(hsm_ctx_t *ctx)
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

int hsm_attach(const char *repository,
               const char *token_label,
               const char *path,
               const char *pin,
               const hsm_config_t *config)
{
    hsm_session_t *session;
    int result;

    result = hsm_session_init(_hsm_ctx,
                              &session,
                              repository,
                              token_label,
                              path,
                              pin,
                              config);
    if (result == HSM_OK) {
        result = hsm_ctx_add_session(_hsm_ctx, session);
    }
    return result;
}

int
hsm_token_attached(hsm_ctx_t *ctx, const char *repository)
{
    unsigned int i;
    for (i = 0; i < ctx->session_count; i++) {
        if (ctx->session[i] &&
            strcmp(ctx->session[i]->module->name, repository) == 0) {
                return 1;
        }
    }

    hsm_ctx_set_error(ctx, HSM_REPOSITORY_NOT_FOUND,
                    "hsm_token_attached()",
                    "Can't find repository: %s", repository);
    return 0;
}

char *
hsm_get_error(hsm_ctx_t *gctx)
{
    hsm_ctx_t *ctx;

    char *message;

    if (!gctx) {
        ctx = _hsm_ctx;
    } else {
        ctx = gctx;
    }

    if (ctx->error) {
        ctx->error = 0;
        message = malloc(HSM_ERROR_MSGSIZE);

        if (message == NULL) {
            return strdup("libhsm memory allocation failed");
        }

        snprintf(message, HSM_ERROR_MSGSIZE,
            "%s: %s",
            ctx->error_action ? ctx->error_action : "unknown()",
            ctx->error_message[0] ? ctx->error_message : "unknown error");
        return message;
    };

    return NULL;
}

void
hsm_print_session(hsm_session_t *session)
{
    printf("\t\tmodule at %p (sym %p)\n", (void *) session->module, (void *) session->module->sym);
    printf("\t\tmodule path: %s\n", session->module->path);
    printf("\t\trepository name: %s\n", session->module->name);
    printf("\t\ttoken label: %s\n", session->module->token_label);
    printf("\t\tsess handle: %u\n", (unsigned int) session->session);
}

void
hsm_print_ctx(hsm_ctx_t *ctx) {
    unsigned int i;
    printf("CTX Sessions: %lu\n",
           (long unsigned int) ctx->session_count);
    for (i = 0; i < ctx->session_count; i++) {
        printf("\tSession at %p\n", (void *) ctx->session[i]);
        hsm_print_session(ctx->session[i]);
    }
}

void
hsm_print_key(hsm_ctx_t *ctx, libhsm_key_t *key) {
    libhsm_key_info_t *key_info;
    if (key) {
        key_info = hsm_get_key_info(ctx, key);
        if (key_info) {
            printf("key:\n");
            printf("\tprivkey handle: %u\n", (unsigned int) key->private_key);
            if (key->public_key) {
                printf("\tpubkey handle: %u\n", (unsigned int) key->public_key);
            } else {
                printf("\tpubkey handle: %s\n", "NULL");
            }
            printf("\trepository: %s\n", key->modulename);
            printf("\talgorithm: %s\n", key_info->algorithm_name);
            printf("\tsize: %lu\n", key_info->keysize);
            printf("\tid: %s\n", key_info->id);
            libhsm_key_info_free(key_info);
        } else {
            printf("key: hsm_get_key_info() returned NULL\n");
        }
    } else {
        printf("key: <void>\n");
    }
}

void
hsm_print_error(hsm_ctx_t *gctx)
{
    char *message;

    message = hsm_get_error(gctx);

    if (message) {
        fprintf(stderr, "%s\n", message);
        free(message);
    } else {
        fprintf(stderr, "Unknown error\n");
    }
}

void
hsm_print_tokeninfo(hsm_ctx_t *ctx)
{
    CK_RV rv;
    CK_SLOT_ID slot_id;
    CK_TOKEN_INFO token_info;
    unsigned int i;
    hsm_session_t *session;
    int result;

    for (i = 0; i < ctx->session_count; i++) {
        session = ctx->session[i];

        result = hsm_get_slot_id(ctx,
                                  session->module->sym,
                                  session->module->token_label,
                                  &slot_id);
        if (result != HSM_OK) return;

        rv = ((CK_FUNCTION_LIST_PTR) session->module->sym)->C_GetTokenInfo(slot_id, &token_info);
        if (hsm_pkcs11_check_error(ctx, rv, "C_GetTokenInfo")) {
            return;
        }

        printf("Repository: %s\n",session->module->name);

        printf("\tModule:        %s\n", session->module->path);
        printf("\tSlot:          %lu\n", slot_id);
        printf("\tToken Label:   %.*s\n",
            (int) sizeof(token_info.label), token_info.label);
        printf("\tManufacturer:  %.*s\n",
            (int) sizeof(token_info.manufacturerID), token_info.manufacturerID);
        printf("\tModel:         %.*s\n",
            (int) sizeof(token_info.model), token_info.model);
        printf("\tSerial:        %.*s\n",
            (int) sizeof(token_info.serialNumber), token_info.serialNumber);

        if (i + 1 != ctx->session_count)
            printf("\n");
    }
}

static int
keycache_cmpfunc(const void* a, const void* b)
{
    const char* x = (const char*)a;
    const char* y = (const char*)b;
    return strcmp(x, y);
}

static void
keycache_delfunc(ldns_rbnode_t* node, void* cargo)
{
    (void)cargo;
    free((void*)node->key);
    free(((libhsm_key_t*)node->data)->modulename);
    free((void*)node->data);
    free((void*)node);
}

void
keycache_create(hsm_ctx_t* ctx)
{
    ctx->keycache = ldns_rbtree_create(keycache_cmpfunc);
    _hsm_ctx->keycache_lock = malloc(sizeof (pthread_mutex_t));
    pthread_mutex_init(_hsm_ctx->keycache_lock, NULL);
}

void
keycache_destroy(hsm_ctx_t* ctx)
{
    ldns_traverse_postorder(ctx->keycache, keycache_delfunc, NULL);
    ldns_rbtree_free(ctx->keycache);
    pthread_mutex_destroy(ctx->keycache_lock);
    free(ctx->keycache_lock);
    ctx->keycache_lock = NULL;
}

const libhsm_key_t*
keycache_lookup(hsm_ctx_t* ctx, const char* locator)
{
    ldns_rbnode_t* node;

    pthread_mutex_lock(ctx->keycache_lock);
        node = ldns_rbtree_search(ctx->keycache, locator);
    pthread_mutex_unlock(ctx->keycache_lock);
    if (node == LDNS_RBTREE_NULL || node == NULL) {
        libhsm_key_t* key;
        if ((key = hsm_find_key_by_id(ctx, locator)) == NULL) {
            node = NULL;
        } else {
            node = malloc(sizeof(ldns_rbnode_t));
            node->key = strdup(locator);
            node->data = key;
            pthread_mutex_lock(ctx->keycache_lock);
                node = ldns_rbtree_insert(ctx->keycache, node);
            pthread_mutex_unlock(ctx->keycache_lock);
        }
    }  

    if (node == LDNS_RBTREE_NULL || node == NULL)
        return NULL;
    else
        return node->data;
}
