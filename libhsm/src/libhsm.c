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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <cryptoki.h>
#include <pkcs11.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

#include "libhsm.h"
#include <config.h>

/* we need some globals, for session management, and for the initial
 * context
 */
static hsm_ctx_t *_hsm_ctx;

/* internal functions */
static hsm_ctx_t *
hsm_ctx_new()
{
    hsm_ctx_t *ctx;
    ctx = malloc(sizeof(hsm_ctx_t));
    memset(ctx->session, 0, HSM_MAX_SESSIONS);
    ctx->session_count = 0;
    return ctx;
}

static hsm_module_t *
hsm_module_new(const char *name, const char *path)
{
    hsm_module_t *module;
    module = malloc(sizeof(hsm_module_t));
    module->id = 0; /*TODO what should this value be?*/
    module->name = malloc(strlen(name) + 1);
    strcpy(module->name, name);
    module->path = malloc(strlen(path) + 1);
    strcpy(module->path, path);
    module->handle = NULL;
    module->sym = NULL;
    return module;
}

static void
hsm_module_free(hsm_module_t *module)
{
    if (module) free(module);
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
        if (session->module) hsm_module_free(session->module);
        free(session);
    }
}

static void
hsm_ctx_free(hsm_ctx_t *ctx)
{
    unsigned int i;
    if (ctx) {
        if (ctx->session) {
            for (i = 0; i < ctx->session_count; i++) {
                hsm_session_free(ctx->session[i]);
            }
            free(ctx->session);
        }
        free(ctx);
    }
}

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

static CK_RV
hsm_pkcs11_load_functions(CK_FUNCTION_LIST_PTR_PTR pkcs11_functions,
                          const char *dl_file)
{
    CK_C_GetFunctionList pGetFunctionList = NULL;

    if (dl_file) {
        /* library provided by application or user */
#if defined(HAVE_LOADLIBRARY)
fprintf(stderr, "have loadlibrary\n");
        /* Load PKCS #11 library */
        HINSTANCE hDLL = LoadLibrary(_T(dl_file));

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
        void* pDynLib = dlopen(dl_file, RTLD_LAZY);

        if (pDynLib == NULL)
        {
            /* Failed to load the PKCS #11 library */
            fprintf(stderr, "dlopen() failed: %s\n", dlerror());
            return CKR_FUNCTION_FAILED;
        }

        /* Retrieve the entry point for C_GetFunctionList */
        pGetFunctionList = (CK_C_GetFunctionList) dlsym(pDynLib, "C_GetFunctionList");
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
    (pGetFunctionList)(pkcs11_functions);

    return CKR_OK;
}

static int
hsm_pkcs11_check_token_name(CK_FUNCTION_LIST_PTR pkcs11_functions,
                             CK_SLOT_ID slotId,
                             const char *token_name)
{
    /* token label is always 32 bytes */
    char *token_name_bytes = malloc(32);
    int result = 0;
    CK_RV rv;
    CK_TOKEN_INFO token_info;
    
    rv = pkcs11_functions->C_GetTokenInfo(slotId, &token_info);
    hsm_pkcs11_check_rv(rv, "C_GetTokenInfo");
    
    memset(token_name_bytes, ' ', 32);
    memcpy(token_name_bytes, token_name, strlen(token_name));
    
    result = memcmp(token_info.label, token_name_bytes, 32) == 0;
    
    free(token_name_bytes);
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


/* external functions */


int
hsm_open(const char *config,
         char *(pin_callback)(char *token_name, void *), void *data)
{
    xmlDocPtr doc;
    xmlXPathContextPtr xpath_ctx;
    xmlXPathObjectPtr xpath_obj;
    xmlNode *curNode;
    xmlChar *xexpr;

    int i;
    char *module_name;
    char *module_path;
    char *module_pin;
    hsm_module_t *module;
    hsm_session_t *session;
    
    CK_SESSION_HANDLE session_handle;
    CK_SLOT_ID slot_id;
    CK_RV rv;
    
    /* create an internal context with an attached session for each
     * configured HSM. */
    _hsm_ctx = hsm_ctx_new();
    
    /* Load XML document */
    fprintf(stdout, "Opening %s\n", config);
    doc = xmlParseFile(config);
    if (doc == NULL) {
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", config);
        return -1;
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
        fprintf(stderr, "%u nodes\n", xpath_obj->nodesetval->nodeNr);
        for (i = 0; i < xpath_obj->nodesetval->nodeNr; i++) {
            /*module = hsm_module_new();*/
            module_name = NULL;
            module_path = NULL;
            module_pin = NULL;
            curNode = xpath_obj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Name"))
                    module_name = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Module"))
                    module_path = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"PIN"))
                    module_pin = (char *) xmlNodeGetContent(curNode);
                curNode = curNode->next;
            }
            if (module_name && module_path) {
                if (module_pin || pin_callback) {
                    if (!module_pin) {
                        module_pin = pin_callback(module_name, data);
                    }
                    /* TODO: move to hsm_pkcs11_module_init? */
                    module = hsm_module_new(module_name, module_path);
                    rv = hsm_pkcs11_load_functions(&(module->sym), module_path);
                    hsm_pkcs11_check_rv(rv, "Load functions");
                    slot_id = ldns_hsm_get_slot_id(module->sym, module_name);
                    module->sym->C_OpenSession(slot_id,
                                               CKF_SERIAL_SESSION,
                                               NULL,
                                               NULL,
                                               &session_handle);
                    session = hsm_session_new(module, session_handle);
                    fprintf(stdout, "module added\n");
                    /* ok we have a module, start a session */
                }
            }
        }
    }

    return 0;
}

int
hsm_close()
{
    hsm_ctx_free(_hsm_ctx);
    return 0;
}
