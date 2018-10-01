/*
 * Copyright (c) 2018 NLNet Labs.
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <malloc.h>
#include <pthread.h>
#include <string.h>
#include <dlfcn.h>
#include <syslog.h>

#include "pkcs11.h"

static CK_FUNCTION_LIST definition;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static const char* libraryPath = "libsofthsm2.so";
static void* libraryReference = NULL;
static CK_FUNCTION_LIST_PTR libraryTable = NULL;

static CK_RV
Unsupported()
{
    syslog(LOG_DAEMON|LOG_ERR, "Unsupported call");
    abort();
    return CKR_DEVICE_ERROR;
}

static CK_RV
Initialize(void *args)
{
    CK_RV status;
    CK_C_GetFunctionList libraryFunction = NULL;
    pthread_mutex_lock(&lock);
    if (libraryReference == NULL) {
        libraryReference = dlopen(libraryPath, RTLD_NOW|RTLD_LOCAL);
    }
    pthread_mutex_unlock(&lock);
    if (libraryReference == NULL) {
        syslog(LOG_DAEMON|LOG_ERR, "Library not found");
        return CKR_DEVICE_ERROR;
    }
    libraryFunction = dlsym(libraryReference, "C_GetFunctionList");
    if (libraryFunction == NULL) {
        syslog(LOG_DAEMON|LOG_ERR, "Unsuitable library");
        return CKR_DEVICE_ERROR;
    }
    status = libraryFunction(&libraryTable);
    if (status != CKR_OK) {
        syslog(LOG_DAEMON|LOG_ERR, "Library faulty");
        return status;
    }
    status = libraryTable->C_Initialize(NULL);
    if(status != CKR_OK && status != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        syslog(LOG_DAEMON|LOG_ERR, "Library initialization failed");
        return status;
    }
    return CKR_OK;
}

static CK_RV
Finalize(void *args)
{
    CK_RV status;
    pthread_mutex_lock(&lock);
    if(libraryTable != NULL) {
        status = libraryTable->C_Finalize(NULL);
        libraryTable = NULL;
    } else {
        status = CKR_OK;
    }
    pthread_mutex_unlock(&lock);
    return status;
}

static CK_RV
GetInfo(CK_INFO *info)
{
    return libraryTable->C_GetInfo(info);
}

static CK_RV
GetSlotList(unsigned char token_present, CK_SLOT_ID *slot_list, unsigned long *count)
{
    return libraryTable->C_GetSlotList(token_present, slot_list, count);
}

static CK_RV
GetSlotInfo(CK_SLOT_ID slot_id, CK_SLOT_INFO* info)
{
    return libraryTable->C_GetSlotInfo(slot_id, info);
}

static CK_RV
GetTokenInfo(CK_SLOT_ID slot_id, CK_TOKEN_INFO* info)
{
    return libraryTable->C_GetTokenInfo(slot_id, info);
}

static CK_RV
OpenSession(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application, CK_NOTIFY notify, CK_SESSION_HANDLE *session)
{
    return libraryTable->C_OpenSession(slot_id, flags, application, notify, session);
}

static CK_RV
CloseSession(CK_SESSION_HANDLE session)
{
    return libraryTable->C_CloseSession(session);
}

static CK_RV
GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO *info)
{
    return libraryTable->C_GetSessionInfo(session, info);
}

static CK_RV
Login(CK_SESSION_HANDLE session, unsigned long user_type, unsigned char *pin, unsigned long pin_len)
{
    return libraryTable->C_Login(session, user_type, pin, pin_len);
}

static CK_RV
Logout(CK_SESSION_HANDLE session)
{
    return libraryTable->C_Logout(session);
}

static CK_RV
DestroyObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
    return libraryTable->C_DestroyObject(session, object);
}

static CK_RV
GetAttributeValue(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE* templ, unsigned long count)
{
    return libraryTable->C_GetAttributeValue(session, object, templ, count);
}

static CK_RV
FindObjectsInit(CK_SESSION_HANDLE session, CK_ATTRIBUTE* templ, unsigned long count)
{
    return libraryTable->C_FindObjectsInit(session, templ, count);
}

static CK_RV
FindObjects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* object, unsigned long max_object_count, unsigned long *object_count)
{
    return libraryTable->C_FindObjects(session, object, max_object_count, object_count);
}

static CK_RV
FindObjectsFinal(CK_SESSION_HANDLE session)
{
    return libraryTable->C_FindObjectsFinal(session);
}

static CK_RV
DigestInit(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr)
{
    return libraryTable->C_DigestInit(session, mechanism_ptr);
}

static CK_RV
Digest(CK_SESSION_HANDLE session, unsigned char *data_ptr, unsigned long data_len, unsigned char *digest, unsigned long *digest_len)
{
    return libraryTable->C_Digest(session, data_ptr, data_len, digest, digest_len);
}

static CK_RV
SignInit(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr, CK_OBJECT_HANDLE key)
{
    return CKR_OK;
}

static CK_RV
Sign(CK_SESSION_HANDLE session, unsigned char *data_ptr, unsigned long data_len, unsigned char *signature, unsigned long *signature_len)
{
    int i;
    *signature_len = 1024/8;
    for (i=0; i<*signature_len; i++) {
        signature[i] = 0;
    }
    return CKR_OK;
}

static CK_RV
GenerateKey(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr,
        CK_ATTRIBUTE* templ, unsigned long count, CK_OBJECT_HANDLE* key)
{
    return libraryTable->C_GenerateKey(session, mechanism_ptr, templ, count, key);
}

static CK_RV
GenerateKeyPair(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr,
        CK_ATTRIBUTE* public_key_template, unsigned long public_key_attribute_count,
        CK_ATTRIBUTE* private_key_template, unsigned long private_key_attribute_count,
        CK_OBJECT_HANDLE* public_key, CK_OBJECT_HANDLE* private_key)
{
    return libraryTable->C_GenerateKeyPair(session, mechanism_ptr, public_key_template, public_key_attribute_count, private_key_template, private_key_attribute_count, public_key, private_key);
}

static CK_RV
SeedRandom(CK_SESSION_HANDLE session, unsigned char *seed_ptr, unsigned long seed_len)
{
    return libraryTable->C_SeedRandom(session, seed_ptr, seed_len);
    return CKR_OK;
}

static CK_RV
GenerateRandom(CK_SESSION_HANDLE session, unsigned char *random_data, unsigned long random_len)
{
    return libraryTable->C_GenerateRandom(session, random_data, random_len);
    memset(random_data, '\0',  random_len);
    return CKR_OK;
}

static CK_RV
GetFunctionList(CK_FUNCTION_LIST_PTR_PTR function_list)
{
  definition.version.major = CRYPTOKI_VERSION_MAJOR;
  definition.version.minor = CRYPTOKI_VERSION_MINOR;
  definition.C_Initialize          = Initialize;
  definition.C_Finalize            = Finalize;
  definition.C_GetInfo             = GetInfo;
  definition.C_GetFunctionList     = GetFunctionList;
  definition.C_GetSlotList         = GetSlotList;
  definition.C_GetSlotInfo         = GetSlotInfo;
  definition.C_GetTokenInfo        = GetTokenInfo;
  definition.C_GetMechanismList    = Unsupported;
  definition.C_GetMechanismInfo    = Unsupported;
  definition.C_InitToken           = Unsupported;
  definition.C_InitPIN             = Unsupported;
  definition.C_SetPIN              = Unsupported;
  definition.C_OpenSession         = OpenSession;
  definition.C_CloseSession        = CloseSession;
  definition.C_CloseAllSessions    = Unsupported;
  definition.C_GetSessionInfo      = GetSessionInfo;
  definition.C_GetOperationState   = Unsupported;
  definition.C_SetOperationState   = Unsupported;
  definition.C_Login               = Login;
  definition.C_Logout              = Logout;
  definition.C_CreateObject        = Unsupported;
  definition.C_CopyObject          = Unsupported;
  definition.C_DestroyObject       = DestroyObject;
  definition.C_GetObjectSize       = Unsupported;
  definition.C_GetAttributeValue   = GetAttributeValue;
  definition.C_SetAttributeValue   = Unsupported;
  definition.C_FindObjectsInit     = FindObjectsInit;
  definition.C_FindObjects         = FindObjects;
  definition.C_FindObjectsFinal    = FindObjectsFinal;
  definition.C_EncryptInit         = Unsupported;
  definition.C_Encrypt             = Unsupported;
  definition.C_EncryptUpdate       = Unsupported;
  definition.C_EncryptFinal        = Unsupported;
  definition.C_DecryptInit         = Unsupported;
  definition.C_Decrypt             = Unsupported;
  definition.C_DecryptUpdate       = Unsupported;
  definition.C_DecryptFinal        = Unsupported;
  definition.C_DigestInit          = DigestInit;
  definition.C_Digest              = Digest;
  definition.C_DigestUpdate        = Unsupported;
  definition.C_DigestKey           = Unsupported;
  definition.C_DigestFinal         = Unsupported;
  definition.C_SignInit            = SignInit;
  definition.C_Sign                = Sign;
  definition.C_SignUpdate          = Unsupported;
  definition.C_SignFinal           = Unsupported;
  definition.C_SignRecoverInit     = Unsupported;
  definition.C_SignRecover         = Unsupported;
  definition.C_VerifyInit          = Unsupported;
  definition.C_Verify              = Unsupported;
  definition.C_VerifyUpdate        = Unsupported;
  definition.C_VerifyFinal         = Unsupported;
  definition.C_VerifyRecoverInit   = Unsupported;
  definition.C_VerifyRecover       = Unsupported;
  definition.C_DigestEncryptUpdate = Unsupported;
  definition.C_DecryptDigestUpdate = Unsupported;
  definition.C_SignEncryptUpdate   = Unsupported;
  definition.C_DecryptVerifyUpdate = Unsupported;
  definition.C_GenerateKey         = GenerateKey;
  definition.C_GenerateKeyPair     = GenerateKeyPair;
  definition.C_WrapKey             = Unsupported;
  definition.C_UnwrapKey           = Unsupported;
  definition.C_DeriveKey           = Unsupported;
  definition.C_SeedRandom          = SeedRandom;
  definition.C_GenerateRandom      = GenerateRandom;
  definition.C_GetFunctionStatus   = Unsupported;
  definition.C_CancelFunction      = Unsupported;
  definition.C_WaitForSlotEvent    = Unsupported;
  *function_list = &definition;
  return CKR_OK;
}

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR function_list)
{
    return GetFunctionList(function_list);
}

__attribute__((constructor))
void
init(void)
{
}

__attribute__((destructor))
void
fini(void)
{
}
