/*
 * $Id$
 *
 * Copyright (c) 2009 Nominet UK.
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
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

#include <cryptoki.h>
#include <pktools.h>


CK_FUNCTION_LIST_PTR sym = 0;

typedef struct {CK_RV rv;const char *rv_str;}
error_table;
error_table error_str[] =
{
    { CKR_OK, "CKR_OK"},
    { CKR_CANCEL, "CKR_CANCEL"},
    { CKR_HOST_MEMORY, "CKR_HOST_MEMORY"},
    { CKR_SLOT_ID_INVALID, "CKR_SLOT_ID_INVALID"},
    { CKR_GENERAL_ERROR, "CKR_GENERAL_ERROR"},
    { CKR_FUNCTION_FAILED, "CKR_FUNCTION_FAILED"},
    { CKR_ARGUMENTS_BAD, "CKR_ARGUMENTS_BAD"},
    { CKR_NO_EVENT, "CKR_NO_EVENT"},
    { CKR_NEED_TO_CREATE_THREADS, "CKR_NEED_TO_CREATE_THREADS"},
    { CKR_CANT_LOCK, "CKR_CANT_LOCK"},
    { CKR_ATTRIBUTE_READ_ONLY, "CKR_ATTRIBUTE_READ_ONLY"},
    { CKR_ATTRIBUTE_SENSITIVE, "CKR_ATTRIBUTE_SENSITIVE"},
    { CKR_ATTRIBUTE_TYPE_INVALID, "CKR_ATTRIBUTE_TYPE_INVALID"},
    { CKR_ATTRIBUTE_VALUE_INVALID, "CKR_ATTRIBUTE_VALUE_INVALID"},
    { CKR_DATA_INVALID, "CKR_DATA_INVALID"},
    { CKR_DATA_LEN_RANGE, "CKR_DATA_LEN_RANGE"},
    { CKR_DEVICE_ERROR, "CKR_DEVICE_ERROR"},
    { CKR_DEVICE_MEMORY, "CKR_DEVICE_MEMORY"},
    { CKR_DEVICE_REMOVED, "CKR_DEVICE_REMOVED"},
    { CKR_ENCRYPTED_DATA_INVALID, "CKR_ENCRYPTED_DATA_INVALID"},
    { CKR_ENCRYPTED_DATA_LEN_RANGE, "CKR_ENCRYPTED_DATA_LEN_RANGE"},
    { CKR_FUNCTION_CANCELED, "CKR_FUNCTION_CANCELED"},
    { CKR_FUNCTION_NOT_PARALLEL, "CKR_FUNCTION_NOT_PARALLEL"},
    { CKR_FUNCTION_NOT_SUPPORTED, "CKR_FUNCTION_NOT_SUPPORTED"},
    { CKR_KEY_HANDLE_INVALID, "CKR_KEY_HANDLE_INVALID"},
    { CKR_KEY_SIZE_RANGE, "CKR_KEY_SIZE_RANGE"},
    { CKR_KEY_TYPE_INCONSISTENT, "CKR_KEY_TYPE_INCONSISTENT"},
    { CKR_KEY_NOT_NEEDED, "CKR_KEY_NOT_NEEDED"},
    { CKR_KEY_CHANGED, "CKR_KEY_CHANGED"},
    { CKR_KEY_NEEDED, "CKR_KEY_NEEDED"},
    { CKR_KEY_INDIGESTIBLE, "CKR_KEY_INDIGESTIBLE"},
    { CKR_KEY_FUNCTION_NOT_PERMITTED, "CKR_KEY_FUNCTION_NOT_PERMITTED"},
    { CKR_KEY_NOT_WRAPPABLE, "CKR_KEY_NOT_WRAPPABLE"},
    { CKR_KEY_UNEXTRACTABLE, "CKR_KEY_UNEXTRACTABLE"},
    { CKR_MECHANISM_INVALID, "CKR_MECHANISM_INVALID"},
    { CKR_MECHANISM_PARAM_INVALID, "CKR_MECHANISM_PARAM_INVALID"},
    { CKR_OBJECT_HANDLE_INVALID, "CKR_OBJECT_HANDLE_INVALID"},
    { CKR_OPERATION_ACTIVE, "CKR_OPERATION_ACTIVE"},
    { CKR_OPERATION_NOT_INITIALIZED, "CKR_OPERATION_NOT_INITIALIZED"},
    { CKR_PIN_INCORRECT, "CKR_PIN_INCORRECT"},
    { CKR_PIN_INVALID, "CKR_PIN_INVALID"},
    { CKR_PIN_LEN_RANGE, "CKR_PIN_LEN_RANGE"},
    { CKR_PIN_EXPIRED, "CKR_PIN_EXPIRED"},
    { CKR_PIN_LOCKED, "CKR_PIN_LOCKED"},
    { CKR_SESSION_CLOSED, "CKR_SESSION_CLOSED"},
    { CKR_SESSION_COUNT, "CKR_SESSION_COUNT"},
    { CKR_SESSION_HANDLE_INVALID, "CKR_SESSION_HANDLE_INVALID"},
    { CKR_SESSION_PARALLEL_NOT_SUPPORTED, "CKR_SESSION_PARALLEL_NOT_SUPPORTED"},
    { CKR_SESSION_READ_ONLY, "CKR_SESSION_READ_ONLY"},
    { CKR_SESSION_EXISTS, "CKR_SESSION_EXISTS"},
    { CKR_SESSION_READ_ONLY_EXISTS, "CKR_SESSION_READ_ONLY_EXISTS"},
    { CKR_SESSION_READ_WRITE_SO_EXISTS, "CKR_SESSION_READ_WRITE_SO_EXISTS"},
    { CKR_SIGNATURE_INVALID, "CKR_SIGNATURE_INVALID"},
    { CKR_SIGNATURE_LEN_RANGE, "CKR_SIGNATURE_LEN_RANGE"},
    { CKR_TEMPLATE_INCOMPLETE, "CKR_TEMPLATE_INCOMPLETE"},
    { CKR_TEMPLATE_INCONSISTENT, "CKR_TEMPLATE_INCONSISTENT"},
    { CKR_TOKEN_NOT_PRESENT, "CKR_TOKEN_NOT_PRESENT"},
    { CKR_TOKEN_NOT_RECOGNIZED, "CKR_TOKEN_NOT_RECOGNIZED"},
    { CKR_TOKEN_WRITE_PROTECTED, "CKR_TOKEN_WRITE_PROTECTED"},
    { CKR_UNWRAPPING_KEY_HANDLE_INVALID, "CKR_UNWRAPPING_KEY_HANDLE_INVALID"},
    { CKR_UNWRAPPING_KEY_SIZE_RANGE, "CKR_UNWRAPPING_KEY_SIZE_RANGE"},
    { CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"},
    { CKR_USER_ALREADY_LOGGED_IN, "CKR_USER_ALREADY_LOGGED_IN"},
    { CKR_USER_NOT_LOGGED_IN, "CKR_USER_NOT_LOGGED_IN"},
    { CKR_USER_PIN_NOT_INITIALIZED, "CKR_USER_PIN_NOT_INITIALIZED"},
    { CKR_USER_TYPE_INVALID, "CKR_USER_TYPE_INVALID"},
    { CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"},
    { CKR_USER_TOO_MANY_TYPES, "CKR_USER_TOO_MANY_TYPES"},
    { CKR_WRAPPED_KEY_INVALID, "CKR_WRAPPED_KEY_INVALID"},
    { CKR_WRAPPED_KEY_LEN_RANGE, "CKR_WRAPPED_KEY_LEN_RANGE"},
    { CKR_WRAPPING_KEY_HANDLE_INVALID, "CKR_WRAPPING_KEY_HANDLE_INVALID"},
    { CKR_WRAPPING_KEY_SIZE_RANGE, "CKR_WRAPPING_KEY_SIZE_RANGE"},
    { CKR_WRAPPING_KEY_TYPE_INCONSISTENT, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"},
    { CKR_RANDOM_SEED_NOT_SUPPORTED, "CKR_RANDOM_SEED_NOT_SUPPORTED"},
    { CKR_RANDOM_NO_RNG, "CKR_RANDOM_NO_RNG"},
    { CKR_DOMAIN_PARAMS_INVALID, "CKR_DOMAIN_PARAMS_INVALID"},
    { CKR_BUFFER_TOO_SMALL, "CKR_BUFFER_TOO_SMALL"},
    { CKR_SAVED_STATE_INVALID, "CKR_SAVED_STATE_INVALID"},
    { CKR_INFORMATION_SENSITIVE, "CKR_INFORMATION_SENSITIVE"},
    { CKR_STATE_UNSAVEABLE, "CKR_STATE_UNSAVEABLE"},
    { CKR_CRYPTOKI_NOT_INITIALIZED, "CKR_CRYPTOKI_NOT_INITIALIZED"},
    { CKR_CRYPTOKI_ALREADY_INITIALIZED, "CKR_CRYPTOKI_ALREADY_INITIALIZED"},
    { CKR_MUTEX_BAD, "CKR_MUTEX_BAD"},
    { CKR_MUTEX_NOT_LOCKED, "CKR_MUTEX_NOT_LOCKED"},
#ifdef CKR_NEW_PIN_MODE
    { CKR_NEW_PIN_MODE, "CKR_NEW_PIN_MODE"},
#endif
#ifdef CKR_NEXT_OTP
    { CKR_NEXT_OTP, "CKR_NEXT_OTP"},
#endif
    { CKR_FUNCTION_REJECTED, "CKR_FUNCTION_REJECTED"}
};

void InitAttributes(CK_ATTRIBUTE_PTR attr, unsigned int n)
{
    while (n--) {
        if ((attr[n].ulValueLen) && (attr[n].pValue == 0))
            attr[n].pValue = calloc(attr[n].ulValueLen,1);
    }
}

void AddAttribute(CK_ATTRIBUTE_PTR attr, int type, const void *Value, size_t size)
{
    attr->type = type;
    attr->pValue = (size)?malloc(size):0;
    memcpy(attr->pValue, Value, size);
    attr->ulValueLen = size;
}

void FlushAttributes(CK_ATTRIBUTE_PTR attr, unsigned int n)
{
    while (n--) {
        if (attr[n].pValue) free(attr[n].pValue);
    }
}

const void* Get_Val(CK_ATTRIBUTE_PTR attr,unsigned type,unsigned int n)
{
    while (n--) {
        if (attr[n].type == type) return attr[n].pValue;
    }
    return 0;
}

CK_ULONG Get_Val_ul(CK_ATTRIBUTE_PTR attr,unsigned type,unsigned int n)
{
    CK_ULONG Value = 0;
    while (n--) {
        if (attr[n].type == type) memcpy(&Value, attr[n].pValue, sizeof(CK_ULONG));
    }
    return Value;
}

unsigned int Get_Val_Len(CK_ATTRIBUTE_PTR attr,unsigned int type,unsigned int n)
{
    while (n--) {
        if (attr[n].type == type) return attr[n].ulValueLen;
    }
    return 0;
}

const char* get_rv_str(CK_RV rv)
{
    int i=0;
    while(error_str[i].rv_str != 0) {
        if (error_str[i].rv == rv) return error_str[i].rv_str;
        i++;
    }
    return 0;
}

/*
 * Handles return values from PKCS11 functions
 *
 * if return value is not CKR_OK (0x00000000), the function will exit.
 * for convenience, a message can be displayed alongside the error message.
 */

void check_rv (const char *message,CK_RV rv)
{
    if (rv != CKR_OK) {
		fprintf(stderr, "Error %s in %s\n", get_rv_str(rv), message); 
		exit(1); 
	}

}

CK_ULONG LabelExists(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label)
{
    CK_ULONG count = 0;
    CK_OBJECT_HANDLE key;
    CK_ATTRIBUTE search[1];
    AddAttribute(search,CKA_LABEL,label,strlen ((char *) label));
    check_rv("C_FindObjectsInit", sym->C_FindObjectsInit (ses, search, 1));
    FlushAttributes(search,1);
    check_rv("C_FindObjects", sym->C_FindObjects(ses, &key, 1, &count));
    check_rv("C_FindObjectsFinal", sym->C_FindObjectsFinal(ses));
    return count;
}

CK_ULONG IDExists(CK_SESSION_HANDLE ses, uuid_t uu)
{
    CK_ULONG count = 0;
    CK_OBJECT_HANDLE key;
    CK_ATTRIBUTE search[1];
    AddAttribute(search,CKA_ID,uu,sizeof(uuid_t));
    check_rv("C_FindObjectsInit", sym->C_FindObjectsInit (ses, search, 1));
    FlushAttributes(search,1);
    check_rv("C_FindObjects", sym->C_FindObjects(ses, &key, 1, &count));
    check_rv("C_FindObjectsFinal", sym->C_FindObjectsFinal(ses));
    return count;
}

CK_SLOT_ID GetSlot()
{
    /* Get list of all slots with a token present, and returns the first of the list */
    CK_SLOT_ID_PTR slotList = (CK_SLOT_ID_PTR) malloc(0);
    CK_ULONG slotcnt = 0;
    CK_RV rv = 0;
    CK_SLOT_ID id = 0;
    while (1) {
        rv =sym->C_GetSlotList(CK_TRUE, slotList, &slotcnt);
        if (rv != CKR_BUFFER_TOO_SMALL) break;
        slotList = realloc(slotList,slotcnt * sizeof(CK_SLOT_ID));
    }
    id = slotList[0];
    return id;
}

void bin2hex (int len, unsigned char *binnum, char *hexnum)
{
    char hex[16] ="0123456789abcdef";
    int i;
    unsigned val;
    for (i = 0; i < len; i++) {
        val = binnum[i];
        hexnum[i * 2] = hex[val >> 4];
        hexnum[i * 2 + 1] = hex[val & 0xf];
    }
    hexnum[len * 2] = 0;
}

