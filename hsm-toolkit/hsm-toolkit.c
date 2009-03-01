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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "cryptoki.h"

// typedef unsigned char BOOL;
static CK_BBOOL    true    = CK_TRUE;
static CK_BBOOL    false   = CK_FALSE;

/*

 The working of hsm-toolkit is straightforward.
 o  If no arguments are given, the toolkit uses the following defaults:
 o  It prompts for the PIN, reads slot:0 for keys.
 o
 o  When generating keys, it will first search the slot to see if the label
 o  already exists.
 o
*/

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
    { CKR_NEW_PIN_MODE, "CKR_NEW_PIN_MODE"},
    { CKR_NEXT_OTP, "CKR_NEXT_OTP"},
    { CKR_FUNCTION_REJECTED, "CKR_FUNCTION_REJECTED"}
};

void Add_Attr(CK_ATTRIBUTE_PTR attr, int type, const void *Value, size_t size)
{
    attr->type = type;
    attr->pValue = (size)?malloc(size):NULL_PTR;
    memcpy(attr->pValue, Value, size);
    attr->ulValueLen = size;
}

void Flush_Attrs(CK_ATTRIBUTE_PTR attr, unsigned int n)
{
    while (n--)
    {
        if (attr[n].pValue) free(attr[n].pValue);
    }
}

const void* Get_Val_string(CK_ATTRIBUTE_PTR attr,unsigned type,unsigned int n)
{   
    while (n--)
    {
        if (attr[n].type == type) return attr[n].pValue;
    }
	return NULL_PTR;
}

CK_ULONG Get_Val_ul(CK_ATTRIBUTE_PTR attr,unsigned type,unsigned int n)
{   CK_ULONG Value = 0;
    while (n--)
    {
        if ((attr+n)->type == type) memcpy(&Value, (attr+n)->pValue,sizeof(CK_ULONG));
    }
	return Value;
}

unsigned int Get_Val_Len(CK_ATTRIBUTE_PTR attr,unsigned int type,unsigned int n)
{
    while (n--)
    {
        if (attr[n].type == type) return attr[n].ulValueLen;
    }
    return 0;
}

void Init_Attrs(CK_ATTRIBUTE_PTR attr, unsigned int n)
{
    while (n--)	
    {
        if ((attr[n].ulValueLen) && (attr[n].pValue == NULL_PTR))
			attr[n].pValue = calloc(attr[n].ulValueLen,1);
    }
}

const char*
get_rv_str(CK_RV rv)
{
    int i=0;
    while(error_str[i].rv_str != NULL_PTR)
    {
        if (error_str[i].rv == rv) return error_str[i].rv_str;
        i++;
    }
    return NULL;
}

/*
 * Handles return values from PKCS11 functions
 *
 * if return value is not CKR_OK (0x00000000), the function will exit.
 * for convenience, a message can be displayed alongside the error message.
 */

void
check_rv (const char *message,CK_RV rv)
{
    if (rv != CKR_OK)
    {
        fprintf (stderr, "Error %s in %s\n", get_rv_str(rv), message);
        exit (1);
    }
}

CK_ULONG
LabelExists(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label)
{
    CK_ULONG count = 0;
    CK_OBJECT_HANDLE key;
    CK_ATTRIBUTE search[1];
    Add_Attr(search,CKA_LABEL,label,strlen ((char *) label));
    check_rv("C_FindObjectsInit", C_FindObjectsInit (ses, search, 1));
    Flush_Attrs(search,1);
    check_rv("C_FindObjects", C_FindObjects(ses, &key, 1, &count));
    check_rv("C_FindObjectsFinal", C_FindObjectsFinal(ses));
    return count;
}

void
ActionRemoveObject(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label)
{
    if (label==NULL_PTR)
    {
        fprintf (stderr, "No label specified.\n");
        exit (1);
    }

    if (!LabelExists(ses,label))
    {
        fprintf (stderr, "Object with label '%s' does not exist.\n",(char*)label);
        exit (1);
    }

    CK_ATTRIBUTE search[1];
    Add_Attr(search,CKA_LABEL,label,strlen ((char *) label));

    CK_OBJECT_CLASS class = 0;
    CK_ATTRIBUTE attributes[1];
    Add_Attr(attributes,CKA_CLASS, &class, sizeof(class));

    CK_ULONG count = 0;
    CK_OBJECT_HANDLE object;

    check_rv("C_FindObjectsInit", C_FindObjectsInit (ses, search, 1));
    Flush_Attrs(search,1);
    while (1)
    {
        check_rv("C_FindObjects", C_FindObjects(ses, &object, 1, &count));
        if (count == 0) break;
        check_rv("C_GetAttributeValue",C_GetAttributeValue(ses, object, attributes, 1));
        check_rv("C_DestroyObject",C_DestroyObject(ses, object));
        printf("Destroyed %s key object, labeled %s\n",(class == CKO_PRIVATE_KEY)?"Private":"Public ",label);
    }
    Flush_Attrs(attributes,1);
    check_rv("C_FindObjectsFinal", C_FindObjectsFinal(ses));
}

void
ActionListObjects(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label)
{
    unsigned int cnt  = 0;
    CK_ATTRIBUTE template[32];
    if (label) Add_Attr(template+cnt++,CKA_LABEL, label, strlen ((char *) label));
    check_rv("C_FindObjectsInit", C_FindObjectsInit (ses, template, cnt));
    Flush_Attrs(template,cnt);
    CK_OBJECT_HANDLE object;
    CK_ULONG found = 0;
    check_rv("C_FindObjects",C_FindObjects(ses, &object, 1, &found));
    while (found)
    {
        cnt = 0;
        Add_Attr(template+cnt++,CKA_CLASS,NULL_PTR,0);
        Add_Attr(template+cnt++,CKA_LABEL,NULL_PTR,0);
        Add_Attr(template+cnt++,CKA_MODULUS,NULL_PTR,0);
        check_rv("C_GetAttributeValue",C_GetAttributeValue(ses, object, template, cnt));
        Init_Attrs(template,cnt);
        check_rv("C_GetAttributeValue",C_GetAttributeValue(ses, object, template, cnt));
		
		printf("%d-bit %s key object, labeled %s\n",
            (int) Get_Val_Len(template,CKA_MODULUS,cnt) *8,
            (Get_Val_ul(template,CKA_CLASS,cnt)== CKO_PRIVATE_KEY)?"Private":"Public ",
            (char*) Get_Val_string(template,CKA_LABEL,cnt));
        Flush_Attrs(template,cnt);
        check_rv("C_FindObjects", C_FindObjects(ses, &object, 1, &found));
    }
    check_rv("C_FindObjectsFinal", C_FindObjectsFinal(ses));
}

void
ActionGenerateObject(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label, CK_ULONG keysize)
{
    if (keysize <512)
    {
        fprintf (stderr, "Keysize (%u) too small.\n",(int)keysize);
        exit (1);
    }
    if (label==NULL_PTR)
    {
        fprintf (stderr, "No label specified.\n");
        exit (1);
    }

    if (LabelExists(ses,label))
    {
        fprintf (stderr, "Key with label '%s' already exists.\n",(char*)label);
        exit (1);
    }

    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

    /* A template to generate an RSA public key objects*/
    CK_BYTE pubex[3] = { 1, 0, 1 };
    CK_KEY_TYPE keyType = CKK_RSA;
    unsigned int cnt1  = 0;
	CK_ATTRIBUTE pub_temp[32];
    Add_Attr(pub_temp+cnt1++,CKA_LABEL, label, strlen ((char *) label));
    Add_Attr(pub_temp+cnt1++,CKA_ID,"",0);
    Add_Attr(pub_temp+cnt1++,CKA_KEY_TYPE, &keyType, sizeof(keyType));
	Add_Attr(pub_temp+cnt1++,CKA_VERIFY, &true, sizeof (true));
	Add_Attr(pub_temp+cnt1++,CKA_ENCRYPT, &false, sizeof (false));
	Add_Attr(pub_temp+cnt1++,CKA_WRAP, &false, sizeof (false));
	Add_Attr(pub_temp+cnt1++,CKA_TOKEN, &true, sizeof (true));
	Add_Attr(pub_temp+cnt1++,CKA_MODULUS_BITS, &keysize, sizeof (keysize));
	Add_Attr(pub_temp+cnt1++,CKA_PUBLIC_EXPONENT, &pubex, sizeof (pubex));
    /* A template to generate an RSA private key objects*/
    unsigned int cnt2  = 0;
	CK_ATTRIBUTE pri_temp[32];
    Add_Attr(pri_temp+cnt2++,CKA_LABEL, label, strlen ((char *) label));
    Add_Attr(pri_temp+cnt2++,CKA_ID,"",0);
    Add_Attr(pri_temp+cnt2++,CKA_KEY_TYPE, &keyType, sizeof(keyType));
	Add_Attr(pri_temp+cnt2++,CKA_SIGN, &true, sizeof (true));
	Add_Attr(pri_temp+cnt2++,CKA_DECRYPT, &false, sizeof (false));
	Add_Attr(pri_temp+cnt2++,CKA_UNWRAP, &false, sizeof (false));
	Add_Attr(pri_temp+cnt2++,CKA_SENSITIVE, &false, sizeof (false));
	Add_Attr(pri_temp+cnt2++,CKA_TOKEN, &true, sizeof (true));
	Add_Attr(pri_temp+cnt2++,CKA_PRIVATE, &true, sizeof (true));
	Add_Attr(pri_temp+cnt2++,CKA_EXTRACTABLE, &true, sizeof (true));
    CK_OBJECT_HANDLE ignore;
    check_rv("C_GenerateKeyPair", C_GenerateKeyPair(ses, &mech, pub_temp, cnt1,
        pri_temp, 10, &ignore,&ignore));
    printf("Created RSA key pair object, labeled %s\n",label);
}

CK_SLOT_ID GetSlot() {
	/* Get list of all slots with a token present */ 
	CK_SLOT_ID_PTR slotList = (CK_SLOT_ID_PTR) malloc(0); 
	CK_ULONG slotcnt = 0; 
	CK_RV rv = 0;
	CK_SLOT_ID id = 0;
	while (1) {
    	rv =C_GetSlotList(CK_TRUE, slotList, &slotcnt); 
  		if (rv != CKR_BUFFER_TOO_SMALL) break; 
		slotList = realloc(slotList,slotcnt * sizeof(CK_SLOT_ID)); 
	}
	id = slotList[0];
	return id;
}

int
main (int argc, char *argv[])
{
    CK_UTF8CHAR *pin    = NULL_PTR;               // NO DEFAULT VALUE
    CK_UTF8CHAR *label  = NULL_PTR;               // NO DEFAULT VALUE
    CK_SLOT_ID  slot    = 0;                      // default value
	CK_BBOOL	slot_specified = false;
    CK_ULONG    keysize = 1024;                   // default value
    CK_SESSION_HANDLE ses;
    int Action  = 0;
    int opt;
    while ((opt = getopt (argc, argv, "GDb:p:s:h")) != -1)
    {
        switch (opt)
        {
            case 'G': Action = 1; break;
            case 'D': Action = 2; break;
            case 'b': keysize = atoi (optarg); break;
            case 'p': pin = (CK_UTF8CHAR*)optarg; break;
			case 's': slot = atoi (optarg); slot_specified=true;break;
            case 'h': fprintf (stderr,
                "usage: hsm-toolkit [-s slot] [-p pin] [-G [-b keysize] label] [-D label]\n");
            exit (2);

        }
    }

    label = (CK_UTF8CHAR *) argv[optind];
    check_rv("C_Initialize",C_Initialize (NULL_PTR));
	if (!slot_specified) slot = GetSlot();
    check_rv("C_OpenSession",C_OpenSession (slot, CKF_RW_SESSION + CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &ses));

    if (!pin) pin = (CK_UTF8CHAR *) getpass ("Enter Pin: ");
    check_rv("C_Login", C_Login(ses, CKU_USER, pin, strlen ((char*)pin)));
	memset(pin, 0, strlen((char *)pin));
    switch (Action)
    {
        case 1: ActionGenerateObject(ses,label,keysize); break;
        case 2: ActionRemoveObject(ses,label); break;
        default:
            ActionListObjects(ses,label);
    }
    check_rv("C_Logout", C_Logout(ses));
    check_rv("C_CloseSession", C_CloseSession(ses));
    check_rv("C_Finalize", C_Finalize (NULL_PTR));
    exit (0);
}
