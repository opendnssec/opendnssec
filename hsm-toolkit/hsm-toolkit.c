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
#include <uuid/uuid.h>
#include <dlfcn.h>
#include <cryptoki.h>
#include <pktools.h>
#include "config.h"

const  CK_BBOOL             ctrue  = CK_TRUE;
const  CK_BBOOL             cfalse = CK_FALSE;
extern CK_FUNCTION_LIST_PTR sym;


void RemoveObject(CK_SESSION_HANDLE session, uuid_t uuid)
{
    CK_ULONG         found = 0;
    CK_ATTRIBUTE     template[2];
    CK_OBJECT_HANDLE object;
    char             uuid_str[37];

    uuid_unparse(uuid,uuid_str);

    if (!IDExists(session,uuid)) {
		fprintf (stderr,"Object with id:%s does not exist.\n", uuid_str);
		exit(1);
	}

    AddAttribute(template,CKA_ID,uuid,sizeof(uuid_t));
    AddAttribute(template+1,CKA_CLASS, 0, 0);
    check_rv("C_FindObjectsInit", sym->C_FindObjectsInit (session, template, 1));
    check_rv("C_FindObjects", sym->C_FindObjects(session, &object, 1, &found));
    while (found) {
        check_rv("C_GetAttributeValue",sym->C_GetAttributeValue(session, object, template, 2));
        InitAttributes(template,2);
        check_rv("C_GetAttributeValue",sym->C_GetAttributeValue(session, object, template, 2));
        check_rv("C_DestroyObject",sym->C_DestroyObject(session, object));
        fprintf(stdout, "Destroyed %s key object: %s\n",(Get_Val_ul(template,CKA_CLASS,2) == CKO_PRIVATE_KEY)?"Private":"Public ",uuid_str);
        check_rv("C_FindObjects", sym->C_FindObjects(session, &object, 1, &found));
    }
    FlushAttributes(template,2);
    check_rv("C_FindObjectsFinal", sym->C_FindObjectsFinal(session));
}

void ListObjects(CK_SESSION_HANDLE session)
{
    CK_ULONG         found = 0;
    CK_ATTRIBUTE     template[4];
    CK_OBJECT_HANDLE object;
    unsigned char*   id;
    char             id_str[128];
    check_rv("C_FindObjectsInit", sym->C_FindObjectsInit (session, 0, 0));
    check_rv("C_FindObjects",sym->C_FindObjects(session, &object, 1, &found));
    while (found) {
        AddAttribute(template,CKA_CLASS,0,0);
        AddAttribute(template+1,CKA_LABEL,0,0);
        AddAttribute(template+2,CKA_MODULUS,0,0);
        AddAttribute(template+3,CKA_ID,0,0);
        check_rv("C_GetAttributeValue",sym->C_GetAttributeValue(session, object, template, 4));
        InitAttributes(template,4);
        check_rv("C_GetAttributeValue",sym->C_GetAttributeValue(session, object, template, 4));
        id = (unsigned char*) Get_Val(template, CKA_ID,4);
        bin2hex(Get_Val_Len(template,CKA_ID,4), id, id_str);
        fprintf(stdout,"%d-bit %s key object, label:%s, id:%s\n",
            (int) Get_Val_Len(template,CKA_MODULUS,4) *8,
            (Get_Val_ul(template,CKA_CLASS,4)== CKO_PRIVATE_KEY)?"Private":"Public ",
            (char*) Get_Val(template,CKA_LABEL,4),
            id_str);
        FlushAttributes(template,4);
        check_rv("C_FindObjects", sym->C_FindObjects(session, &object, 1, &found));
    }
    check_rv("C_FindObjectsFinal", sym->C_FindObjectsFinal(session));
}

void GenerateObject(CK_SESSION_HANDLE session, CK_ULONG keysize)
{

    CK_ATTRIBUTE     pub_temp[ 9];
    CK_ATTRIBUTE     pri_temp[10];
    CK_MECHANISM     mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 };
    CK_BYTE          pubex[3] = { 1, 0, 1 };
    CK_KEY_TYPE      keyType = CKK_RSA;
    CK_OBJECT_HANDLE ignore;

    uuid_t           uuid;
    char             uuid_str[37];


    if (keysize <512) {
		fprintf(stderr, "Keysize (%u) too small.\n",(int)keysize);
		exit(1);
	}
    do uuid_generate(uuid); while (IDExists(session,uuid));

    uuid_unparse(uuid, uuid_str);

    /* A template to generate an RSA public key objects*/
    AddAttribute(pub_temp  ,CKA_LABEL,(CK_UTF8CHAR*) uuid_str, strlen (uuid_str));
    AddAttribute(pub_temp+1,CKA_ID,              uuid,     sizeof(uuid_t));
    AddAttribute(pub_temp+2,CKA_KEY_TYPE,        &keyType, sizeof(keyType));
    AddAttribute(pub_temp+3,CKA_VERIFY,          &ctrue,   sizeof (ctrue));
    AddAttribute(pub_temp+4,CKA_ENCRYPT,         &cfalse,  sizeof (cfalse));
    AddAttribute(pub_temp+5,CKA_WRAP,            &cfalse,  sizeof (cfalse));
    AddAttribute(pub_temp+6,CKA_TOKEN,           &ctrue,   sizeof (ctrue));
    AddAttribute(pub_temp+7,CKA_MODULUS_BITS,    &keysize, sizeof (keysize));
    AddAttribute(pub_temp+8,CKA_PUBLIC_EXPONENT, &pubex,   sizeof (pubex));

    /* A template to generate an RSA private key objects*/
    AddAttribute(pri_temp,  CKA_LABEL,(CK_UTF8CHAR *) uuid_str, strlen (uuid_str));
    AddAttribute(pri_temp+1,CKA_ID,          uuid,     sizeof(uuid_t));
    AddAttribute(pri_temp+2,CKA_KEY_TYPE,    &keyType, sizeof(keyType));
    AddAttribute(pri_temp+3,CKA_SIGN,        &ctrue,   sizeof (ctrue));
    AddAttribute(pri_temp+4,CKA_DECRYPT,     &cfalse,  sizeof (cfalse));
    AddAttribute(pri_temp+5,CKA_UNWRAP,      &cfalse,  sizeof (cfalse));
    AddAttribute(pri_temp+6,CKA_SENSITIVE,   &cfalse,  sizeof (cfalse));
    AddAttribute(pri_temp+7,CKA_TOKEN,       &ctrue,   sizeof (ctrue));
    AddAttribute(pri_temp+8,CKA_PRIVATE,     &ctrue,   sizeof (ctrue));
    AddAttribute(pri_temp+9,CKA_EXTRACTABLE, &ctrue,   sizeof (ctrue));
    check_rv("C_GenerateKeyPair", sym->C_GenerateKeyPair(session, &mech, pub_temp, 9, pri_temp, 10, &ignore,&ignore));
    fprintf(stdout,"Created RSA key pair object, labeled %s\n",uuid_str);
}

int
main (int argc, char *argv[])
{
    CK_UTF8CHAR *pin = 0;                         // NO DEFAULT VALUE
    CK_SLOT_ID slot = 0;                          // default value
    CK_BBOOL slot_specified = cfalse;
    CK_ULONG keysize = 1024;                      // default value
    CK_SESSION_HANDLE ses;
    uuid_t uuid;
    int Action  = 0;
    int opt;
    unsigned int nkeys = 1;
    char *pklib = 0;
    while ((opt = getopt (argc, argv, "GDb:l:n:p:s:h")) != -1) {
        switch (opt) {
            case 'G': Action = 1; break;
            case 'D': Action = 2; break;
            case 'b': keysize = atoi (optarg); break;
            case 'l': pklib = optarg; break;
            case 'n': nkeys = atoi (optarg); break;
            case 'p': pin = (CK_UTF8CHAR*)optarg; break;
            case 's': slot = atoi (optarg); slot_specified=ctrue;break;
            case 'h': fprintf(stderr, "usage: hsm-toolkit -l pkcs11-library [-s slot] [-p pin] [-n number-of-keys] [-G [-b keysize]] [-D UUID-string]\n");
					  exit(2);		
		}
   	}
    if (!pklib) {
		fprintf (stderr, "Please specify a pkcs11 library.\n");
		exit(1);
	}

    void *handle = dlopen(pklib, RTLD_NOW);
    if (!handle) {
 		fprintf (stderr, "%s: dlopen: `%s'\n", pklib, dlerror ());
		exit(1);
	}

    void (*gGetFunctionList)() = dlsym(handle, "C_GetFunctionList");
    if (!gGetFunctionList) {
 		fprintf (stderr, "%s: dlsym: `C_GetFunctionList'\n", dlerror ());
		exit(1);
	}
    gGetFunctionList(&sym);

    check_rv("C_Initialize",sym->C_Initialize(0));
    if (!slot_specified) slot = GetSlot();
    check_rv("C_OpenSession",sym->C_OpenSession (slot, CKF_RW_SESSION + CKF_SERIAL_SESSION, 0, 0, &ses));

    if (!pin) pin = (CK_UTF8CHAR *) 
#ifdef HAVE_GETPASSPHRASE 
		getpassphrase("Enter Pin:"); 
#else 
	getpass("Enter Pin:");
#endif
    check_rv("C_Login", sym->C_Login(ses, CKU_USER, pin, strlen ((char*)pin)));
    memset(pin, 0, strlen((char *)pin));
    switch (Action) {
	case 1: while(nkeys>0 && nkeys--) GenerateObject(ses,keysize); break;
        case 2: if (uuid_parse(argv[optind],uuid)) {
					fprintf (stderr, "argument %s is not a valid UUID string\n", argv[optind]);
					exit(1);
				}
				RemoveObject(ses,uuid); break;
        default:
            ListObjects(ses);
    }
    check_rv("C_Logout", sym->C_Logout(ses));
    check_rv("C_CloseSession", sym->C_CloseSession(ses));
    check_rv("C_Finalize", sym->C_Finalize (0));
    dlclose(handle);
    exit (0);
}
