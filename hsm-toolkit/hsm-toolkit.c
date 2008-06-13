/*
 * $Id$
 *
 * Copyright 2008 Nominet UK,
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <security/cryptoki.h>

typedef unsigned char BOOL;
static CK_BBOOL    true    = CK_TRUE;
static CK_BBOOL    false   = CK_FALSE;

/*

 The working of hsm-toolkit is straightforward.

 o  It searches the HSM to see if the label already exists.
 o  If not, it will generate a public/private keypair.

*/

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
        fprintf (stderr, "Error  0x%.8X in %s\n", (unsigned int) rv, message);
        exit (1);
    }
}

CK_ULONG
LabelExists(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label)
{
    CK_ATTRIBUTE search[] =
    {
        {
            CKA_LABEL, label, strlen ((char *) label)
        }
    };
    CK_ULONG count = 0;
    CK_OBJECT_HANDLE key;

    CK_RV rv = C_FindObjectsInit (ses, search, 1);
    check_rv("C_FindObjectsInit", rv );

    rv = C_FindObjects(ses, &key, 1, &count);
    check_rv("C_FindObjects", rv );

    rv = C_FindObjectsFinal(ses);
    check_rv("C_FindObjectsFinal", rv );
    return count;
}

void
GoRemoveKeypair(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label)
{
    CK_ATTRIBUTE search[] =
    {
        {
            CKA_LABEL, label, strlen ((char *) label)
        }
    };
    CK_ULONG count = 0;
    CK_OBJECT_HANDLE key;

    CK_RV rv = C_FindObjectsInit (ses, search, 1);
    check_rv("C_FindObjectsInit", rv );

    while (1)
    {
        rv = C_FindObjects(ses, &key, 1, &count);
        check_rv("C_FindObjects", rv);
        if (count == 0) break;
        rv = C_DestroyObject(ses, key);
        check_rv("C_DestroyObject",rv);
        printf("Destroyed RSA key, labeled %s\n",label);
    }

    rv = C_FindObjectsFinal(ses);
    check_rv("C_FindObjectsFinal", rv );
}

void
ListKeys(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label, int Act)
{
    CK_ULONG count = 0;
    CK_RV rv;
    if (label != NULL_PTR)
    {
        // list one
        CK_ATTRIBUTE search[] =
        {
            {
                CKA_LABEL, label, strlen ((char *) label)
            }
        };
        rv = C_FindObjectsInit (ses, search, 1);
    }
    else
    {
        // list all
        rv = C_FindObjectsInit (ses, NULL_PTR, 0);
    }
    check_rv("C_FindObjectsInit", rv );

    CK_OBJECT_HANDLE key;
    CK_KEY_TYPE keytype;
    CK_OBJECT_CLASS class = 0;
    while (1)
    {
        CK_ATTRIBUTE attributes[] =
        {
            {CKA_CLASS, &class, sizeof(class)},
            {CKA_LABEL, NULL_PTR, 0},
            {CKA_MODULUS, NULL_PTR, 0},
            {CKA_KEY_TYPE, &keytype, sizeof(keytype)}
        };

        rv = C_FindObjects(ses, &key, 1, &count);
        check_rv("C_FindObjects", rv);
        if (count == 0) break;
        rv = C_GetAttributeValue(ses, key, attributes, 4);
        check_rv("C_GetAttributeValue",rv);
        attributes[1].pValue = malloc(attributes[1].ulValueLen);
        attributes[2].pValue = malloc(attributes[2].ulValueLen);
        rv = C_GetAttributeValue(ses, key, attributes, 4);
        check_rv("C_GetAttributeValue",rv);
        if (Act & 1)
        {
            printf("%d-bit %s RSA key, labeled %s, keytype 0x%.8X\n",
                (int) attributes[2].ulValueLen *8,
                (class == CKO_PRIVATE_KEY)?"Private":"Public ",
                (char*)attributes[1].pValue,
                (unsigned int) keytype);
        }
        if (Act & 4)
        {
            printf("DNSKEY, labeled %s\n",
                (char*)attributes[1].pValue);
        }
        free(attributes[1].pValue);
        free(attributes[2].pValue);
        free(attributes[3].pValue);
    }

    rv = C_FindObjectsFinal(ses);
    check_rv("C_FindObjectsFinal", rv );
}

void
GoGenerateKeypair(CK_SESSION_HANDLE ses, CK_UTF8CHAR* label, CK_ULONG modulus)
{
    if (LabelExists(ses,label))
    {
        fprintf (stderr, "Key with label '%s' exists.\n",(char*)label);
        exit (1);
    }

    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    /* Template for Public Key */
    CK_BYTE pubex[] = { 1, 0, 1 };
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ATTRIBUTE publickey_template[] =
    {
        {CKA_LABEL, label, strlen ((char *) label)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_VERIFY, &true, sizeof (true)},
        {CKA_ENCRYPT, &true, sizeof (false)},
        {CKA_WRAP, &true, sizeof (false)},
        {CKA_TOKEN, &true, sizeof (true)},
        {CKA_MODULUS_BITS, &modulus, sizeof (modulus)},
        {CKA_PUBLIC_EXPONENT, &pubex, sizeof (pubex)}
    };

    /* A template to generate a private key */
    CK_ATTRIBUTE privatekey_template[] =
    {
        {CKA_LABEL, label, strlen ((char *) label)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_SIGN, &true, sizeof (true)},
        {CKA_DECRYPT, &true, sizeof (true)},
        {CKA_TOKEN, &true, sizeof (true)},
        {CKA_PRIVATE, &true, sizeof (true)},
        {CKA_SENSITIVE, &false, sizeof (false)},
        {CKA_UNWRAP, &true, sizeof (true)},
        {CKA_EXTRACTABLE, &true, sizeof (true)}
    };
    CK_OBJECT_HANDLE privatekey, publickey;
    CK_RV rv = C_GenerateKeyPair(ses, &mech, publickey_template, 8,
        privatekey_template, 9,
        &publickey, &privatekey);
    check_rv("C_GenerateKeyPair", rv);
    printf("Created RSA key pair, labeled %s\n",label);
}

int
main (int argc, char *argv[])
{
    CK_UTF8CHAR *pin    = NULL;                   // NO DEFAULT VALUE
    CK_SLOT_ID  slot    = 0;                      // default value
    CK_UTF8CHAR *label  = NULL_PTR;               // NO DEFAULT VALUE
    CK_ULONG    modulus = 1024;                   // default value
    CK_RV       rv      = CKR_OK;
    int         Action  = 0;

    int opt;
    while ((opt = getopt (argc, argv, "GRPLb:p:s:")) != -1)
    {
        switch (opt)
        {
            case 'L':                             // List
                Action = (Action | 1);
                break;
            case 'G':                             // Generate
                Action = (Action | 2);
                break;
            case 'P':                             // Print Public
                Action = (Action | 4);
                break;
            case 'R':                             // Remove
                Action = (Action | 8);
                break;
            case 'b':
                modulus = atoi (optarg);
                break;
            case 'p':
                pin = (CK_UTF8CHAR*)optarg;
                break;
            case 's':
                slot = atoi (optarg);
                break;
            default:
                fprintf (stderr, "Unrecognised option: -%c\n", optopt);
                exit (2);
        }
    }
    if (Action > 8)
    {
        fprintf (stderr, "Removing a key can't be used with other actions\n");
        exit (2);
    }

    if ((argc <= optind) && (Action && 5)==0)
    {
        fprintf (stderr,
            "usage: hsm-toolkit [GRDL] [-s slot] [-p pin] [-b keysize] label\n");
        exit (2);
    }
    label = (CK_UTF8CHAR *) argv[optind];

    /*
     * C_Initialize
     */

    rv = C_Initialize (NULL_PTR);
    check_rv("C_Initialize",rv);

    /*
     * C_OpenSession
     */

    CK_SESSION_HANDLE ses;
    rv = C_OpenSession (slot, CKF_RW_SESSION + CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &ses);
    check_rv("C_OpenSession",rv);

    /*
     * C_Login
     */

    // pin can be specified on demand
    if (!pin) pin = (CK_UTF8CHAR *) getpassphrase ("Enter Pin: ");
    rv = C_Login(ses, CKU_USER, pin, strlen ((char*)pin));

    memset(pin, 0, strlen((char *)pin));

    check_rv("C_Login", rv);
    if (Action & 2) GoGenerateKeypair(ses,label,modulus);
    if (Action & 5) ListKeys(ses,label,Action);
    if (Action & 8) GoRemoveKeypair(ses,label);

    rv = C_Logout(ses);
    check_rv("C_Logout", rv );

    rv = C_CloseSession(ses);
    check_rv("C_CloseSession", rv );

    rv = C_Finalize (NULL_PTR);
    check_rv("C_Finalize", rv);

    exit (0);
}
