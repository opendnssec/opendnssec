#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <dlfcn.h>
#include <cryptoki.h>
#include <pktools.h>

extern CK_FUNCTION_LIST_PTR sym;
void *handle;
CK_SESSION_HANDLE ses;
const  CK_BBOOL             ctrue  = CK_TRUE;
const  CK_BBOOL             cfalse = CK_FALSE;

/* Links to pkcs11 lib
* returns 1 if fail
*/
int
PK_LinkLib(char *pklib)
{
  handle = dlopen(pklib, RTLD_NOW);
  if (!handle) {
		fprintf (stderr, "%s: dlopen: `%s'\n", pklib, dlerror ());
	return(1);
	}

  void (*gGetFunctionList)() = dlsym(handle, "C_GetFunctionList");
  if (!gGetFunctionList) {
		fprintf (stderr, "dlsym: C_GetFunctionList: %s\n", dlerror ());
	return(1);
  }
  gGetFunctionList(&sym);
}

/* unLinks to pkcs11 lib
* returns 1 if fail
*/
int
PK_UnlinkLib()
{
  int status;
  status = dlclose(handle);
  if (status == -1){
    fprintf (stderr, "dlclose: %s'\n", dlerror ());
    return 1;
  }
  return 0;
}

int    
PK_Startup(int slot, char *pin)
{
  check_rv("C_Initialize",sym->C_Initialize(0));
  check_rv("C_OpenSession",sym->C_OpenSession ((CK_SLOT_ID)slot, CKF_RW_SESSION + CKF_SERIAL_SESSION, 0, 0, &ses));

  if (!pin) pin = getpass ("Enter Pin: ");
  check_rv("C_Login", sym->C_Login(ses, CKU_USER, (CK_UTF8CHAR*)pin, strlen (pin)));
  memset(pin, 0, strlen(pin));
}

int
PK_Shutdown()
{
  check_rv("C_Logout", sym->C_Logout(ses));
  check_rv("C_CloseSession", sym->C_CloseSession(ses));
  check_rv("C_Finalize", sym->C_Finalize (0));
}


void
PK_RemoveObject(uuid_t uuid)
{
    CK_ULONG         found = 0;
    CK_ATTRIBUTE     template[2];
    CK_OBJECT_HANDLE object;
    char             uuid_str[37];

    uuid_unparse_lower(uuid,uuid_str);

    if (!IDExists(ses,uuid)) {
		fprintf (stderr,"Object with id:%s does not exist.\n", uuid_str);
		exit(1);
	}

    AddAttribute(template,CKA_ID,uuid,sizeof(uuid_t));
    AddAttribute(template+1,CKA_CLASS, 0, 0);
    check_rv("C_FindObjectsInit", sym->C_FindObjectsInit (ses, template, 1));
    check_rv("C_FindObjects", sym->C_FindObjects(ses, &object, 1, &found));
    while (found) {
        check_rv("C_GetAttributeValue",sym->C_GetAttributeValue(ses, object, template, 2));
        InitAttributes(template,2);
        check_rv("C_GetAttributeValue",sym->C_GetAttributeValue(ses, object, template, 2));
        check_rv("C_DestroyObject",sym->C_DestroyObject(ses, object));
        fprintf(stdout, "Destroyed %s key object: %s\n",(Get_Val_ul(template,CKA_CLASS,2) == CKO_PRIVATE_KEY)?"Private":"Public ",uuid_str);
        check_rv("C_FindObjects", sym->C_FindObjects(ses, &object, 1, &found));
    }
    FlushAttributes(template,2);
    check_rv("C_FindObjectsFinal", sym->C_FindObjectsFinal(ses));
}

void
PK_ListObjects()
{
    CK_ULONG         found = 0;
    CK_ATTRIBUTE     template[4];
    CK_OBJECT_HANDLE object;
    unsigned char*   id;
    char             id_str[128];
    check_rv("C_FindObjectsInit", sym->C_FindObjectsInit (ses, 0, 0));
    check_rv("C_FindObjects",sym->C_FindObjects(ses, &object, 1, &found));
    while (found) {
        AddAttribute(template,CKA_CLASS,0,0);
        AddAttribute(template+1,CKA_LABEL,0,0);
        AddAttribute(template+2,CKA_MODULUS,0,0);
        AddAttribute(template+3,CKA_ID,0,0);
        check_rv("C_GetAttributeValue",sym->C_GetAttributeValue(ses, object, template, 4));
        InitAttributes(template,4);
        check_rv("C_GetAttributeValue",sym->C_GetAttributeValue(ses, object, template, 4));
        id = (unsigned char*) Get_Val(template, CKA_ID,4);
        bin2hex(Get_Val_Len(template,CKA_ID,4), id, id_str);
        fprintf(stdout,"%d-bit %s key object, label:%s, id:%s\n",
            (int) Get_Val_Len(template,CKA_MODULUS,4) *8,
            (Get_Val_ul(template,CKA_CLASS,4)== CKO_PRIVATE_KEY)?"Private":"Public ",
            (char*) Get_Val(template,CKA_LABEL,4),
            id_str);
        FlushAttributes(template,4);
        check_rv("C_FindObjects", sym->C_FindObjects(ses, &object, 1, &found));
    }
    check_rv("C_FindObjectsFinal", sym->C_FindObjectsFinal(ses));
}

void
PK_GenerateObject(long keysize)
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
    do uuid_generate(uuid); while (IDExists(ses,uuid));

    uuid_unparse_lower(uuid, uuid_str);

    /* A template to generate an RSA public key objects*/
    AddAttribute(pub_temp  ,CKA_LABEL,(CK_UTF8CHAR*) uuid_str, strlen (uuid_str));
    AddAttribute(pub_temp+1,CKA_ID,              uuid,     sizeof(uuid_t));
    AddAttribute(pub_temp+2,CKA_KEY_TYPE,        &keyType, sizeof(keyType));
    AddAttribute(pub_temp+3,CKA_VERIFY,          &ctrue,   sizeof (ctrue));
    AddAttribute(pub_temp+4,CKA_ENCRYPT,         &cfalse,  sizeof (cfalse));
    AddAttribute(pub_temp+5,CKA_WRAP,            &cfalse,  sizeof (cfalse));
    AddAttribute(pub_temp+6,CKA_TOKEN,           &ctrue,   sizeof (ctrue));
    AddAttribute(pub_temp+7,CKA_MODULUS_BITS,    &(CK_ULONG)keysize, sizeof (keysize));
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
    check_rv("C_GenerateKeyPair", sym->C_GenerateKeyPair(ses, &mech, pub_temp, 9, pri_temp, 10, &ignore,&ignore));
    fprintf(stdout,"Created RSA key pair object, labeled %s\n",uuid_str);
}
