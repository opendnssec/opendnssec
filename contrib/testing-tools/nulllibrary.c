#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <malloc.h>
#include <pthread.h>
#include <string.h>
#include <syslog.h>

#include "cryptoki_compat/pkcs11.h"

static CK_FUNCTION_LIST definition;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static struct connection_struct {
    int validLogin;
    struct session_struct* sessions;
} connection = { 0 , NULL };

struct session_struct {
    struct connection_struct connection;
    struct session_struct* next;
    struct session_struct* prev;
};

void
astrxcpy(unsigned char* dst, const char* src, size_t size)
{
    int len = strlen(src);
    if(size < len)
        len = size;
    memset(dst, ' ', size);
    strncpy((char*)dst, src, len);
}

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
    if (sizeof(unsigned long) < sizeof(void*)) {
        syslog(LOG_DAEMON|LOG_ERR, "Unsuitable library");
        return CKR_DEVICE_ERROR;
    }
    return CKR_OK;
}

static CK_RV
Finalize(void *args)
{
    connection.validLogin = 0;
    return CKR_OK;
}

static CK_RV
GetInfo(CK_INFO *info)
{
    info->cryptokiVersion.major = 0;
    info->cryptokiVersion.minor = 0;
    info->flags = 0;
    astrxcpy(info->libraryDescription, "", sizeof(info->libraryDescription));
    info->libraryVersion.major = 0;
    info->libraryVersion.minor = 0;
    astrxcpy(info->manufacturerID, "", sizeof(info->manufacturerID));
    return CKR_OK;
}

static CK_RV
GetSlotList(unsigned char token_present, CK_SLOT_ID *slot_list, unsigned long *count)
{
    if (slot_list) {
        slot_list[0] = 0;
    }
    *count = 1;
    return CKR_OK;
}

static CK_RV
GetSlotInfo(CK_SLOT_ID slot_id, CK_SLOT_INFO* info)
{
    abort();
}

static CK_RV
GetTokenInfo(CK_SLOT_ID slot_id, CK_TOKEN_INFO* info)
{
    info->firmwareVersion.major = 1;
    info->firmwareVersion.minor = 0;
    info->hardwareVersion.major = 1;
    info->hardwareVersion.minor = 0;
    info->flags = 0L;
    astrxcpy(info->label, "OpenDNSSEC", sizeof(info->label));
    astrxcpy(info->manufacturerID, "NLnet Labs", sizeof(info->manufacturerID));
    astrxcpy(info->model, "pretty", sizeof(info->model));
    astrxcpy(info->serialNumber, "1.0", sizeof(info->serialNumber));
    info->ulMaxSessionCount = 0;
    info->ulSessionCount = 0;
    info->ulMaxRwSessionCount = 0;
    info->ulMaxPinLen = 4;
    info->ulMinPinLen = 4;
    info->ulTotalPublicMemory = 0;
    info->ulFreePublicMemory = 0;
    info->ulTotalPrivateMemory = 0;
    info->ulFreePrivateMemory = 0;
    astrxcpy(info->utcTime, "now", sizeof(info->utcTime));
    return CKR_OK;
}

static CK_RV
OpenSession(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application, CK_NOTIFY notify, CK_SESSION_HANDLE *session)
{
    struct session_struct* sessionImpl;
    sessionImpl = malloc(sizeof(struct session_struct));
    if(sessionImpl) {
        sessionImpl->connection = connection;
        pthread_mutex_lock(&lock);
        sessionImpl->next = connection.sessions;
        sessionImpl->prev = NULL;
        if(connection.sessions)
            connection.sessions->prev = sessionImpl;
        connection.sessions = sessionImpl;
        pthread_mutex_unlock(&lock);
        *session = (unsigned long) sessionImpl;
        return CKR_OK;
    } else {
        return CKR_DEVICE_MEMORY;
    }
}

static CK_RV
CloseSession(CK_SESSION_HANDLE session)
{
    struct session_struct* sessionImpl = (struct session_struct*)session;
    pthread_mutex_lock(&lock);
    if (sessionImpl->next) {
        sessionImpl->next->prev = sessionImpl->prev;
    }
    if (sessionImpl->prev) {
        sessionImpl->prev->next = sessionImpl->next;
    } else {
        sessionImpl->connection.sessions = sessionImpl->next;
    }
    pthread_mutex_unlock(&lock);
    free(sessionImpl);
    return CKR_OK;
}

static CK_RV
GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO *info)
{
    info->flags = 0;
    info->slotID = 0;
    info->state = CKS_RW_USER_FUNCTIONS;
    info->ulDeviceError = 0;
    return CKR_OK;
}

static CK_RV
Login(CK_SESSION_HANDLE session, unsigned long user_type, unsigned char *pin, unsigned long pin_len)
{
    struct session_struct* sessionImpl = (struct session_struct*)session;
    sessionImpl->connection.validLogin = 1;
    return CKR_OK;
}

static CK_RV
Logout(CK_SESSION_HANDLE session)
{
    struct session_struct* sessionImpl = (struct session_struct*)session;
    sessionImpl->connection.validLogin = 0;
    return CKR_OK;
}

static CK_RV
DestroyObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
    abort();
}

static CK_RV
GetAttributeValue(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE* templ, unsigned long count)
{
    int i;
    for (i=0; i<count; i++) {
        switch (templ[i].type) {
            case CKA_ID:
            case CKA_KEY_TYPE:
            case CKA_PRIME:
            case CKA_SUBPRIME:
            case CKA_BASE:
            case CKA_VALUE:
                if (templ[i].pValue != NULL) {
                    if (templ[i].ulValueLen >= sizeof (unsigned long)) {
                        *(unsigned long*) templ[i].pValue = 1;
                    }
                }
                templ[i].ulValueLen = sizeof (unsigned long);
                break;
            default:
                abort();
        }
    }
    return CKR_OK;
}

static CK_RV
FindObjectsInit(CK_SESSION_HANDLE session, CK_ATTRIBUTE* templ, unsigned long count)
{
    int i, j;
    for(i=0; i<count; i++) {
        switch(templ[0].type) {
            case CKA_CLASS:
                break;
            case CKA_ID:
                break;
            default:
                abort();
        }
    }
    return CKR_OK;
}

static CK_RV
FindObjects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* object, unsigned long max_object_count, unsigned long *object_count)
{
    int i;
    *object_count = 1;
    for(i=0; i<*object_count && i<max_object_count; i++) {
        object[i] = 1L;
    }
    return CKR_OK;
}

static CK_RV
FindObjectsFinal(CK_SESSION_HANDLE session)
{
    return CKR_OK;
}

static CK_RV
DigestInit(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr)
{
    abort();
}

static CK_RV
Digest(CK_SESSION_HANDLE session, unsigned char *data_ptr, unsigned long data_len, unsigned char *digest, unsigned long *digest_len)
{
    abort();
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
    for(i=0; i<*signature_len; i++) {
        signature[i] = 0;
    }
    return CKR_OK;
}

static CK_RV
GenerateKey(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr,
        CK_ATTRIBUTE* templ, unsigned long count, CK_OBJECT_HANDLE* key)
{
    abort();
}

static CK_RV
GenerateKeyPair(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr,
        CK_ATTRIBUTE* public_key_template, unsigned long public_key_attribute_count,
        CK_ATTRIBUTE* private_key_template, unsigned long private_key_attribute_count,
        CK_OBJECT_HANDLE* public_key, CK_OBJECT_HANDLE* private_key)
{
    abort();
}

static CK_RV
SeedRandom(CK_SESSION_HANDLE session, unsigned char *seed_ptr, unsigned long seed_len)
{
    return CKR_OK;
}

static CK_RV
GenerateRandom(CK_SESSION_HANDLE session, unsigned char *random_data, unsigned long random_len)
{
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

extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR function_list);

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR function_list)
{
    return GetFunctionList(function_list);
}

__attribute__((constructor))
void
init(void)
{
    connection.validLogin = 0;
    connection.sessions = NULL;
}

__attribute__((destructor))
void
fini(void)
{
}
