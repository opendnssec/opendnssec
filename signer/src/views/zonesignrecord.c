#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ldns/ldns.h>
#include "cryptoki_compat/pkcs11.h"
#include <dlfcn.h>
#include "uthash.h"
#include "proto.h"
#include "utilities.h"

#pragma GCC optimize ("O0")

struct signconf {
    int nkeys;
    const ldns_rdf* owner;
#ifdef NOTDEFINED
    struct signconfkey {
        char* filename;
        FILE* fp;
        ldns_key* key;
    }* keys;
#else
    struct signconfkey {
        int algorithm;
        time_t inception;
        time_t expiration;
        uint16_t keytag;
        ldns_rr* dnskey;
        char* keylocator;
        int keyflags;
        void* handle;
        CK_FUNCTION_LIST_PTR pkcs;
        CK_SESSION_HANDLE session;
        CK_OBJECT_HANDLE key;
    }* keys;
#endif
    ldns_key_list* keylist;
};

struct signconf*
createsignconf(int nkeys)
{
    int i;
    struct signconf* signconf;
    signconf = malloc(sizeof(struct signconf));
    signconf->nkeys = nkeys;
    signconf->keys = malloc(signconf->nkeys * sizeof(struct signconfkey));
    for(i=0; i<signconf->nkeys; i++) {
        signconf->keys[i].keylocator = NULL;
        signconf->keys[i].keyflags = 0;
    }
    return signconf;
}

void
locatekeysignconf(struct signconf* signconf, int index, const char* keylocator, int keyflags)
{
    signconf->keys[index].keylocator = strdup(keylocator);
    signconf->keys[index].keyflags = keyflags;
}

void
destroysignconf(struct signconf* signconf)
{
    int i;
    for(i=0; i<signconf->nkeys; i++) {
        free(signconf->keys[i].keylocator);
    }
    free(signconf->keys);
    free(signconf);
}

void
setupsignconf(struct signconf* signconf)
{
    ldns_status statuscode;
    int statusflag;
    int i;
    signconf->keylist = ldns_key_list_new();
    for(i=0; i<signconf->nkeys; i++) {
        //signconf->keys[i].keyrecord = ldns_key2rr(signconf->keys[i].key);
        //signconf->keys[i].dsrecord = NULL;
        //signconf->keys[i].dsrecord = ldns_key_rr2ds(signconf->keys[i].keyrecord, LDNS_SHA256);
    }
}

void
teardownsignconf(struct signconf* signconf)
{
    int i;
    for(i=0; i<signconf->nkeys; i++) {
#ifdef NOTDEFINED
        if(signconf->keys[i].dsrecord) {
            ldns_rr_free(signconf->keys[i].dsrecord);
            signconf->keys[i].dsrecord = 0;
        }
        if(signconf->keys[i].keyrecord) {
            ldns_rr_free(signconf->keys[i].keyrecord);
            signconf->keys[i].keyrecord = 0;
        }
        //if(signconf->keys[i].key) {
        //    ldns_key_deep_free(signconf->keys[i].key);
        //    signconf->keys[i].key = 0;
        //}
        if(signconf->keys[i].fp) {
            fclose(signconf->keys[i].fp);
            signconf->keys[i].fp = 0;
        }
#endif
    }
    //while(ldns_key_list_pop_key(signconf->keylist))  ;
    ldns_key_list_free(signconf->keylist);
}

unsigned char*
signrecordpartial(struct signconf* signconf, struct signconfkey* signconfkey, ldns_rr_list* rrset)
{
    unsigned int i;
    ldns_rr *rrsig;
    uint16_t ttl;
    uint8_t nlabels;
    ldns_rdf* name;
    ldns_buffer* buffer;
    CK_RV rv;
    CK_ULONG signatureLen = 512;
    CK_BYTE signature[signatureLen];
    CK_ULONG digest_len;
    CK_BYTE *data;
    CK_ULONG data_len = 0;
    CK_MECHANISM hashmechanism;
    CK_MECHANISM signmechanism;
    CK_ULONG digestprefixlen;
    const CK_BYTE* digestprefix;
    const CK_BYTE RSA_MD5_ID[] = { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
    const CK_BYTE RSA_SHA1_ID[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };
    const CK_BYTE RSA_SHA256_ID[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
    const CK_BYTE RSA_SHA512_ID[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

    hashmechanism.pParameter = NULL;
    hashmechanism.ulParameterLen = 0;
    signmechanism.pParameter = NULL;
    signmechanism.ulParameterLen = 0;
    
    switch((ldns_signing_algorithm)signconfkey->algorithm) {
        case LDNS_SIGN_RSAMD5:
            hashmechanism.mechanism = CKM_MD5;
            signmechanism.mechanism = CKM_RSA_PKCS;
            digestprefix = RSA_MD5_ID;
            digestprefixlen = sizeof(RSA_MD5_ID);
            digest_len = 16;
            break;
        case LDNS_SIGN_RSASHA1:
        case LDNS_SIGN_RSASHA1_NSEC3:
            hashmechanism.mechanism = CKM_SHA_1;
            signmechanism.mechanism = CKM_RSA_PKCS;
            digestprefix = RSA_SHA1_ID;
            digestprefixlen = sizeof(RSA_SHA1_ID);
            digest_len = LDNS_SHA1_DIGEST_LENGTH;
            break;
        case LDNS_SIGN_RSASHA256:
            hashmechanism.mechanism = CKM_SHA256;
            signmechanism.mechanism = CKM_RSA_PKCS;
            digestprefix = RSA_SHA256_ID;
            digestprefixlen = sizeof(RSA_SHA256_ID);
            digest_len = LDNS_SHA256_DIGEST_LENGTH;
            break;
        case LDNS_SIGN_RSASHA512:
            hashmechanism.mechanism = CKM_SHA512;
            signmechanism.mechanism = CKM_RSA_PKCS;
            digestprefix = RSA_SHA512_ID;
            digestprefixlen = sizeof(RSA_SHA512_ID);
            digest_len = LDNS_SHA512_DIGEST_LENGTH;
            break;
        case LDNS_SIGN_DSA:
        case LDNS_SIGN_DSA_NSEC3:
            hashmechanism.mechanism = CKM_DSA;
            signmechanism.mechanism = CKM_DSA;
            digestprefix = NULL;
            digestprefixlen = 0;
            digest_len = LDNS_SHA1_DIGEST_LENGTH;
            break;
        case LDNS_SIGN_ECC_GOST:
            hashmechanism.mechanism = CKM_GOSTR3411;
            signmechanism.mechanism = CKM_GOSTR3411;
            digestprefix = NULL;
            digestprefixlen = 0;
            digest_len = 32;
            break;
        case LDNS_SIGN_ECDSAP256SHA256:
            hashmechanism.mechanism = CKM_SHA256;
            signmechanism.mechanism = CKM_ECDSA;
            digestprefix = NULL;
            digestprefixlen = 0;
            digest_len = LDNS_SHA256_DIGEST_LENGTH;
            break;
        case LDNS_SIGN_ECDSAP384SHA384:
            hashmechanism.mechanism = CKM_SHA384;
            signmechanism.mechanism = CKM_ECDSA;
            digestprefix = NULL;
            digestprefixlen = 0;
            digest_len = LDNS_SHA384_DIGEST_LENGTH;
            break;
        default:
            abort(); // FIXME
    }

    ldns_rr* rrsample = ldns_rr_list_rr(rrset,0);
    name = ldns_rr_owner(rrsample);
    ttl = ldns_rr_ttl(rrsample);
    /* label count - get it from the first rr in the rr_list
     * RFC 4035 section 2.2: dnssec label length and wildcards
     */
    nlabels = ldns_dname_label_count(name);
    if(nlabels > 0 && strncmp((char*)ldns_rdf_data(name),"\001*",2)) {
        --nlabels;
    }

    rrsig = ldns_rr_new_frm_type(LDNS_RR_TYPE_RRSIG);
    ldns_rr_set_class(rrsig, ldns_rr_get_class(rrsample));
    ldns_rr_set_ttl(rrsig, ttl);
    ldns_rr_set_owner(rrsig, ldns_rdf_clone(name));
    CHECK(!ldns_rr_rrsig_set_origttl(rrsig, ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, ttl)));
    CHECK(!ldns_rr_rrsig_set_signame(rrsig, ldns_rdf_clone(signconf->owner)));
    CHECK(!ldns_rr_rrsig_set_labels(rrsig, ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, nlabels)));
    CHECK(!ldns_rr_rrsig_set_inception(rrsig, ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, signconfkey->inception)));
    CHECK(!ldns_rr_rrsig_set_expiration(rrsig,ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, signconfkey->expiration)));
    CHECK(!ldns_rr_rrsig_set_keytag(rrsig, ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, signconfkey->keytag)));
    CHECK(!ldns_rr_rrsig_set_algorithm(rrsig, ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG, signconfkey->algorithm)));
    CHECK(!ldns_rr_rrsig_set_typecovered(rrsig, ldns_native2rdf_int16(LDNS_RDF_TYPE_TYPE, ldns_rr_get_type(rrsample))));
   

    buffer = ldns_buffer_new(LDNS_MAX_PACKETLEN);

    for (i = 0; i < ldns_rr_rd_count(rrsig) - 1; i++) {
        ldns_rdf*x = ldns_rr_rdf(rrsig, i);
        (void) ldns_rdf2buffer_wire_canonical(buffer, x);
    }


    ldns_rrsig2buffer_wire(buffer, rrsig);
    for(i=0; i<ldns_rr_list_rr_count(rrset); i++) {
        ldns_rr2canonical(ldns_rr_list_rr(rrset, i));
    }
    ldns_rr_list2buffer_wire(buffer, rrset);

    hashmechanism.pParameter = NULL;
    hashmechanism.ulParameterLen = 0;
    signmechanism.pParameter = NULL;
    signmechanism.ulParameterLen = 0;

    data_len = digest_len + digestprefixlen;
    data = malloc(data_len);
    if(digestprefixlen)
        memcpy(data, digestprefix, digestprefixlen);
    rv = signconfkey->pkcs->C_DigestInit(signconfkey->session, &hashmechanism);
    rv = signconfkey->pkcs->C_Digest(signconfkey->session, ldns_buffer_begin(buffer), ldns_buffer_position(buffer), &data[digestprefixlen], &digest_len);

    signconfkey->pkcs->C_SignInit(signconfkey->session, &signmechanism, signconfkey->key);
    signconfkey->pkcs->C_Sign(signconfkey->session, data, data_len, signature, &signatureLen);

    ldns_rr_rrsig_set_sig(rrsig, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, signatureLen, signature));

    free(data);
    ldns_buffer_free(buffer);

    return signature;
}

static CK_C_INITIALIZE_ARGS initializationArgs = { NULL, NULL, NULL, NULL, CKF_OS_LOCKING_OK, NULL };

void
initializesignconfkey(struct signconfkey* signing)
{
    const char* solibrary = "/home/berry/netlabs/lib/libsofthsm2.so"; // FIXME
    const char* locator = "e5983eddbe98fafd03130122bd04c6ea";
    const char* passphrase = "0000";
    int algorithm = 8;

    unsigned long numslots = 1;
    CK_BBOOL ctrue = CK_TRUE;
    time_t now;
    CK_SLOT_ID slotids[1];
    CK_C_GetFunctionList getFunctionList;
    unsigned long objectcount;
    CK_OBJECT_HANDLE objectlist[1];
    CK_ATTRIBUTE findTemplate[] = {
        { CKA_SIGN, &ctrue, sizeof(ctrue) }
    };
    
    signing->handle = dlopen(solibrary, RTLD_NOW);
    getFunctionList = (CK_C_GetFunctionList) functioncast(dlsym(signing->handle, "C_GetFunctionList"));
    getFunctionList(&signing->pkcs);


    signing->pkcs->C_Initialize(&initializationArgs);
    signing->pkcs->C_GetSlotList(CK_TRUE, slotids, &numslots);
    signing->pkcs->C_OpenSession(slotids[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &signing->session);
    signing->pkcs->C_Login(signing->session, CKU_USER, (unsigned char*) passphrase, strlen(passphrase));
    signing->pkcs->C_FindObjectsInit(signing->session, findTemplate, sizeof (findTemplate) / sizeof (CK_ATTRIBUTE));
    signing->pkcs->C_FindObjects(signing->session, objectlist, sizeof (objectlist) / sizeof (CK_OBJECT_HANDLE), &objectcount);

    time(&now);
    signing->inception  = now;
    signing->expiration = now + 3600000;
    signing->keytag = 1;
    signing->algorithm = algorithm;
    signing->key = objectlist[0];
    
    signing->pkcs->C_Logout(signing->session);
    signing->pkcs->C_CloseSession(signing->session);
    signing->pkcs->C_Finalize(NULL_PTR);
}

static void
trimleadingzeros(CK_BYTE_PTR data, CK_ULONG *len)
{
    unsigned int i;
    for(i=0; i<*len && data[i]=='\0'; i++)
        ;
    if(i>0) {
        memmove(data,&data[i],*len-i);
        *len -= i;
    }
}

void
keytag(struct signconf* signconf, struct signconfkey* signconfkey)
{
    uint16_t keytag;
    ldns_rr *dnskey;
    ldns_rdf *rdata;
    uint16_t flags = 0;
    CK_ATTRIBUTE template[] = {
        {CKA_PUBLIC_EXPONENT, NULL, 0},
        {CKA_MODULUS, NULL, 0},
    };
    ldns_rdf *rdf;
    CK_BYTE_PTR public_exponent = NULL;
    CK_ULONG public_exponent_len = 0;
    CK_BYTE_PTR modulus = NULL;
    CK_ULONG modulus_len = 0;
    unsigned long hKey = 0;
    unsigned char *data = NULL;
    size_t data_size = 0;

    flags |= LDNS_KEY_ZONE_KEY;

    dnskey = ldns_rr_new();
    ldns_rr_set_type(dnskey, LDNS_RR_TYPE_DNSKEY);
    ldns_rr_set_owner(dnskey, ldns_rdf_clone(signconf->owner));
    ldns_rr_push_rdf(dnskey, ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, flags));
    ldns_rr_push_rdf(dnskey, ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, LDNS_DNSSEC_KEYPROTO));
    ldns_rr_push_rdf(dnskey, ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG, signconfkey->algorithm));
    
    switch ((ldns_algorithm)signconfkey->algorithm) {
        case CKK_RSA:
            (signconfkey->pkcs)->C_GetAttributeValue(signconfkey->session, signconfkey->key, template, 2);
            public_exponent_len = template[0].ulValueLen;
            modulus_len = template[1].ulValueLen;
            public_exponent = template[0].pValue = malloc(public_exponent_len);

            modulus = template[1].pValue = malloc(modulus_len);
            (signconfkey->pkcs)->C_GetAttributeValue(signconfkey->session, signconfkey->key, template, 2);
            
            trimleadingzeros(public_exponent, &public_exponent_len);
            trimleadingzeros(modulus, &modulus_len);

            data_size = public_exponent_len + modulus_len + 1;
            if (public_exponent_len <= 255) {
                data = malloc(data_size);
                data[0] = public_exponent_len;
                memcpy(&data[1], public_exponent, public_exponent_len);
                memcpy(&data[1 + public_exponent_len], modulus, modulus_len);
            } else if (public_exponent_len <= 65535) {
                data_size += 2;
                data = malloc(data_size);
                data[0] = 0;
                ldns_write_uint16(&data[1], (uint16_t) public_exponent_len);
                memcpy(&data[3], public_exponent, public_exponent_len);
                memcpy(&data[3 + public_exponent_len], modulus, modulus_len);
            } else {
                abort(); // FIXME
            }
            rdata = ldns_rdf_new(LDNS_RDF_TYPE_B64, data_size, data);
            free(public_exponent);
            free(modulus);


            break;
        case CKK_DSA:
        case CKK_GOSTR3410:
        case CKK_EC:
        default:
            abort(); // FIXME
    }
    ldns_rr_push_rdf(dnskey, rdata);
    signconfkey->keytag = ldns_calc_keytag(dnskey);
    signconfkey->dnskey = dnskey;
}

void
signrecord2(struct signconf* signconf, dictionary record, const char* apex)
{
    names_iterator typeiter;
    names_iterator dataiter;
    resourcerecord_t item;
    int i, len;
    const char* recordname;
    const char* recordinfo;
    ldns_rr_type recordtype;
    char* recorddata;
    ldns_rr* rr;
    ldns_rr_list* rrset;
    char* signature;
    char* s;
    ldns_rdf* origin;
    uint32_t defaultttl = 60;
    ldns_status err;
    origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, apex);
    
    getset(record, "name", &recordname, NULL);
    
    for(typeiter = names_recordalltypes(record); names_iterate(&typeiter, &recordtype); names_advance(&typeiter, NULL)) {
        rrset = ldns_rr_list_new();
        for(dataiter = names_recordallvalues(record, recordtype); names_iterate(&dataiter, &item); names_advance(&dataiter, NULL)) {
            rr = names_rr2ldns(record, recordname, recordtype, item);
            ldns_rr_list_push_rr(rrset, rr);
        }
        for(i=0; i<signconf->nkeys; i++) {
            signature = signrecordpartial(signconf, &signconf->keys[i], rrset);
            names_recordaddsignature(record, recordtype, signature, signconf->keys[i].keylocator, signconf->keys[i].keyflags);
            free(signature);
        }
    }
}
void
signrecord(struct signconf* signconf, dictionary record, const char* apex)
{
    names_iterator typeiter;
    names_iterator dataiter;
    resourcerecord_t item;
    const char* recordname;
    const char* recordinfo;
    ldns_rr_type recordtype;
    char* recorddata;
    ldns_rr* rr;
    ldns_rr_list* rrset;
    ldns_rr_list* rrsignatures;
    char** signatures;
    int nsignatures, signaturesidx;
    int len;
    char* s;
    ldns_rdf* origin;
    uint32_t defaultttl = 60;
    ldns_status err;
    origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, apex);
    
    getset(record, "name", &recordname, NULL);

    for(typeiter = names_recordalltypes(record); names_iterate(&typeiter, &recordtype); names_advance(&typeiter, NULL)) {
        rrset = ldns_rr_list_new();
        for(dataiter = names_recordallvalues(record, recordtype); names_iterate(&dataiter, &item); names_advance(&dataiter, NULL)) {
            rr = names_rr2ldns(record, recordname, recordtype, item);
            ldns_rr_list_push_rr(rrset, rr);
        }        
        rrsignatures = ldns_sign_public(rrset, signconf->keylist);
        nsignatures = ldns_rr_list_rr_count(rrsignatures);
        signatures = malloc(sizeof(char*)*nsignatures);
        signaturesidx = 0;
        while((rr = ldns_rr_list_pop_rr(rrsignatures))) {
            signatures[signaturesidx++] = ldns_rdf2str(ldns_rr_rdf(rr,0));
            ldns_rr_free(rr);
        }
        ldns_rr_list_deep_free(rrset);
        ldns_rr_list_deep_free(rrsignatures);

        free(signatures);
    }
}
