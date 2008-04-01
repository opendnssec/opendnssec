/*
 * Copyright (C) 2007 Internet Corporation for Assigned Names 
 *                         and Numbers ("ICANN")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ICANN DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ICANN BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Author: RHLamb 2007
 *   pkcs11 HSM key backup utility
 *
 * cc foo.c -o foo -ldl 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <malloc.h>
#include "cryptoki.h"

typedef unsigned char uchar;
typedef unsigned char uint8;
typedef int boolean;

#define BUFFERSIZ 8192
#define MAX_SLOTS 100
#define MAX_KEYS_PER_SLOT 64
#define min(x,y) ((x)<(y)?(x):(y))

static char teststr[]="0123456789";
static CK_FUNCTION_LIST_PTR  pfl;
CK_BBOOL true=CK_TRUE;

int hex2i(char c);
int cleanup(char *io);
int rdump(unsigned char *ptr,int n);
char *fgetsne(char *bufin,int bufinsize,FILE *streamin);
#define PEM_LINE_LENGTH 64
int base64encode(char *out,uint8 *in,int n);
int base64decode(char *in,uint8 *out);
int delobject(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hObj);

int read_keys_into_hsm(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hWrappingkey,FILE *fp);

int display_pubkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub,int flags);

int signit(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,uchar *message,CK_ULONG messagelen,char *sigout,long *siglen);
int verify(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub,uchar *message,CK_ULONG messagelen,char *sig,long slen);
int getwrapkey(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_HANDLE *hWrappingKey);
int export_pubkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub);

int wrap_and_export_privkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,CK_OBJECT_HANDLE hWrappingKey);

int getkey(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_CLASS class,CK_OBJECT_HANDLE *hKey);
int getkeyarray(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_CLASS iclass,CK_OBJECT_HANDLE *hKeyA,int *ofound);


int main(int argc,char *argv[])
{
  CK_C_GetFunctionList   pGFL=0;
  CK_RV                  rv;
  CK_ULONG               nslots;
  CK_SLOT_ID             slots[MAX_SLOTS];
  CK_SESSION_HANDLE      sh;
  CK_OBJECT_HANDLE       hKeys[MAX_KEYS_PER_SLOT];
  void                   *hLib;
  int                    i,k,n;
  char                   *p,*wrappingkeylabel,lbuf[512];  
  CK_OBJECT_HANDLE       hWrappingKey;
  int                    cmd,wslot;
  char                   *keylabel;
  char                   *userpin;

  {
    int ch;
    extern char *optarg;
    extern int optind;
    extern int optopt;
    extern int opterr;
    extern int optreset;
    
    keylabel = NULL;
    wrappingkeylabel = NULL;
    userpin = NULL;
    cmd = 0;
    wslot = -1;
    while((ch=getopt(argc,argv,"p::s::l::w:d:D:P:S:")) != -1) {
      switch(ch) {
      case 'p':
      case 's':
      case 'l':
	if(cmd != 0) {
	  fprintf(stderr,"error: Can only perform one action at a time.\n");
	  return -1;
	}
	if(optarg) keylabel = optarg;
	else keylabel = NULL;
	cmd = ch;
	break;
      case 'w':
	wrappingkeylabel = optarg;
	break;
      case 'S':
	wslot = atoi(optarg);
	break;
      case 'P':
        userpin = optarg;
        break;
      case 'd':
      case 'D':
	if(cmd != 0) {
          fprintf(stderr,"error: Can only perform one action at a time.\n");
          return -1;
	}
	cmd = ch;
	keylabel = optarg;
	break;
      case '?':
      default:
	printf("Usage:%s [[-l[label]][-d label][-p[label]]][-P pin][-S slot][-w wrappingkey][ < keyfile ]\n",argv[0]);
	printf(" -l[label] : lists all keys or more info on \"label\"ed key\n");
	printf(" -d label  : deletes \"label\"ed key\n");
	printf(" -D label  : deletes \"label\"ed secret key\n");
	printf(" -p[label] : outputs wrapped base64 signing key for all or \"label\"ed key\n");
	printf(" -s[label] : outputs wrapped base64 secret key for all or \"label\"ed key\n");

	printf(" With no arguments, reads key info created by \"-p\" to import key(s)\n");

	printf(" A specfic (un)wrapping key can be specified using\n \"-w label\" for \"-p,-s, and < keyfile\" operations. If specified wrapping\n key does not exist, a new one will be created inside the HSM\n");
	printf(" -P pin    : pin code\n");
	printf(" -S slot   : HSM slot number (0-n)\n");
	return -1;
      }
    }
    argc -= optind;
    argv += optind;
    if(cmd == 0) cmd = 'b';
  }

  /*
   * The dynamic lib will also need to know where libs are so:
   *  export KEYPER_LIBRARY_PATH=$PWD
   *  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$KEYPER_LIBRARY_PATH
   *
   */
  if((p=getenv("PKCS11_LIBRARY_PATH")) == NULL) {
    fprintf(stderr,"You must set PKCS11_LIBRARY_PATH, e.g.,\n \"export PKCS11_LIBRARY_PATH=/home/dnssec/AEP/pkcs11.so.3.10\"\n");
    return -1;
  }
  sprintf(lbuf,"%s",p);
  hLib = dlopen(lbuf,RTLD_LAZY);
  if(!hLib) {
    fprintf(stderr,"pkcs11: error: failed to open lib %s\n %s\n",lbuf,dlerror());
    return -1;
  }
  if((pGFL=(CK_C_GetFunctionList)dlsym(hLib,"C_GetFunctionList")) == NULL) {
    fprintf(stderr,"pkcs11: error: Cannot find GetFunctionList()\n");
    dlclose(hLib);
    return -1;
  }
  if((rv=pGFL(&pfl)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetFunctionList returned 0x%08X\n",rv);
    return -1;
  }
  if((rv = pfl->C_Initialize(NULL)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_Initialize returned 0x%08X\n",rv);
    return -1;
  }
  nslots = MAX_SLOTS;
  if((rv=pfl->C_GetSlotList(TRUE,slots,&nslots)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_Getslots returned 0x%08X\n",rv);
    /*pfl->C_Finalize(0);/**/
    return -1;
  }
  /*printf("Got %d Slots\n",nslots);/**/
  k = 0;
  if(wslot >= 0 && nslots <= wslot) {
    k = wslot;
  } else
  if(nslots > 1) {
    fprintf(stderr,"Found %d slots. Enter slot number (0-%d) to operate on (0):",nslots,nslots-1);
    if(fgets(lbuf,sizeof(lbuf),stdin) == NULL) {
      return -1;
    }
    cleanup(lbuf);
    k = atoi(lbuf);
    fprintf(stderr,"%d\n",k);
  }
  rv = pfl->C_OpenSession(slots[k],CKF_RW_SESSION|CKF_SERIAL_SESSION,NULL,NULL,&sh);
  if(rv != CKR_OK) {
    fprintf(stderr,"pkcs11: error: Could not open slot %d\n C_OpenSession returned 0x%08X\n",k,rv);
    return -1;
  }

  if(userpin) {
    strcpy(lbuf,userpin);
  } else {
    fprintf(stderr,"Enter PIN for slot %d: ",k);
    if(fgetsne(lbuf,sizeof(lbuf),stdin) == NULL) {
      return -1;
    }
    cleanup(lbuf);
  }

  if((rv=pfl->C_Login(sh,CKU_USER,lbuf,strlen(lbuf))) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: Invalid PIN\n C_Login returned 0x%08X\n",rv);
    pfl->C_CloseSession(sh); 
    return -1;
  }

  if(wrappingkeylabel == NULL) wrappingkeylabel="dnssec backup key";

  if(cmd == 'b') {
    if(getwrapkey(sh,wrappingkeylabel,&hWrappingKey)) {
      goto endit;
    }
    read_keys_into_hsm(sh,hWrappingKey,stdin);
    goto endit;
  } else
  if(cmd == 'l') { /* list */
    listkeys(sh,keylabel);
    goto endit;
  } else
  if(cmd == 'd') {
    deletekey(sh,keylabel,CKO_PRIVATE_KEY);
    deletekey(sh,keylabel,CKO_PUBLIC_KEY);
    goto endit;
  } else
  if(cmd == 'D') {
    fprintf(stderr,"Are you sure you want to delete secret key \"%s\"? [N/y]: ",keylabel);
    if(fgets(lbuf,sizeof(lbuf),stdin) == NULL) {
      return -1;
    }
    cleanup(lbuf);
    if(lbuf[0] == 'y' || lbuf[0] == 'Y') {
      deletekey(sh,keylabel,CKO_SECRET_KEY);
    } else {
      fprintf(stderr,"Key \"%s\" not deleted\n",keylabel);
    }
    goto endit;
  } else
  if(cmd == 'p') {
    if(getwrapkey(sh,wrappingkeylabel,&hWrappingKey)) {
      goto endit;
    }
    if(getkeyarray(sh,keylabel,CKO_PRIVATE_KEY,hKeys,&n)) {
      goto endit;
    }
    for(i=0;i<n;i++) {
      wrap_and_export_privkey(sh,hKeys[i],hWrappingKey);
    }
    if(getkeyarray(sh,keylabel,CKO_PUBLIC_KEY,hKeys,&n)) {
      goto endit;
    }
    for(i=0;i<n;i++) {
      export_pubkey(sh,hKeys[i]);
    }
    goto endit;
  } else
  if(cmd == 's') {
    if(getwrapkey(sh,wrappingkeylabel,&hWrappingKey)) {
      goto endit;
    }
    if(getkeyarray(sh,keylabel,CKO_SECRET_KEY,hKeys,&n)) {
      goto endit;
    }
    for(i=0;i<n;i++) {
      wrap_and_export_privkey(sh,hKeys[i],hWrappingKey);
    }
    goto endit;
  } else {
    fprintf(stderr,"Unknown command \"%s\"\n",argv[1]);
  }

 endit:

  if((rv=pfl->C_Logout(sh)) != CKR_OK) {
    printf("pkcs11: error: C_Logout returned 0x%08X\n",rv);
  }

  if((rv=pfl->C_CloseSession(sh)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_CloseSession returned 0x%08X\n",rv);
  }
  /*pfl->C_Finalize(0);/* never */
  return 0;
}

int getkeyarray(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_CLASS iclass,CK_OBJECT_HANDLE *hKeyA,int *ofound)
{
  int j,n;
  CK_RV rv;
  CK_OBJECT_CLASS class;
  CK_ATTRIBUTE template[2];

  class = iclass;
  j = 0;
  template[j].type = CKA_CLASS;
  template[j].pValue = &class;
  template[j].ulValueLen = sizeof(class);
  j++;
  if(label) {
    template[j].type = CKA_LABEL;
    template[j].pValue = label;
    template[j].ulValueLen = strlen(label);
    j++;
  }
  rv = pfl->C_FindObjectsInit(sh,template,j);
  if(rv != CKR_OK) return -1;
  rv = pfl->C_FindObjects(sh,hKeyA,MAX_KEYS_PER_SLOT,(CK_RV *)&n);
  if(rv != CKR_OK) return -1;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) return -1;
  if(n > 0) {
    if(label && n > 1) {
      fprintf(stderr,"pkcs11: error: Found more than one key matching label:\"%s\"\n",label);
      return -1;
    }
  } else {
    fprintf(stderr,"pkcs11: error: Found no private keys labeled:\"%s\"\n",label);
    return -1;
  }
  *ofound = n;
  return 0;
}

int getwrapkey(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_HANDLE *hWrappingKey)
{
  int i;
  CK_RV rv;
  CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
  CK_ATTRIBUTE template[2];
  CK_OBJECT_HANDLE hKeys[MAX_KEYS_PER_SLOT];
  CK_RV ofound;

  if(label == NULL || strlen(label) == 0) {
    label = "dnssec backup key";
  }
  template[0].type = CKA_CLASS;
  template[0].pValue = &secretClass;
  template[0].ulValueLen = sizeof(secretClass);
  template[1].type = CKA_LABEL;
  template[1].pValue = label;
  template[1].ulValueLen = strlen(label);
  if((rv=pfl->C_FindObjectsInit(sh,template,2)) != CKR_OK) { 
    fprintf(stderr,"pkcs11: error: C_FindObjectsInit returned 0x%08X\n",rv); return -1; 
  }
  if((rv=pfl->C_FindObjects(sh,hKeys,MAX_KEYS_PER_SLOT,&ofound)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_FindObjects returned 0x%08X\n",rv); return -1;
  }
  if((rv=pfl->C_FindObjectsFinal(sh)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_FindObjectsFinal returned 0x%08X\n",rv); return -1;
  }
  if(ofound > 0) {
    *hWrappingKey = hKeys[0];
    if(ofound > 1) {
      fprintf(stderr,"pkcs11: error: Found %d (>1) wrapping keys with label:\"%s\"\n",ofound,label);
      for(i=0;i<ofound;i++) {
	display_secretkey(sh,hKeys[i],0);
      }
      return -1;
    }
    return 0;
  } else {
    fprintf(stderr,"pkcs11: warnning: Could not find a wrapping key...creating one labeled:\"%s\"\n",label);
  }

  if(0) {
    CK_ULONG dhbits = 512;
    CK_ATTRIBUTE dhdntmp[] = {
      {CKA_PRIME_BITS, &dhbits, sizeof(dhbits)},
    };
    CK_OBJECT_HANDLE hDHDN;
    CK_MECHANISM dhdgenmech = { CKM_DH_PKCS_PARAMETER_GEN, NULL_PTR, 0};
    rv = pfl->C_GenerateKey(sh,&dhdgenmech,dhdntmp,1,&hDHDN);
    if(rv != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_GenerateKey returned 0x%08X\n",rv);
      /*return -1;*/
    }
  }
  if(0) {
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_BYTE prime[20];
    CK_BYTE base[20];
    CK_MECHANISM keyPairMechanism = { CKM_DH_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_ATTRIBUTE publicKeyTemplate[] = {
      {CKA_PRIME, prime, sizeof(prime)},
      {CKA_BASE, base, sizeof(base)}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
      {CKA_DERIVE, &true, sizeof(true)}
    };
    rv = pfl->C_GenerateKeyPair(sh,&keyPairMechanism,
			  publicKeyTemplate,
			  (sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE)),
			  privateKeyTemplate, 
			  (sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE)),
			  &hPublicKey,&hPrivateKey);
    if(rv != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_GenerateKeyPair returned 0x%08X\n",rv);
      return -1;
    }
  }
  if(0) {
    CK_OBJECT_HANDLE hPublicKey;
    CK_BYTE publicValue[128];
    CK_ATTRIBUTE pTemplate[] = {
      CKA_VALUE, &publicValue, sizeof(publicValue)
    };
    rv = pfl->C_GetAttributeValue(sh,hPublicKey,pTemplate,1);
    if(rv != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_GetAttributeValue returned 0x%08X\n",rv);
      return -1;
    }
  }
  /* Put other guy.s public value in otherPublicValue */
  if(0) { /* derive a key from something we both know to Wrap */
    CK_OBJECT_HANDLE hPrivateKey;
    CK_BYTE otherPublicValue[128];
    CK_MECHANISM mechanism = {
      CKM_DH_PKCS_DERIVE, otherPublicValue, sizeof(otherPublicValue)
    };
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_DES;
    CK_ATTRIBUTE template[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_ENCRYPT, &true, sizeof(true)},
      {CKA_DECRYPT, &true, sizeof(true)}
    };

    rv = pfl->C_DeriveKey(sh,&mechanism,
				      hPrivateKey,
				      template,
				      4,
				      hWrappingKey);
    if (rv != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_DeriveKey returned 0x%08X\n",rv);
      return -1;
    }
  }

  if(1) { /* gen a raw key to Wrap */
    CK_MECHANISM genmechanism = {
      CKM_DES3_KEY_GEN, NULL_PTR, 0
    };
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_DES3;
    CK_BYTE value[24];
    CK_ATTRIBUTE wkeytmp[] = {
      {CKA_LABEL,NULL_PTR,0},
      {CKA_CLASS,&keyClass,sizeof(keyClass)},
      {CKA_KEY_TYPE,&keyType,sizeof(keyType)},
      {CKA_TOKEN,&true,sizeof(true)},
      {CKA_ENCRYPT,&true,sizeof(true)},
      {CKA_DECRYPT,&true,sizeof(true)},
      {CKA_WRAP,&true,sizeof(true)},
      {CKA_UNWRAP,&true,sizeof(true)},
      {CKA_EXTRACTABLE,&true,sizeof(true)},
      /*{CKA_VALUE, value, sizeof(value)},/**/
    };

    wkeytmp[0].pValue = label;
    wkeytmp[0].ulValueLen = strlen(label);
    if((rv=pfl->C_GenerateKey(sh,&genmechanism,
			      wkeytmp,
			      (sizeof(wkeytmp)/sizeof(CK_ATTRIBUTE)),
			      hWrappingKey)) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_GenerateKey returned 0x%08X\n",rv);
      return -1;
    }
  }
  if(0) {
    CK_BYTE publicValue[24];
    CK_UTF8CHAR label[128];
    CK_ATTRIBUTE pTemplate[] = {
      /*{CKA_VALUE, publicValue, sizeof(publicValue)},*/
      {CKA_LABEL, label, sizeof(label)-1},
    };
    
    memset(label,0,sizeof(label));
    for(i=0;i<24;i++) publicValue[i] = 0;

    rv = pfl->C_GetAttributeValue(sh,*hWrappingKey,
			    pTemplate,
			    (sizeof(pTemplate)/sizeof(CK_ATTRIBUTE)));
    if(rv != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_GetAttributeValue returned 0x%08X\n",rv);
      return -1;
    }
    printf("DES \"%s\" (%x)=",label,*hWrappingKey);
    for(i=0;i<24;i++) printf("%02x ",publicValue[i]);
    printf("\n");
  }
  printf("pkcs11: Created new wrapping key labeled:\"%s\".\n",label);
  printf(" You will need to manually export this to other HSMs you plan on\n");
  printf(" exchanging keys with using your HSM's specific backup procedures.\n");
  return 0;
}

int listkeys(CK_SESSION_HANDLE sh,char *label)
{
  CK_RV rv;
  CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
  CK_ATTRIBUTE template[2];
  CK_OBJECT_HANDLE hKeys[MAX_KEYS_PER_SLOT];
  CK_RV ofound;
  int i,j,flag;

  flag = 1; /* min */
  if(label) flag = 2; /* verbose */

  j = 0;
  template[j].type = CKA_CLASS;
  template[j].pValue = &pubClass;
  template[j].ulValueLen = sizeof(pubClass);
  j++;
  if(label) {
    template[j].type = CKA_LABEL;
    template[j].pValue = label;
    template[j].ulValueLen = strlen(label);
    j++;
  }    
  rv = pfl->C_FindObjectsInit(sh,template,j);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjects(sh,hKeys,MAX_KEYS_PER_SLOT,&ofound);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) goto endit;
  if(ofound > 0) {
    fprintf(stdout,"%d public keys:\n",ofound);
    for(i=0;i<ofound;i++) {
      display_pubkey(sh,hKeys[i],flag);
    }
  }

  j = 0;
  template[j].type = CKA_CLASS;
  template[j].pValue = &privClass;
  template[j].ulValueLen = sizeof(privClass);
  j++;
  if(label) {
    template[j].type = CKA_LABEL;
    template[j].pValue = label;
    template[j].ulValueLen = strlen(label);
    j++;
  }
  rv = pfl->C_FindObjectsInit(sh,template,j);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjects(sh,hKeys,MAX_KEYS_PER_SLOT,&ofound);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) goto endit;
  if(ofound > 0) {
    fprintf(stdout,"%d private keys:\n",ofound);
    for(i=0;i<ofound;i++) {
      display_privkey(sh,hKeys[i],flag);
    }
  }

  j = 0;
  template[j].type = CKA_CLASS;
  template[j].pValue = &secretClass;
  template[j].ulValueLen = sizeof(secretClass);
  j++;
  if(label) {
    template[j].type = CKA_LABEL;
    template[j].pValue = label;
    template[j].ulValueLen = strlen(label);
    j++;
  }
  rv = pfl->C_FindObjectsInit(sh,template,j);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjects(sh,hKeys,MAX_KEYS_PER_SLOT,&ofound);
  if(rv != CKR_OK) goto endit;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) goto endit;
  if(ofound > 0) {
    fprintf(stdout,"%d secret keys:\n",ofound);
    for(i=0;i<ofound;i++) {
      display_secretkey(sh,hKeys[i],flag);
    }
  }
  return 0;
 endit:
  return -1;
}

int deletekey(CK_SESSION_HANDLE sh,CK_UTF8CHAR *label,CK_OBJECT_CLASS class)
{
  CK_RV rv;
  CK_ATTRIBUTE template[2];
  CK_OBJECT_HANDLE hKeys[MAX_KEYS_PER_SLOT];
  CK_OBJECT_CLASS lclass;
  CK_RV ofound;
  int i;

  lclass = class;
  template[0].type = CKA_CLASS;
  template[0].pValue = &lclass;
  template[0].ulValueLen = sizeof(lclass);
  template[1].type = CKA_LABEL;
  template[1].pValue = label;
  template[1].ulValueLen = strlen(label);
  rv = pfl->C_FindObjectsInit(sh,template,2);
  if(rv != CKR_OK) return -1;
  rv = pfl->C_FindObjects(sh,hKeys,MAX_KEYS_PER_SLOT,&ofound);
  if(rv != CKR_OK) return -1;
  rv = pfl->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) return -1;
  if(ofound > 0) {
    delobject(sh,hKeys[0]);
    if(ofound > 1) {
      fprintf(stderr,"pkcs11: warnning: Found %d(>1) keys labeled:\"%s\"\n",ofound,label);
#ifdef FOOP
      for(i=1;i<ofound;i++) {
	display_pubkey(sh,hKeys[i],1);
	delobject(sh,hKeys[i]);
      }
#endif
    }
    return 0;
  } else {
    char *p;

    switch(lclass) {
    case CKO_PRIVATE_KEY: p = "private"; break;
    case CKO_PUBLIC_KEY: p = "public"; break;
    case CKO_SECRET_KEY: p = "secret"; break;
    default: p = "unknown"; break;
    }
    fprintf(stderr,"pkcs11: error: No %s key labeled:\"%s\"\n",p,label);/**/
    return -1;
  }
}

#define FREE_AND_CLEAR(x) { if(x) { free(x); x = NULL; } }

int read_keys_into_hsm(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hWrappingkey,FILE *fp)
{
  char *p64,*p,lbuf[512];
  int n,j;
  char *label;
  uint8 *id,*wrappedkey;
  int idlen,moduluslen,exponentlen,wrappedkeylen;
  CK_RV rv;
  CK_BYTE *modulus,*exponent;
  CK_OBJECT_CLASS keyclass;
  CK_KEY_TYPE keytype;
  CK_OBJECT_HANDLE htmp;
  CK_BBOOL true=CK_TRUE;

  label = NULL;
  id = NULL;
  modulus = NULL;
  exponent = NULL;
  wrappedkey = NULL;
  p64 = NULL;
  while(fgets(lbuf,sizeof(lbuf),fp)) {
    if(lbuf[0] == '#') continue;
    cleanup(lbuf);
    j = strlen(lbuf);
    p = strchr(lbuf,':');
    if(p64) {
      if(j > 0 && p == NULL) strcat(p64,lbuf);
      if(strchr(lbuf,'=') || j < PEM_LINE_LENGTH || p) {
	char *q,*r;

	/*printf("%s\n",p64);*/

	if((r=strchr(p64,':')) == NULL) {
	  fprintf(stderr,"error: malformed base64 key file format\n");
	  goto err64;
	}
	*r++ = '\0';
	if((q=(uint8 *)malloc(strlen(r)+4)) == NULL) {
	  fprintf(stderr,"error: out of memory in %s\n",__func__);
	  goto err64;
	}
	if((n=base64decode(r,q)) < 0) {
	  fprintf(stderr,"error: malformed base64 encoding in key file\n");
	  free(q);
	  goto err64;
	}
	if(strcmp(p64,"modulus") == 0) {
	  modulus = q;
	  moduluslen = n;
	} else if(strcmp(p64,"exponent") == 0) {
	  exponent = q;
	  exponentlen = n;
	} else if(strcmp(p64,"wrappedkey") == 0) {
	  wrappedkey = q;
	  wrappedkeylen = n;
	} else {
	  fprintf(stderr,"warning: unknown key record |%s|\n",p64);
	  free(q);
	}
      err64:
	free(p64);
	p64 = NULL;
      }
    }
    if(j == 0) { /* try to import the key */
      if(label == NULL) continue; /* superfulous <LF> */
      printf("importing %s\n",label);
      if(keyclass == CKO_PUBLIC_KEY) {
	CK_ATTRIBUTE template[] = {
	  {CKA_CLASS,&keyclass,sizeof(keyclass)},
	  {CKA_KEY_TYPE,&keytype,sizeof(keytype)},
	  {CKA_TOKEN,&true,sizeof(true)},
	  {CKA_LABEL,NULL_PTR,0},
	  {CKA_ID,NULL_PTR,0},
	  {CKA_WRAP,&true,sizeof(true)},
	  {CKA_ENCRYPT,&true,sizeof(true)},
	  {CKA_MODULUS,NULL_PTR,0},
	  {CKA_PUBLIC_EXPONENT,NULL_PTR,0},
	  {CKA_VERIFY,&true,sizeof(true)},
	  {CKA_EXTRACTABLE,&true,sizeof(true)},
	};
	if(label == NULL || modulus == NULL || exponent == NULL) {
	  fprintf(stderr,"pkcs11: error: incomplete info for public key\n");
	  goto endit;
	}
	template[3].pValue = (CK_UTF8CHAR *)label;
	template[3].ulValueLen = strlen(label);
        template[4].pValue = id;
        template[4].ulValueLen = idlen;
	template[7].pValue = modulus;
	template[7].ulValueLen = moduluslen;
	template[8].pValue = exponent;
	template[8].ulValueLen = exponentlen;
	if((rv=pfl->C_CreateObject(sh,
				   template,
				   sizeof(template)/sizeof(CK_ATTRIBUTE),
				   &htmp)) != CKR_OK) {
	  fprintf(stderr,"pkcs11: error: C_CreateObject returned 0x%08X\n",rv);
	  goto endit;
	}
	FREE_AND_CLEAR(label);
	FREE_AND_CLEAR(id);
	FREE_AND_CLEAR(modulus);
	FREE_AND_CLEAR(exponent);
	FREE_AND_CLEAR(wrappedkey);
      } else if(keyclass == CKO_PRIVATE_KEY) {
	CK_MECHANISM uwmechanism = {
	  CKM_DES3_ECB, NULL_PTR, 0
	};
	CK_ATTRIBUTE template[] = {
	  {CKA_LABEL,NULL_PTR,0},
	  {CKA_ID,NULL_PTR,0},
	  {CKA_CLASS,&keyclass,sizeof(keyclass)},
	  {CKA_KEY_TYPE,&keytype,sizeof(keytype)},
	  {CKA_TOKEN,&true,sizeof(true)},
	  {CKA_PRIVATE,&true,sizeof(true)},
	  {CKA_SENSITIVE,&true,sizeof(true)},
	  {CKA_EXTRACTABLE,&true,sizeof(true)},
	  {CKA_SIGN,&true,sizeof(true)},
	  {CKA_DECRYPT,&true,sizeof(true)},
	};
	if(label == NULL || wrappedkey == NULL) {
          fprintf(stderr,"pkcs11: error: incomplete info for private key\n");
          goto endit;
        }
        template[0].pValue = (CK_UTF8CHAR *)label;
        template[0].ulValueLen = strlen(label);
        template[1].pValue = id;
        template[1].ulValueLen = idlen;
	if((rv=pfl->C_UnwrapKey(sh,&uwmechanism,
				hWrappingkey,
				wrappedkey,
				wrappedkeylen,
				template,
				(sizeof(template)/sizeof(CK_ATTRIBUTE)),
				&htmp)) != CKR_OK) {
	  fprintf(stderr,"pkcs11: error: C_UnWrapKey returned 0x%08X\n",rv);
	  goto endit;
	}
        FREE_AND_CLEAR(label);
        FREE_AND_CLEAR(id);
        FREE_AND_CLEAR(modulus);
        FREE_AND_CLEAR(exponent);
        FREE_AND_CLEAR(wrappedkey);
      } else if(keyclass == CKO_SECRET_KEY) {
        CK_MECHANISM uwmechanism = {
          CKM_DES3_ECB, NULL_PTR, 0
        };
        CK_ATTRIBUTE template[] = {
          {CKA_LABEL,NULL_PTR,0},
          {CKA_ID,NULL_PTR,0},
          {CKA_CLASS,&keyclass,sizeof(keyclass)},
          {CKA_KEY_TYPE,&keytype,sizeof(keytype)},
          {CKA_TOKEN,&true,sizeof(true)},
          {CKA_EXTRACTABLE,&true,sizeof(true)},
          {CKA_ENCRYPT,&true,sizeof(true)},
          {CKA_DECRYPT,&true,sizeof(true)},
	  {CKA_WRAP, &true, sizeof(true)},
	  {CKA_UNWRAP, &true, sizeof(true)},
        };
        if(label == NULL || wrappedkey == NULL) {
          fprintf(stderr,"pkcs11: error: incomplete info for secret key\n");
          goto endit;
        }
        template[0].pValue = (CK_UTF8CHAR *)label;
        template[0].ulValueLen = strlen(label);
        template[1].pValue = id;
        template[1].ulValueLen = idlen;
        if((rv=pfl->C_UnwrapKey(sh,&uwmechanism,
                                hWrappingkey,
                                wrappedkey,
                                wrappedkeylen,
                                template,
                                (sizeof(template)/sizeof(CK_ATTRIBUTE)),
                                &htmp)) != CKR_OK) {
          fprintf(stderr,"pkcs11: error: C_UnWrapKey returned 0x%08X\n",rv);
          goto endit;
        }
        FREE_AND_CLEAR(label);
        FREE_AND_CLEAR(id);
        FREE_AND_CLEAR(modulus);
        FREE_AND_CLEAR(exponent);
        FREE_AND_CLEAR(wrappedkey);
      } else {
	fprintf(stderr,"pkcs11: error: trying to import unknown key class\n");
	goto endit;
      }
      continue;
    }
    if(p64) continue;
    if(p == NULL) { /* last line of base64 encoding */
      /*fprintf(stderr,"warning: keyfile has malformed line:\n|%s|\n",lbuf);*/
      continue;
    }
    *p++ = '\0';
    if(strcmp(lbuf,"label") == 0) {
      label = strdup(p);
    } else if(strcmp(lbuf,"id") == 0) {
      char *q;
      int k;
      idlen = strlen(p)/2;
      id = (uint8 *)malloc(idlen);
      for(q=p,k=0;k<idlen;k++,q += 2) {
	id[k] = hex2i(*q)<<4 | hex2i(*(q+1));
      }
    } else if(strcmp(lbuf,"type") == 0) {
      if(strcmp(p,"rsa") == 0) {
	keytype = CKK_RSA;
      } else if(strcmp(p,"dsa") == 0) {
	keytype = CKK_DSA;
      } else if(strcmp(p,"des3") == 0) {
	keytype = CKK_DES3;
      } else {
	keytype = 0;
	fprintf(stderr,"error: trying to import unknown key type |%s|\n",p);
      }
    } else if(strcmp(lbuf,"class") == 0) {
      if(strcmp(p,"private") == 0) {
        keyclass = CKO_PRIVATE_KEY;
      } else if(strcmp(p,"public") == 0) {
        keyclass = CKO_PUBLIC_KEY;
      } else if(strcmp(p,"secret") == 0) {
        keyclass = CKO_SECRET_KEY;
      } else {
        keytype = 0;
        fprintf(stderr,"error: trying to import unknown key class |%s|\n",p);
      }
    } else if(strcmp(lbuf,"modulus") == 0
	      || strcmp(lbuf,"exponent") == 0
	      || strcmp(lbuf,"wrappedkey") == 0) {
      if((p64=(char *)malloc(2048)) == NULL) {
	fprintf(stderr,"error out of memory in %s\n",__func__);
	continue;
      }
      sprintf(p64,"%s:",lbuf);
    } else {
      fprintf(stderr,"warning: unknown key record |%s|\n",lbuf);
    }
  }
  return 0;
 endit:
  FREE_AND_CLEAR(label);
  FREE_AND_CLEAR(id);
  FREE_AND_CLEAR(modulus);
  FREE_AND_CLEAR(exponent);
  FREE_AND_CLEAR(wrappedkey);
  return -1;
}

int wrap_and_export_privkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,CK_OBJECT_HANDLE hWrappingKey)
{
  CK_RV rv;
  int ret;
  uint8 *wrappedKeyBuf;
  int wkeybuflen;

  ret = -1;
  wkeybuflen = 2048; /* > ((4096bit max keylen) / (8bits/byte)) = 512 x 2 for priv exponent and other RSA key material */
  if((wrappedKeyBuf=(uint8 *)malloc(wkeybuflen)) == NULL) goto endit;
  {
    CK_MECHANISM wmechanism = {
      CKM_DES3_ECB, NULL_PTR, 0
    };
    if((rv=pfl->C_WrapKey(sh,&wmechanism,
			  hWrappingKey,
			  hPriv,
			  wrappedKeyBuf,(CK_ULONG *)&wkeybuflen)) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_WrapKey returned 0x%08X\n",rv);
      goto endit;
    }
  }
  /*rdump(wrappedKeyBuf,wkeybuflen);/**/
  if(print_privkeyinfo(sh,hPriv,stdout,0)) goto endit;
  {
    int i,j;
    char *pl,*pl0;
    pl = pl0 = (char *)malloc(((4*(wkeybuflen+1))/3) + 1);
    base64encode(pl,wrappedKeyBuf,wkeybuflen);
    fprintf(stdout,"wrappedkey:\n");
    j = strlen(pl);
    while(j > 0) {
      for(i=0;i<min(j,PEM_LINE_LENGTH);i++) fprintf(stdout,"%c",*pl++);
      fprintf(stdout,"\n");
      j -= PEM_LINE_LENGTH;
    }
    free(pl0);
  }
  fprintf(stdout,"\n"); /* end of key */
  ret = 0;
 endit:
  if(wrappedKeyBuf) free(wrappedKeyBuf);
  return ret;
}
int export_pubkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub)
{
  if(print_pubkeyinfo(sh,hPub,stdout,0)) return -1;
  fprintf(stdout,"\n"); /* end of key marker */
  return 0;
}

int print_pubkeyinfo(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub,FILE *fout,int flags)
{
  CK_RV rv;
  char *p;
  int i,j;
  CK_ULONG tsize;
  CK_ATTRIBUTE getattributes[] = {
    {CKA_MODULUS,NULL_PTR,0},
    {CKA_PUBLIC_EXPONENT,NULL_PTR,0},
    {CKA_ID,NULL_PTR,0},
    {CKA_LABEL,NULL_PTR,0},
    {CKA_CLASS,NULL_PTR,0},
    {CKA_KEY_TYPE,NULL_PTR,0},
    {CKA_MODULUS_BITS,NULL_PTR,0},
  };

  tsize = sizeof(getattributes)/sizeof (CK_ATTRIBUTE);
  if((rv=pfl->C_GetAttributeValue(sh,hPub,getattributes,tsize)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetAttributeValue returned 0x%08X\n",rv);
    return -1;
  }
  for(i=0;i<tsize;i++) {
    getattributes[i].pValue = malloc(getattributes[i].ulValueLen *sizeof(CK_VOID_PTR));
    if(getattributes[i].pValue == NULL) {
      for(j=0;j<i;j++) free(getattributes[j].pValue);
      fprintf(stderr,"pkcs11: error: malloc failed in %s\n",__func__);
      return -1;
    }
  }
  if((rv=pfl->C_GetAttributeValue(sh,hPub,getattributes,tsize)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetAttributeValue returned 0x%08X\n",rv);
    for(j=0;j<tsize;j++) free(getattributes[j].pValue);
    return -1;
  }
  {
    i = getattributes[3].ulValueLen;
    p = (char *)malloc(i+1);
    memcpy(p,getattributes[3].pValue,i);
    p[i] = '\0';
    fprintf(fout,"label:%s\n",p);
    free(p);
  }
  if(flags == 1) goto endit;
  {
    uint8 *pl;
    pl = (uint8 *)getattributes[2].pValue;
    fprintf(fout,"id:");
    for(i=0;i<getattributes[2].ulValueLen;i++) fprintf(fout,"%02x",pl[i]);
    fprintf(fout,"\n");
  }
  {
    if(getattributes[4].ulValueLen < sizeof(CK_OBJECT_CLASS)) fprintf(fout,"class:error\n");
    switch(*(CK_OBJECT_CLASS *)getattributes[4].pValue) {
    case CKO_PRIVATE_KEY: p = "private"; break;
    case CKO_PUBLIC_KEY: p = "public"; break;
    case CKO_SECRET_KEY: p = "secret"; break;
    default: p = "unknown"; break;
    }
    fprintf(fout,"class:%s\n",p);
  }
  {
    if(getattributes[5].ulValueLen < sizeof(CK_KEY_TYPE)) fprintf(fout,"type:error\n");
    switch(*(CK_KEY_TYPE *)getattributes[5].pValue) {
    case CKK_RSA: p = "rsa"; break;
    case CKK_DSA: p = "dsa"; break;
    case CKK_DES3: p = "des3"; break;
    default: p = "unknown"; break;
    }
    fprintf(fout,"type:%s\n",p);
  }

  if(flags == 2) {
    uint8 *pl;
    fprintf(fout, "modulus bits: %d\n",
	    *((CK_ULONG_PTR)(getattributes[6].pValue)));    
    pl = (uint8 *)getattributes[0].pValue;
    fprintf(fout,"modulus: ");
    for(i=0;i<getattributes[0].ulValueLen;i++) {
      fprintf(fout,"%.2x",pl[i]);
    }
    fprintf(fout,"\n");
    pl = (uint8 *)getattributes[1].pValue;
    fprintf(fout,"public exponent: ");
    for(i=0;i<getattributes[1].ulValueLen;i++) {
      fprintf(fout,"%.2x",pl[i]);
    }
    fprintf(fout,"\n");
    goto endit;
  }

  {
    char *p0;
    i = getattributes[0].ulValueLen;
    p = p0 = (char *)malloc(((4*(i+1))/3) + 1);
    base64encode(p,getattributes[0].pValue,i);
    fprintf(fout,"modulus:\n");
    j = strlen(p);
    while(j > 0) {
      for(i=0;i<min(j,PEM_LINE_LENGTH);i++) fprintf(fout,"%c",*p++);
      fprintf(fout,"\n");
      j -= PEM_LINE_LENGTH;
    }
    free(p0);
  }
  {
    char *p0;
    i = getattributes[1].ulValueLen;
    p = p0 = (char *)malloc(((4*(i+1))/3) + 1);
    base64encode(p,getattributes[1].pValue,i);
    fprintf(fout,"exponent:\n");
    j = strlen(p);
    while(j > 0) {
      for(i=0;i<min(j,PEM_LINE_LENGTH);i++) fprintf(fout,"%c",*p++);
      fprintf(fout,"\n");
      j -= PEM_LINE_LENGTH;
    }
    free(p0);
  }
 endit:
  for(j=0;j<tsize;j++) free(getattributes[j].pValue);
  return 0;
}
int print_privkeyinfo(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,FILE *fout,int flags)
{
  CK_RV rv;
  int i,j,n;
  char *pl,*p;
  CK_ULONG tsize;
  CK_ATTRIBUTE getattributes[] = {
    {CKA_ID,NULL_PTR,0},
    {CKA_LABEL,NULL_PTR,0},
    {CKA_CLASS,NULL_PTR,0},
    {CKA_KEY_TYPE,NULL_PTR,0},
  };
  tsize = sizeof (getattributes) / sizeof (CK_ATTRIBUTE);
  if((rv=pfl->C_GetAttributeValue(sh,hPriv,getattributes,tsize)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetAttributeValue returned 0x%08X\n",rv);
    goto endit;
  }
  for(i=0;i<tsize;i++) {
    getattributes[i].pValue = malloc(getattributes[i].ulValueLen *sizeof(CK_VOID_PTR));
    if(getattributes[i].pValue == NULL) {
      for(j=0;j <i;j++) free(getattributes[j].pValue);
      fprintf(stderr,"pkcs11: error: malloc failed in %s\n",__func__);
      goto endit;
    }
  }
  if((rv=pfl->C_GetAttributeValue(sh,hPriv,getattributes,tsize)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetAttributeValue returned 0x%08X\n",rv);
    for(j=0;j<tsize;j++) free(getattributes[j].pValue);
    goto endit;
  }
  {
    n = getattributes[1].ulValueLen;
    p = (char *)malloc(n+1);
    memcpy(p,getattributes[1].pValue,n);
    p[n] = '\0';
    fprintf(fout,"label:%s\n",p);
    free(p);
  }
  if(flags == 1) goto endit;
  {
    uint8 *pu;
    pu = (uint8 *)getattributes[0].pValue;
    fprintf(fout,"id:");
    for(i=0;i<getattributes[0].ulValueLen;i++) fprintf(fout,"%02x",pu[i]);
    fprintf(fout,"\n");
  }
  {
    if(getattributes[2].ulValueLen < sizeof(CK_OBJECT_CLASS)) fprintf(fout,"class:error\n");
    switch(*(CK_OBJECT_CLASS *)getattributes[2].pValue) {
    case CKO_PRIVATE_KEY: p = "private"; break;
    case CKO_PUBLIC_KEY: p = "public"; break;
    case CKO_SECRET_KEY: p = "secret"; break;
    default: p = "unknown"; break;
    }
    fprintf(fout,"class:%s\n",p);
  }
  {
    if(getattributes[3].ulValueLen < sizeof(CK_KEY_TYPE)) fprintf(fout,"type:error\n");
    switch(*(CK_KEY_TYPE *)getattributes[3].pValue) {
    case CKK_RSA: p = "rsa"; break;
    case CKK_DSA: p = "dsa"; break;
    case CKK_DES3: p = "des3"; break;
    default: p = "unknown"; break;
    }
    fprintf(fout,"type:%s\n",p);
  }
 endit:
  for(j=0;j<tsize;j++) free(getattributes[j].pValue);
  return 0;
}

int display_privkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,int flags)
{
  return print_privkeyinfo(sh,hPriv,stdout,flags);
}
int display_pubkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub,int flags)
{
  return print_pubkeyinfo(sh,hPub,stdout,flags);
}
int display_secretkey(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hSkey,int flags)
{
  return display_privkey(sh,hSkey,flags);
}

int delobject(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hObj)
{
  CK_RV rv;
  if((rv=pfl->C_DestroyObject(sh,hObj)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error C_DestroyObject returned 0x%08X\n",rv);
    return -1;
  }
  fprintf(stderr,"pkcs11: Deleted object %08x\n",hObj);
  return 0;
}

int signit(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,uchar *message,CK_ULONG messagelen,char *sign,long *slen) 
{
  CK_RV rv;
  CK_MECHANISM smech;

  smech.mechanism = CKM_RSA_PKCS;
  smech.pParameter = NULL_PTR;
  smech.ulParameterLen = 0;

  rv = pfl->C_SignInit(sh,&smech,hPriv);
  if(rv != CKR_OK) {
    printf("C_SignInit failed no = %02x\n", rv);
    return -1;
  }
  rv = pfl->C_Sign(sh,(CK_BYTE_PTR)message,messagelen,(CK_BYTE_PTR)sign,(CK_ULONG *)slen);
  if(rv != CKR_OK) {
    printf("C_Sign: rv = 0x%.8X\n", rv);
    return -1;
  }
  printf("%d bytes successfully generated %d byte signature!\n",messagelen,*slen);
  return 0;
}

int verify(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPub,uchar *message,CK_ULONG messagelen,char *sign,long slen)
{
  CK_RV rv;
  CK_MECHANISM smech;

  smech.mechanism = CKM_RSA_PKCS;
  smech.pParameter = NULL_PTR;
  smech.ulParameterLen = 0;

  rv = pfl->C_VerifyInit(sh,&smech,hPub);
  if(rv != CKR_OK) {
    printf("pkcs11: error: C_VerifyInit returned 0x%08X\n",rv);
    return -1;
  }
  rv = pfl->C_Verify(sh,(CK_BYTE_PTR)message,messagelen,(CK_BYTE_PTR)sign,(CK_ULONG)slen);
  if(rv != CKR_OK) {
    printf("pkcs11: error: C_Verify returned 0x%08X\n",rv);
    return -1;
  }
  printf("%d byte message verified\n",messagelen);
  return 0;
}

int rdump(unsigned char *ptr,int n)
{
  int i,j1,j2; char buf[80]; static char htoas[]="0123456789ABCDEF";
  j1 = j2 = 0; /* gcc -W */
  for(i=0;i<n;i++,j1+=3,j2++) {
    if((i&0xf) == 0) {
      if(i) { buf[j2]='\0'; printf("%s|\n",buf); }
      j1=0; j2=51; memset(buf,' ',80); buf[50]='|';
    }
    buf[j1] = htoas[(ptr[i]&0xf0) >> 4]; buf[j1+1] = htoas[ptr[i]&0x0f];
    if(ptr[i] >= 0x20 && ptr[i] < 0x80) buf[j2]=ptr[i]; else buf[j2]='.';
  }
  buf[j2]='\0'; printf("%s|\n",buf);
  return 0;
}
int cleanup(char *io)
{
  char *q,*p;

  for(q = io + strlen(io);q-- != io && (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r');) ;
  *(q+1) = '\0';
  for(q=io;*q == ' ' || *q == '\t';q++) ; /* skip leading space */
  for(p=io;*q;) *p++ = *q++;
  return 0;
}
int hex2i(char c)
{
  if(c >= '0' && c <= '9') return (int)(c - '0');
  if(c >= 'A' && c <= 'F') return (int)((c - 'A') + 10);
  return -1;
}

static const char base64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/* "outlen" should be at least (4/3)*n */
int base64encode(char *out,uint8 *in,int n)
{
  int i,len;

  i = 0;
  len = 0;
  while(n > 0) {
    *out++ = base64[ ((in[0]>>2)&0x3f) ];
    if(n > 2) {
      *out++ = base64[ ((in[0]<<4)&0x30) | ((in[1]>>4)&0x0f) ];
      *out++ = base64[ ((in[1]<<2)&0x3c) | ((in[2]>>6)&0x03) ];
      *out++ = base64[ in[2]&0x3f ];
    } else if(n == 2) {
      *out++ = base64[ ((in[0]<<4)&0x30) | ((in[1]>>4)&0x0f) ];
      *out++ = base64[ ((in[1]<<2)&0x3c) ];
      *out++ = '=';
    } else if(n == 1) {
      *out++ = base64[ ((in[0]<<4)&0x30) ];
      *out++ = '=';
      *out++ = '=';
    }
    len += 4;
    n -= 3;
    in += 3;
  }
  *out = '\0';
  return len;
}
int base64decode(char *in,uint8 *out)
{
  char *c,*p,*p0;
  int i,n,len;

  len = 0;
  n = strlen(in);
  p0 = p = (char *)malloc(n+4);
  strcpy(p0,in);
  for(i=0;i<n;i++) {
    if((c=strchr(base64,*p)) == NULL) { free(p0); return -1; }
    *p++ = c - base64;
  }
  p = p0;
  while(n > 0) {
    int k;
    k = (p[2] == 64)?1:(p[3] == 64)?2:3;
    if(k != 3) {
      if(p[2] == 64) p[2] = 0;
      if(p[3] == 64) p[3] = 0;
    }
    *out++ = (p[0]<<2)|(p[1]>>4);
    *out++ = (p[1]<<4)|(p[2]>>2);
    *out++ = (p[2]<<6)|(p[3]);
    n -= 4;
    p += 4;
    len += k;
  }
  free(p0);
  return len;
}

#ifdef FOOP
main()
{
  int i,n,j,kk;
  char *in,*out,*out0,*out2;

  for(kk=0;kk<10000;kk++) {
    n = (random()%10000) + PEM_LINE_LENGTH;
    in = malloc(n);
    out0 = out = malloc((4*(n+1))/3);
    out2 = malloc(n);
    for(i=0;i<n;i++) in[i] = random();
    base64encode(out,in,n);
    {
      FILE *fp;
      int ii,jj;
      fp = fopen("/tmp/tmpii64","w");
      jj = strlen(out);
      while(jj > 0) {
	for(ii=0;ii<min(jj,PEM_LINE_LENGTH);ii++) fprintf(fp,"%c",*out++);
	fprintf(fp,"\n");
	jj -= PEM_LINE_LENGTH;
      }
      fclose(fp);
    }
    {
      FILE *fp;
      int ii,jj;
      char lbuf[512];
      out = out0;
      out[0] = '\0';
      fp = fopen("/tmp/tmpii64","r");
      while(fgets(lbuf,sizeof(lbuf),fp)) {
	lbuf[strlen(lbuf) - 1] = '\0';
	strcat(out,lbuf);
      }
      fclose(fp);
    }
    j = base64decode(out,out2);
    if(memcmp(in,out2,n)) {
      printf("error: encoding(decoding) %d(%d) bytes\n",n,j);
    }
    free(in);
    free(out);
    free(out2);
  }

  return 0;
}
#endif

/*#include <curses.h>*/
char *fgetsne(char *s,int n, FILE *fp)
{
  char *p;
  /*noecho();*/
  p = fgets(s,n,fp);
  /*echo();*/
  return p;
}

