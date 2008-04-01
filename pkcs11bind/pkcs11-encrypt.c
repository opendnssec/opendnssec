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

int encrypt_stream(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hKey,FILE *fin,FILE *fout);
int decrypt_stream(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hKey,FILE *fin,FILE *fout);
int print_privkeyinfo(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hPriv,FILE *fout,
int flags);

int hex2i(char c);
int cleanup(char *io);
int rdump(unsigned char *ptr,int n);
char *fgetsne(char *bufin,int bufinsize,FILE *streamin);
#define PEM_LINE_LENGTH 64
int base64encode(char *out,uint8 *in,int n);
int base64decode(char *in,uint8 *out);

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
  char                   *userpin,*infile,*outfile;
  FILE *fin,*fout;

  {
    int ch;
    extern char *optarg;
    extern int optind;
    extern int optopt;
    extern int opterr;
    extern int optreset;
    
    infile = NULL;
    outfile = NULL;
    wrappingkeylabel = NULL;
    userpin = NULL;
    cmd = 0;
    wslot = -1;
    while((ch=getopt(argc,argv,"P:S:w:dei:o:")) != -1) {
      switch(ch) {
      case 'i':
        infile = optarg;
        break;
      case 'o':
        outfile = optarg;
        break;
      case 'P':
        userpin = optarg;
        break;
      case 'w':
	wrappingkeylabel = optarg;
	break;
      case 'S':
	wslot = atoi(optarg);
	break;
      case 'e':
	cmd = 'e';
        break;
      case 'd':
	cmd = 'd';
	break;
      case '?':
      default:
	printf("Usage:%s -e|-d -i infile -o outfile [-P pin] [-w keylabel] [-S HSM_slot_number]\n",argv[0]);
	return -1;
      }
    }
    argc -= optind;
    argv += optind;
  }
  if(infile == NULL) {
    fprintf(stderr,"No input file specified\n");
    return -1;
  }
  if(outfile == NULL) {
    fprintf(stderr,"No output file specified\n");
    return -1;
  }
  if(cmd == 0) {
    fprintf(stderr,"You must specify either -e for encryption or -d for decryption\n");
    return -1;
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
  if((rv=pfl->C_OpenSession(slots[k],CKF_RW_SESSION|CKF_SERIAL_SESSION,NULL,NULL,&sh)) != CKR_OK) {
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

  if(cmd == 'e') {
    if((fin=fopen(infile,"r")) == NULL) {
      fprintf(stderr,"Cannot open input file %s\n",infile);
      goto endit;
    }
    if((fout=fopen(outfile,"w")) == NULL) {
      fprintf(stderr,"Cannot open output file %s\n",outfile);
      goto endit;
    }
    if(getwrapkey(sh,wrappingkeylabel,&hWrappingKey)) {
      goto endit;
    }
    encrypt_stream(sh,hWrappingKey,fin,fout);
    fclose(fin);
    fclose(fout);
    goto endit;
  } else
  if(cmd == 'd') {
    if((fin=fopen(infile,"r")) == NULL) {
      fprintf(stderr,"Cannot open input file %s\n",infile);
      goto endit;
    }
    if((fout=fopen(outfile,"w")) == NULL) {
      fprintf(stderr,"Cannot open output file %s\n",outfile);
      goto endit;
    }
    if(getwrapkey(sh,wrappingkeylabel,&hWrappingKey)) {
      goto endit;
    }
    decrypt_stream(sh,hWrappingKey,fin,fout);
    fclose(fin);
    fclose(fout);
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
  /*pfl->C_Finalize(0);/* never on smartcard */
  return 0;
}
int encrypt_stream(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hKey,FILE *fin,FILE *fout)
{
  CK_BYTE  iv[8];
  CK_MECHANISM mechanism = {
    CKM_DES3_CBC_PAD, iv, sizeof(iv)
  };
  CK_BYTE  buf[1024];
  CK_ULONG olen;
  CK_RV rv;
  CK_LONG n;
  unsigned long icnt,ocnt;

  icnt = ocnt = 0;
  memset(iv,0,sizeof(iv));
  if((rv=pfl->C_EncryptInit(sh,&mechanism,hKey)) != CKR_OK) {
    printf("pkcs11: error: C_EncryptInit returned 0x%08X\n",rv);
    return -1;
  }
  while((n=fread(buf,1,(sizeof(buf)/2),fin)) > 0) {
    olen = sizeof(buf);
    if((rv=pfl->C_EncryptUpdate(sh,buf,n,buf,&olen)) != CKR_OK) {
      printf("pkcs11: error: C_EncryptUpdate returned 0x%08X\n",rv);
      return -1;
    }
    fwrite(buf,1,olen,fout);
    icnt += n;
    ocnt += olen;
    if(olen != n) {
      printf("--in:%d out:%d\n",n,olen);
    }
  }
  /* Get last little encrypted bit */
  olen = sizeof(buf);
  if((rv=pfl->C_EncryptFinal(sh,buf,&olen)) != CKR_OK) {
    printf("pkcs11: error: C_EncryptFinal returned 0x%08X\n",rv);
    return -1;
  }
  fwrite(buf,1,olen,fout);
  ocnt += olen;
  /*printf("in:%lu out:%lu (last=%d)\n",icnt,ocnt,olen);*/
  return 0;
}
int decrypt_stream(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hKey,FILE *fin,FILE *fout)
{
  CK_BYTE  iv[8];
  CK_MECHANISM mechanism = {
    CKM_DES3_CBC_PAD, iv, sizeof(iv)
  };
  CK_BYTE  buf[1024];
  CK_ULONG olen;
  CK_RV rv;
  CK_LONG n;
  unsigned long icnt,ocnt;

  icnt = ocnt = 0;
  memset(iv,0,sizeof(iv));
  if((rv=pfl->C_DecryptInit(sh,&mechanism,hKey)) != CKR_OK) {
    printf("pkcs11: error: C_DecryptInit returned 0x%08X\n",rv);
    return -1;
  }
  while((n=fread(buf,1,(sizeof(buf)/2),fin)) > 0) {
    olen = sizeof(buf);
    if((rv=pfl->C_DecryptUpdate(sh,buf,n,buf,&olen)) != CKR_OK) {
      printf("pkcs11: error: C_DecryptUpdate returned 0x%08X\n",rv);
      return -1;
    }
    fwrite(buf,1,olen,fout);
    icnt += n;
    ocnt += olen;
    if(olen != n) {
      printf("--in:%d out:%d\n",n,olen);
    }
  }
  /* Get last little encrypted bit */
  olen = sizeof(buf);
  if((rv=pfl->C_DecryptFinal(sh,buf,&olen)) != CKR_OK) {
    printf("pkcs11: error: C_DecryptFinal returned 0x%08X\n",rv);
    return -1;
  }
  fwrite(buf,1,olen,fout);
  ocnt += olen;
  /*printf("in:%lu out:%lu (last=%d)\n",icnt,ocnt,olen);*/
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
	print_privkeyinfo(sh,hKeys[i],stdout,0);
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

