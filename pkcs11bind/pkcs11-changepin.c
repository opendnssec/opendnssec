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
 *   pkcs11 HSM PIN change utility
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

typedef unsigned char uint8;
#define min(x,y) ((x)<(y)?(x):(y))

#define BUFFERSIZ 8192
#define MAX_SLOTS 100
#define MAX_KEYS_PER_SLOT 64

static CK_FUNCTION_LIST_PTR  pfl;
CK_BBOOL true=CK_TRUE;

int cleanup(char *io);
int rdump(unsigned char *ptr,int n);
char *fgetsne(char *bufin,int bufinsize,FILE *streamin);

int main(int argc,char *argv[])
{
  CK_C_GetFunctionList   pGFL=0;
  CK_RV                  rv;
  CK_ULONG               nslots;
  CK_SLOT_ID             slots[MAX_SLOTS];
  CK_SESSION_HANDLE      sh;
  void                   *hLib;
  int                    i,k,n;
  char                   *p,lbuf[512];  
  char                   *opin,*npin;

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
    fprintf(stderr,"pkcs11: error: failed to open lib %s\n",lbuf);
    return -1;
  }
  if((pGFL=(CK_C_GetFunctionList)dlsym(hLib,"C_GetFunctionList")) == NULL) {
    fprintf(stderr,"pkcs11: error: Cannot find GetFunctionList()\n");
    dlclose(hLib);
    return -1;
  }
  if((rv=pGFL(&pfl)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetFunctionList returned 0x%02x\n",rv);
    return -1;
  }
  if((rv = pfl->C_Initialize(NULL)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_Initialize returned 0x%02x\n",rv);
    return -1;
  }
  nslots = MAX_SLOTS;
  if((rv=pfl->C_GetSlotList(TRUE,slots,&nslots)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_Getslots returned 0x%x\n",rv);
    return -1;
  }
  /*printf("Got %d Slots\n",nslots);/**/
  k = 0;
  if(nslots > 1) {
    fprintf(stderr,"Found %d slots. Enter slot number to operate on (0):",nslots);
    if(fgets(lbuf,sizeof(lbuf),stdin) == NULL) {
      return -1;
    }
    cleanup(lbuf);
    k = atoi(lbuf);
    fprintf(stderr,"%d\n",k);
  }
  rv = pfl->C_OpenSession(slots[k],CKF_RW_SESSION|CKF_SERIAL_SESSION,NULL,NULL,&sh);
  if(rv != CKR_OK) {
    fprintf(stderr,"pkcs11: error: Could not open slot %d\n C_OpenSession returned 0x%02x\n",k,rv);
    return -1;
  }
  fprintf(stderr,"Enter Old PIN for slot %d: ",k);
  if(fgetsne(lbuf,sizeof(lbuf),stdin) == NULL) {
    goto endit;
  }
  cleanup(lbuf);
  if((rv=pfl->C_Login(sh,CKU_USER,lbuf,strlen(lbuf))) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: Invalid PIN\n C_Login returned 0x%08x\n",rv);
    goto endit;
  }
  opin = strdup(lbuf);
  fprintf(stderr,"Enter New PIN for slot %d: ",k);
  if(fgetsne(lbuf,sizeof(lbuf),stdin) == NULL) {
    goto endit;
  }
  cleanup(lbuf);
  npin = strdup(lbuf);
  fprintf(stderr,"Re-enter New PIN for slot %d: ",k);
  if(fgetsne(lbuf,sizeof(lbuf),stdin) == NULL) {
    goto endit;
  }
  cleanup(lbuf);
  if(strcmp(npin,lbuf)) {
    fprintf(stderr," new PINs dont match! Try again\n");
    goto endit;
  }
  if((rv=pfl->C_SetPIN(sh,opin,strlen(opin),lbuf,strlen(lbuf))) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: Invalid PIN\n C_SetPin returned 0x%08x\n",rv);
    goto endit;
  }
  fprintf(stderr,"PIN change for slot %d sucessful\n",k);
 endit:
  if((rv=pfl->C_Logout(sh)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_Logout returned x%08x\n",rv);
  }
  if((rv=pfl->C_CloseSession(sh)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_CloseSession returned x%08x",rv);
  }
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
/*#include <curses.h>*/
char *fgetsne(char *s,int n, FILE *fp)
{
  char *p;
  /*noecho();*/
  p = fgets(s,n,fp);
  /*echo();*/
  return p;
}

