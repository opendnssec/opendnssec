/* $Id$ */

/*
 * Copyright (c) 2008-2009 .SE (The Internet Infrastructure Foundation).
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

#ifndef SOFTHSM_SOFTHSM_H
#define SOFTHSM_SOFTHSM_H 1

#include "pkcs11_unix.h"

typedef struct key_material_t {
  CK_ULONG sizeE;
  CK_ULONG sizeN;
  CK_ULONG sizeD;
  CK_ULONG sizeP;
  CK_ULONG sizeQ;
  CK_VOID_PTR bigE;
  CK_VOID_PTR bigN;
  CK_VOID_PTR bigD;
  CK_VOID_PTR bigP;
  CK_VOID_PTR bigQ;
  key_material_t() {
    sizeE = 0;
    sizeN = 0;
    sizeD = 0;
    sizeP = 0;
    sizeQ = 0;
    bigE = NULL_PTR;
    bigN = NULL_PTR;
    bigD = NULL_PTR;
    bigP = NULL_PTR;
    bigQ = NULL_PTR;
  }
} key_material_t;

void usage();
void initToken(char *slot, char *label, char *soPIN, char *userPIN);
void showSlots();
void importKeyPair(char *filePath, char *filePIN, char *slot, char *userPIN, char *objectLabel, char *objectID);
char* hexStrToBin(char *objectID, int idLength, int *newLen);
int hexdigit_to_int(char ch);
key_material_t* importKeyMat(char *filePath, char *filePIN);
void freeKeyMaterial(key_material_t *keyMaterial);

#endif /* SOFTHSM_SOFTHSM_H */
