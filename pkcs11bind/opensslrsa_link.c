/*
 * Copyright (C) 2004-2006  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2000-2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Principal Author: Brian Wellington
 * $Id$
 */
#define PKCS11

#ifdef OPENSSL

#include <config.h>

#include <isc/entropy.h>
#include <isc/md5.h>
#include <isc/sha1.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dst/result.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER > 0x00908000L
#include <openssl/bn.h>
#endif

/*
 * We don't use configure for windows so enforce the OpenSSL version
 * here.  Unlike with configure we don't support overriding this test.
 */
#ifdef WIN32
#if !((OPENSSL_VERSION_NUMBER >= 0x009070cfL && \
       OPENSSL_VERSION_NUMBER < 0x00908000L) || \
      OPENSSL_VERSION_NUMBER >= 0x0090804fL)
#error Please upgrade OpenSSL to 0.9.8d/0.9.7l or greater.
#endif
#endif


	/*
	 * XXXMPA  Temporarially disable RSA_BLINDING as it requires
	 * good quality random data that cannot currently be guarenteed.
	 * XXXMPA  Find which versions of openssl use pseudo random data
	 * and set RSA_FLAG_BLINDING for those.
	 */

#if 0
#if OPENSSL_VERSION_NUMBER < 0x0090601fL
#define SET_FLAGS(rsa) \
	do { \
	(rsa)->flags &= ~(RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE); \
	(rsa)->flags |= RSA_FLAG_BLINDING; \
	} while (0)
#else
#define SET_FLAGS(rsa) \
	do { \
		(rsa)->flags |= RSA_FLAG_BLINDING; \
	} while (0)
#endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x0090601fL
#define SET_FLAGS(rsa) \
	do { \
	(rsa)->flags &= ~(RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE); \
	(rsa)->flags &= ~RSA_FLAG_BLINDING; \
	} while (0)
#elif defined(RSA_FLAG_NO_BLINDING)
#define SET_FLAGS(rsa) \
	do { \
		(rsa)->flags &= ~RSA_FLAG_BLINDING; \
		(rsa)->flags |= RSA_FLAG_NO_BLINDING; \
	} while (0)
#else
#define SET_FLAGS(rsa) \
	do { \
		(rsa)->flags &= ~RSA_FLAG_BLINDING; \
	} while (0)
#endif




#ifdef PKCS11
#include <dns/name.h>
#define MAXPATHLEN 512
static int use_pkcs11=0; /*off by default. on if PKCS11_LIBRARY_PATH defined*/
/* 
 * Caution: since this loads a 3rd party library and initializes it, 
 * it may reset signal() handling and the like. So pkcs11_initlib must 
 * be called in main() before anything else. 
 * Will check for PKCS11_LIBRARY_PATH lib and set.
 */
int pkcs11_initlib(char *pin);
static int pkcs11_RSA_sign(dst_key_t *key,unsigned char *msg,unsigned int mlen,unsigned char *sign,unsigned int *slen);
static int pkcs11_parse(dst_key_t *key,isc_lex_t *lexer,unsigned char *modulus,int *modulus_len,unsigned char *pubexponent,int *pubexponent_len);
static void pkcs11_free(void *cb);
#define PKCS11_MAGIC 0x5A62
static int ispkcs11(const dst_key_t *key);
static int pkcs11_getkey(dst_key_t *key,unsigned char *modulus,int *modulus_len,unsigned char *pubexponent,int *pubexponent_len);
static int pkcs11_genkey(dst_key_t *key,unsigned char *modulus,int *modulus_len,unsigned char *pubexponent,int *pubexponent_len);
static int pkcs11_writeparams(const dst_key_t *key,char *fname);
#endif /* PKCS11 */




static isc_result_t opensslrsa_todns(const dst_key_t *key, isc_buffer_t *data);

static isc_result_t
opensslrsa_createctx(dst_key_t *key, dst_context_t *dctx) {
	UNUSED(key);
	REQUIRE(dctx->key->key_alg == DST_ALG_RSAMD5 ||
		dctx->key->key_alg == DST_ALG_RSASHA1);

	if (dctx->key->key_alg == DST_ALG_RSAMD5) {
		isc_md5_t *md5ctx;

		md5ctx = isc_mem_get(dctx->mctx, sizeof(isc_md5_t));
		if (md5ctx == NULL)
			return (ISC_R_NOMEMORY);
		isc_md5_init(md5ctx);
		dctx->opaque = md5ctx;
	} else {
		isc_sha1_t *sha1ctx;

		sha1ctx = isc_mem_get(dctx->mctx, sizeof(isc_sha1_t));
		if (sha1ctx == NULL)
			return (ISC_R_NOMEMORY);
		isc_sha1_init(sha1ctx);
		dctx->opaque = sha1ctx;
	}

	return (ISC_R_SUCCESS);
}

static void
opensslrsa_destroyctx(dst_context_t *dctx) {
	REQUIRE(dctx->key->key_alg == DST_ALG_RSAMD5 ||
		dctx->key->key_alg == DST_ALG_RSASHA1);

	if (dctx->key->key_alg == DST_ALG_RSAMD5) {
		isc_md5_t *md5ctx = dctx->opaque;

		if (md5ctx != NULL) {
			isc_md5_invalidate(md5ctx);
			isc_mem_put(dctx->mctx, md5ctx, sizeof(isc_md5_t));
		}
	} else {
		isc_sha1_t *sha1ctx = dctx->opaque;

		if (sha1ctx != NULL) {
			isc_sha1_invalidate(sha1ctx);
			isc_mem_put(dctx->mctx, sha1ctx, sizeof(isc_sha1_t));
		}
	}
	dctx->opaque = NULL;
}

static isc_result_t
opensslrsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	REQUIRE(dctx->key->key_alg == DST_ALG_RSAMD5 ||
		dctx->key->key_alg == DST_ALG_RSASHA1);

	if (dctx->key->key_alg == DST_ALG_RSAMD5) {
		isc_md5_t *md5ctx = dctx->opaque;
		isc_md5_update(md5ctx, data->base, data->length);
	} else {
		isc_sha1_t *sha1ctx = dctx->opaque;
		isc_sha1_update(sha1ctx, data->base, data->length);
	}
	return (ISC_R_SUCCESS);
}

static isc_result_t
opensslrsa_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	dst_key_t *key = dctx->key;
	RSA *rsa = key->opaque;
	isc_region_t r;
	/* note: ISC_SHA1_DIGESTLENGTH > ISC_MD5_DIGESTLENGTH */
	unsigned char digest[ISC_SHA1_DIGESTLENGTH];
	unsigned int siglen = 0;
	int status;
	int type;
	unsigned int digestlen;
	char *message;
	unsigned long err;
	const char* file;
	int line;

	REQUIRE(dctx->key->key_alg == DST_ALG_RSAMD5 ||
		dctx->key->key_alg == DST_ALG_RSASHA1);

	isc_buffer_availableregion(sig, &r);

	if (r.length < (unsigned int) RSA_size(rsa))
		return (ISC_R_NOSPACE);

	if (dctx->key->key_alg == DST_ALG_RSAMD5) {
		isc_md5_t *md5ctx = dctx->opaque;
		isc_md5_final(md5ctx, digest);
		type = NID_md5;
		digestlen = ISC_MD5_DIGESTLENGTH;
	} else {
		isc_sha1_t *sha1ctx = dctx->opaque;
		isc_sha1_final(sha1ctx, digest);
		type = NID_sha1;
		digestlen = ISC_SHA1_DIGESTLENGTH;
	}

	if(ispkcs11(key)) {
	  siglen = r.length; /* pass size of buffer to signer */
	  status = pkcs11_RSA_sign(key,digest,digestlen,r.base,&siglen);
	  if(status == 0) status = 1; else status = 0;
	} else {
	  status = RSA_sign(type, digest, digestlen, r.base, &siglen, rsa);
	}
	if (status == 0) {
		err = ERR_peek_error_line(&file, &line);
		if (err != 0U) {
			message = ERR_error_string(err, NULL);
			fprintf(stderr, "%s:%s:%d\n", message,
				file ? file : "", line);
		}
		return (dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	isc_buffer_add(sig, siglen);

	return (ISC_R_SUCCESS);
}

static isc_result_t
opensslrsa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	dst_key_t *key = dctx->key;
	RSA *rsa = key->opaque;
	/* note: ISC_SHA1_DIGESTLENGTH > ISC_MD5_DIGESTLENGTH */
	unsigned char digest[ISC_SHA1_DIGESTLENGTH];
	int status = 0;
	int type;
	unsigned int digestlen;

	REQUIRE(dctx->key->key_alg == DST_ALG_RSAMD5 ||
		dctx->key->key_alg == DST_ALG_RSASHA1);

	if (dctx->key->key_alg == DST_ALG_RSAMD5) {
		isc_md5_t *md5ctx = dctx->opaque;
		isc_md5_final(md5ctx, digest);
		type = NID_md5;
		digestlen = ISC_MD5_DIGESTLENGTH;
	} else {
		isc_sha1_t *sha1ctx = dctx->opaque;
		isc_sha1_final(sha1ctx, digest);
		type = NID_sha1;
		digestlen = ISC_SHA1_DIGESTLENGTH;
	}

	if (sig->length < (unsigned int) RSA_size(rsa))
		return (DST_R_VERIFYFAILURE);

	status = RSA_verify(type, digest, digestlen, sig->base,
			    RSA_size(rsa), rsa);

	if (status == 0)
		return (dst__openssl_toresult(DST_R_VERIFYFAILURE));

	return (ISC_R_SUCCESS);
}

static isc_boolean_t
opensslrsa_compare(const dst_key_t *key1, const dst_key_t *key2) {
	int status;
	RSA *rsa1, *rsa2;

	rsa1 = (RSA *) key1->opaque;
	rsa2 = (RSA *) key2->opaque;

	if (rsa1 == NULL && rsa2 == NULL)
		return (ISC_TRUE);
	else if (rsa1 == NULL || rsa2 == NULL)
		return (ISC_FALSE);

	status = BN_cmp(rsa1->n, rsa2->n) ||
		 BN_cmp(rsa1->e, rsa2->e);

	if (status != 0)
		return (ISC_FALSE);

	if (rsa1->d != NULL || rsa2->d != NULL) {
		if (rsa1->d == NULL || rsa2->d == NULL)
			return (ISC_FALSE);
		status = BN_cmp(rsa1->d, rsa2->d) ||
			 BN_cmp(rsa1->p, rsa2->p) ||
			 BN_cmp(rsa1->q, rsa2->q);

		if (status != 0)
			return (ISC_FALSE);
	}
	return (ISC_TRUE);
}

static isc_result_t
opensslrsa_generate(dst_key_t *key, int exp) {
#if OPENSSL_VERSION_NUMBER > 0x00908000L
	BN_GENCB cb;
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();

        if (rsa == NULL || e == NULL)
          goto err;

#ifdef PKCS11
	/*
	 * load public key from HSM as well as a "handle" to priv info.
	 */
	if(key->key_size == 0) { /* "dnssec-genkey -b 0" */
	  unsigned char pkcs11_modulus[512],pkcs11_publicexponent[512];
          int pkcs11_modulus_len=0;
	  int pkcs11_publicexponent_len=0;

	  if(pkcs11_getkey(key,pkcs11_modulus,&pkcs11_modulus_len,pkcs11_publicexponent,&pkcs11_publicexponent_len)) {
	    goto err;
	  }
	  
	  BN_free(e);
	  SET_FLAGS(rsa);
	  rsa->d = key->opaque; /* from pkcs11_getkey(). fakes out ispriv */
	  key->opaque = rsa;    /* do this to fit in */
	  
	  rsa->n = BN_bin2bn(pkcs11_modulus,pkcs11_modulus_len,NULL);
	  rsa->e = BN_bin2bn(pkcs11_publicexponent,pkcs11_publicexponent_len,NULL);
	  {
	    isc_buffer_t dnsbuf;
	    unsigned char dns_array[DST_KEY_MAXSIZE];
	    isc_region_t r;
	    isc_result_t ret;
	    char namestr[512];
	    
	    isc_buffer_init(&dnsbuf, dns_array, sizeof(dns_array));
	    ret = dst_key_todns(key,&dnsbuf);
	    if (ret != ISC_R_SUCCESS)
	      return (ret);
	    
	    isc_buffer_usedregion(&dnsbuf, &r);
	    key->key_id = dst_region_computeid(&r,key->key_alg);
	    dns_name_format(key->key_name,namestr,sizeof(namestr));
	    fprintf(stderr,"Label smart card K%s.+%03d+%05d\n",namestr,key->key_alg,key->key_id);
	  }
	  key->key_size = BN_num_bits(rsa->n);
	  
	  return (ISC_R_SUCCESS);
	}

	if(use_pkcs11) { /* generate a new key in the HSM */
	  unsigned char pkcs11_modulus[512],pkcs11_publicexponent[512];
          int pkcs11_modulus_len=0;
	  int pkcs11_publicexponent_len=0;

	  if(pkcs11_genkey(key,pkcs11_modulus,&pkcs11_modulus_len,pkcs11_publicexponent,&pkcs11_publicexponent_len)) {
	    goto err;
	  }
	  
	  BN_free(e);
	  SET_FLAGS(rsa);

	  rsa->d = key->opaque; /* from pkcs11_getkey(). fakes out ispriv */
	  key->opaque = rsa;    /* do this to fit in */
	  
	  rsa->n = BN_bin2bn(pkcs11_modulus,pkcs11_modulus_len,NULL);
	  rsa->e = BN_bin2bn(pkcs11_publicexponent,pkcs11_publicexponent_len,NULL);
	  key->key_size = BN_num_bits(rsa->n);
	  return (ISC_R_SUCCESS);
	}


#else /* PKCS11 */
	if(key->key_size == 0) {
	  return (DST_R_UNSUPPORTEDALG);
	}
#endif /* PKCS11 */

	if (exp == 0) {
		/* RSA_F4 0x10001 */
		BN_set_bit(e, 0);
		BN_set_bit(e, 16);
	} else {
		/* F5 0x100000001 */
		BN_set_bit(e, 0);
		BN_set_bit(e, 32);
	}

	BN_GENCB_set_old(&cb, NULL, NULL);

	if (RSA_generate_key_ex(rsa, key->key_size, e, &cb)) {
		BN_free(e);
		SET_FLAGS(rsa);
		key->opaque = rsa;
		return (ISC_R_SUCCESS);
	}
err:
	if (e != NULL)
		BN_free(e);
	if (rsa != NULL)
		RSA_free(rsa);
	return (dst__openssl_toresult(DST_R_OPENSSLFAILURE));
#else
	RSA *rsa;
	unsigned long e;

	if (exp == 0)
	       e = RSA_F4;
	else
	       e = 0x40000003;
	rsa = RSA_generate_key(key->key_size, e, NULL, NULL);
	if (rsa == NULL)
	       return (dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	SET_FLAGS(rsa);
	key->opaque = rsa;

	return (ISC_R_SUCCESS);
#endif
}

static isc_boolean_t
opensslrsa_isprivate(const dst_key_t *key) {
	RSA *rsa = (RSA *) key->opaque;

	return (ISC_TF(rsa != NULL && rsa->d != NULL));
}

static void
opensslrsa_destroy(dst_key_t *key) {
	RSA *rsa = key->opaque;

#ifdef PKCS11
	if(ispkcs11(key)) {
	  pkcs11_free((void *)rsa->d);
	  rsa->d = NULL;
	}
#endif
	RSA_free(rsa);
	key->opaque = NULL;
}


static isc_result_t
opensslrsa_todns(const dst_key_t *key, isc_buffer_t *data) {
	RSA *rsa;
	isc_region_t r;
	unsigned int e_bytes;
	unsigned int mod_bytes;

	REQUIRE(key->opaque != NULL);

	rsa = (RSA *) key->opaque;

	isc_buffer_availableregion(data, &r);

	e_bytes = BN_num_bytes(rsa->e);
	mod_bytes = BN_num_bytes(rsa->n);

	if (e_bytes < 256) {	/*%< key exponent is <= 2040 bits */
		if (r.length < 1)
			return (ISC_R_NOSPACE);
		isc_buffer_putuint8(data, (isc_uint8_t) e_bytes);
	} else {
		if (r.length < 3)
			return (ISC_R_NOSPACE);
		isc_buffer_putuint8(data, 0);
		isc_buffer_putuint16(data, (isc_uint16_t) e_bytes);
	}

	if (r.length < e_bytes + mod_bytes)
		return (ISC_R_NOSPACE);
	isc_buffer_availableregion(data, &r);

	BN_bn2bin(rsa->e, r.base);
	r.base += e_bytes;
	BN_bn2bin(rsa->n, r.base);

	isc_buffer_add(data, e_bytes + mod_bytes);

	return (ISC_R_SUCCESS);
}

static isc_result_t
opensslrsa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	RSA *rsa;
	isc_region_t r;
	unsigned int e_bytes;

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0)
		return (ISC_R_SUCCESS);

	rsa = RSA_new();
	if (rsa == NULL)
		return (dst__openssl_toresult(ISC_R_NOMEMORY));
	SET_FLAGS(rsa);

	if (r.length < 1) {
		RSA_free(rsa);
		return (DST_R_INVALIDPUBLICKEY);
	}
	e_bytes = *r.base++;
	r.length--;

	if (e_bytes == 0) {
		if (r.length < 2) {
			RSA_free(rsa);
			return (DST_R_INVALIDPUBLICKEY);
		}
		e_bytes = ((*r.base++) << 8);
		e_bytes += *r.base++;
		r.length -= 2;
	}

	if (r.length < e_bytes) {
		RSA_free(rsa);
		return (DST_R_INVALIDPUBLICKEY);
	}
	rsa->e = BN_bin2bn(r.base, e_bytes, NULL);
	r.base += e_bytes;
	r.length -= e_bytes;

	rsa->n = BN_bin2bn(r.base, r.length, NULL);

	key->key_size = BN_num_bits(rsa->n);

	isc_buffer_forward(data, r.length);

	key->opaque = (void *) rsa;

	return (ISC_R_SUCCESS);
}


static isc_result_t
opensslrsa_tofile(const dst_key_t *key, const char *directory) {
	int i;
	RSA *rsa;
	dst_private_t priv;
	unsigned char *bufs[8];
	isc_result_t result;

	if (key->opaque == NULL)
		return (DST_R_NULLKEY);

        if(ispkcs11(key)) {
          char namestr[512],fname[512];

          dns_name_format(key->key_name,namestr,sizeof(namestr));
	  if(namestr[0] != '.') strcat(namestr,"."); else { /* root */ }
	  if(directory) sprintf(fname,"%s/K%s+%03d+%05u.private",directory,namestr,key->key_alg,key->key_id);
	  else sprintf(fname,"K%s+%03d+%05u.private",namestr,key->key_alg,key->key_id);
	  pkcs11_writeparams(key,fname);
          return (ISC_R_SUCCESS);
        }

	rsa = (RSA *) key->opaque;

	for (i = 0; i < 8; i++) {
		bufs[i] = isc_mem_get(key->mctx, BN_num_bytes(rsa->n));
		if (bufs[i] == NULL) {
			result = ISC_R_NOMEMORY;
			goto fail;
		}
	}

	i = 0;

	priv.elements[i].tag = TAG_RSA_MODULUS;
	priv.elements[i].length = BN_num_bytes(rsa->n);
	BN_bn2bin(rsa->n, bufs[i]);
	priv.elements[i].data = bufs[i];
	i++;

	priv.elements[i].tag = TAG_RSA_PUBLICEXPONENT;
	priv.elements[i].length = BN_num_bytes(rsa->e);
	BN_bn2bin(rsa->e, bufs[i]);
	priv.elements[i].data = bufs[i];
	i++;

	priv.elements[i].tag = TAG_RSA_PRIVATEEXPONENT;
	priv.elements[i].length = BN_num_bytes(rsa->d);
	BN_bn2bin(rsa->d, bufs[i]);
	priv.elements[i].data = bufs[i];
	i++;

	priv.elements[i].tag = TAG_RSA_PRIME1;
	priv.elements[i].length = BN_num_bytes(rsa->p);
	BN_bn2bin(rsa->p, bufs[i]);
	priv.elements[i].data = bufs[i];
	i++;

	priv.elements[i].tag = TAG_RSA_PRIME2;
	priv.elements[i].length = BN_num_bytes(rsa->q);
	BN_bn2bin(rsa->q, bufs[i]);
	priv.elements[i].data = bufs[i];
	i++;

	priv.elements[i].tag = TAG_RSA_EXPONENT1;
	priv.elements[i].length = BN_num_bytes(rsa->dmp1);
	BN_bn2bin(rsa->dmp1, bufs[i]);
	priv.elements[i].data = bufs[i];
	i++;

	priv.elements[i].tag = TAG_RSA_EXPONENT2;
	priv.elements[i].length = BN_num_bytes(rsa->dmq1);
	BN_bn2bin(rsa->dmq1, bufs[i]);
	priv.elements[i].data = bufs[i];
	i++;

	priv.elements[i].tag = TAG_RSA_COEFFICIENT;
	priv.elements[i].length = BN_num_bytes(rsa->iqmp);
	BN_bn2bin(rsa->iqmp, bufs[i]);
	priv.elements[i].data = bufs[i];
	i++;

	priv.nelements = i;
	result =  dst__privstruct_writefile(key, &priv, directory);
 fail:
	for (i = 0; i < 8; i++) {
		if (bufs[i] == NULL)
			break;
		isc_mem_put(key->mctx, bufs[i], BN_num_bytes(rsa->n));
	}
	return (result);
}

static isc_result_t
opensslrsa_parse(dst_key_t *key, isc_lex_t *lexer) {
	dst_private_t priv;
	isc_result_t ret;
	int i;
	RSA *rsa = NULL;
	isc_mem_t *mctx = key->mctx;
#define DST_RET(a) {ret = a; goto err;}

	/* read private key file */
	ret = dst__privstruct_parse(key, DST_ALG_RSA, lexer, mctx, &priv);
	if (ret != ISC_R_SUCCESS) {
	  unsigned char pkcs11_modulus[512],pkcs11_publicexponent[512];
	  int pkcs11_modulus_len=0;
	  int pkcs11_publicexponent_len=0;

	  if(key->opaque) {
	    fprintf(stderr,"pkcs11: warning: pkcs11_parse() already called\n");
	  }
	  if(pkcs11_parse(key,lexer,pkcs11_modulus,&pkcs11_modulus_len,pkcs11_publicexponent,&pkcs11_publicexponent_len)) {
	    return (ret);
	  } else {
	    /*
	     * load public key from HSM as well as a "handle" to priv info.
	     */
	    rsa = RSA_new();
	    SET_FLAGS(rsa);
	    rsa->d = key->opaque; /* from pkcs11_parse(). fakes out ispriv */
	    key->opaque = rsa; /* do this to fit in */

	    rsa->n = BN_bin2bn(pkcs11_modulus,pkcs11_modulus_len,NULL);
	    rsa->e = BN_bin2bn(pkcs11_publicexponent,pkcs11_publicexponent_len,NULL);
	    {
	      isc_buffer_t dnsbuf;
	      unsigned char dns_array[DST_KEY_MAXSIZE];
	      isc_region_t r;
	      isc_result_t ret;

	      isc_buffer_init(&dnsbuf, dns_array, sizeof(dns_array));
	      ret = dst_key_todns(key, &dnsbuf);
	      if (ret != ISC_R_SUCCESS)
                return (ret);

	      isc_buffer_usedregion(&dnsbuf,&r);
	      key->key_id = dst_region_computeid(&r,key->key_alg);
	    }
	    key->key_size = BN_num_bits(rsa->n);

	    return ISC_R_SUCCESS;
	  }
	}

	rsa = RSA_new();
	if (rsa == NULL)
		DST_RET(ISC_R_NOMEMORY);
	SET_FLAGS(rsa);
	key->opaque = rsa;

	for (i = 0; i < priv.nelements; i++) {
		BIGNUM *bn;
		bn = BN_bin2bn(priv.elements[i].data,
			       priv.elements[i].length, NULL);
		if (bn == NULL)
			DST_RET(ISC_R_NOMEMORY);

		switch (priv.elements[i].tag) {
			case TAG_RSA_MODULUS:
				rsa->n = bn;
				break;
			case TAG_RSA_PUBLICEXPONENT:
				rsa->e = bn;
				break;
			case TAG_RSA_PRIVATEEXPONENT:
				rsa->d = bn;
				break;
			case TAG_RSA_PRIME1:
				rsa->p = bn;
				break;
			case TAG_RSA_PRIME2:
				rsa->q = bn;
				break;
			case TAG_RSA_EXPONENT1:
				rsa->dmp1 = bn;
				break;
			case TAG_RSA_EXPONENT2:
				rsa->dmq1 = bn;
				break;
			case TAG_RSA_COEFFICIENT:
				rsa->iqmp = bn;
				break;
		}
	}
	dst__privstruct_free(&priv, mctx);

	key->key_size = BN_num_bits(rsa->n);

	return (ISC_R_SUCCESS);

 err:
	opensslrsa_destroy(key);
	dst__privstruct_free(&priv, mctx);
	memset(&priv, 0, sizeof(priv));
	return (ret);
}

static dst_func_t opensslrsa_functions = {
	opensslrsa_createctx,
	opensslrsa_destroyctx,
	opensslrsa_adddata,
	opensslrsa_sign,
	opensslrsa_verify,
	NULL, /*%< computesecret */
	opensslrsa_compare,
	NULL, /*%< paramcompare */
	opensslrsa_generate,
	opensslrsa_isprivate,
	opensslrsa_destroy,
	opensslrsa_todns,
	opensslrsa_fromdns,
	opensslrsa_tofile,
	opensslrsa_parse,
	NULL, /*%< cleanup */
};

isc_result_t
dst__opensslrsa_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);
	if (*funcp == NULL)
		*funcp = &opensslrsa_functions;
	return (ISC_R_SUCCESS);
}

#else /* OPENSSL */

#include <isc/util.h>

EMPTY_TRANSLATION_UNIT

#endif /* OPENSSL */
/*! \file */




/******************************************************************
 *
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
 * Author: RHLamb 8/2007
 *   pkcs11 support 
 *
 * add LFLAGS -ldl for dynamic library loading
 ******************************************************************/
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <dlfcn.h>
#include <malloc.h>
#include "cryptoki.h"

#include <isc/lex.h>

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>

typedef unsigned char uint8;
#define min(x,y) ((x)<(y)?(x):(y))
#define MAX_SLOTS 16
#define MAX_KEYS 64

/* 
 * pkcs11 driver only supports one session at a time 
 * warning - forces pin saving in memory
 */
#define PKCS11_SINGLE_SESSION

typedef struct {
  long magic;
  CK_SESSION_HANDLE sh;
  CK_OBJECT_HANDLE pub;
  CK_OBJECT_HANDLE priv;
  char *library;
  char *pin;
  char *label;
  int reader;
  int slot;
  char *id; /* CKA_ID on token */
} pkcs11_cb;

static int pkcs11_login(pkcs11_cb *p11,char *keystr);
static int pkcs11_logout(pkcs11_cb *p11);
static char *cnvtid2str(uint8 *p,int len);
static char *cnvtlabel2str(uint8 *p,int len);
static char *utf82ascii(uint8 *p,int n);
static int pkcs11_label_exists(CK_SESSION_HANDLE sh,char *label);
static int pkcs11_delete_object(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hObj);
static int hex2i(char c);

static const char *pkcs11_library=NULL;
static CK_FUNCTION_LIST_PTR fnclist;
static char *pkcs11_pin;

static int pkcs11_parse(dst_key_t *key,isc_lex_t *lexer,uint8 *modulus,int *modulus_len,uint8 *pub_exponent,int *pub_exponent_len)
{
  int ret;
  pkcs11_cb *p11;

  ret = -1;
  if(key->opaque) return 0;

  if((p11=(pkcs11_cb *)malloc(sizeof(pkcs11_cb))) == NULL) return ret;
  memset(p11,0,sizeof(pkcs11_cb));
  p11->magic = PKCS11_MAGIC;

  /* ISC token handling */
  {
    isc_token_t token;
    unsigned int opt = ISC_LEXOPT_EOL;
    isc_result_t ret;
    char *p,*q;
#define DST_AS_STR(t) ((t).value.as_textregion.base)

    while(1) {
      ret = isc_lex_gettoken(lexer,opt,&token);
      if(ret == ISC_R_EOF) break;
      else if(ret != ISC_R_SUCCESS) return ret;
      if(token.type != isc_tokentype_string) continue;
      q = DST_AS_STR(token);
      
      if(*q == '#') continue;
      if((p=strchr(q,':')) == NULL) continue;
      *p++ = '\0';

      /*
       * if p11->library is NULL, then assume OpenSC libs.
       */
      if(p11->library == NULL && strcasecmp(q,"library") == 0) p11->library = strdup(p);
      if(strcasecmp(q,"reader") == 0) p11->reader = atoi(p);
      if(strcasecmp(q,"slot") == 0) p11->slot = atoi(p);
      /* 
       * if p11->pin is NULL, then assume no Login needed;
       * if p11->pin is a zero len string, ask for PIN at login.
       */ 
      if(p11->pin == NULL && strcasecmp(q,"pin") == 0) {
	if(strlen(p) > 0) p11->pin = strdup(p);
      }
      /*
       * note: id is in hex format for smart cards. arb bytes for HSM
       */
      if(p11->id == NULL && strcasecmp(q,"id") == 0) p11->id = strdup(p);
      /* UTF-8 should be ok */
      if(p11->label == NULL && strcasecmp(q,"label") == 0) p11->label = strdup(p);
    }
    if(p11->pin == NULL && pkcs11_pin && strlen(pkcs11_pin) > 0) {
      p11->pin = strdup(pkcs11_pin);
    }
  }

  {
    int i,j;
    CK_SESSION_HANDLE sh;
    int rv;
    CK_OBJECT_CLASS  privClass = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS  pubClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE     template[5];
    CK_OBJECT_HANDLE hPub,hKeys[MAX_KEYS];
    int ofound;
    int ts;
    uint8 id[128];
    char *p;
    CK_ATTRIBUTE getattributes[] = {
      {CKA_MODULUS_BITS, NULL_PTR, 0},
      {CKA_MODULUS, NULL_PTR, 0},
      {CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
      {CKA_ID, NULL_PTR, 0},
      {CKA_LABEL, NULL_PTR, 0}
    };

    if(pkcs11_login(p11,isc_lex_getsourcename(lexer))) goto endit;
    sh = p11->sh;

    ts = 0;
    template[ts].type = CKA_CLASS;
    template[ts].pValue = &pubClass;
    template[ts].ulValueLen = sizeof(pubClass);
    ts++;
    if(p11->label) {
      template[ts].type = CKA_LABEL;
      template[ts].pValue = p11->label;
      template[ts].ulValueLen = strlen(p11->label);
      ts++;
    }
    if(p11->id) {
      j = min(strlen(p11->id)/2,sizeof(id));
      for(p=p11->id,i=0;i<j;i++,p += 2) id[i] = hex2i(*p)<<4 | hex2i(*(p+1));
      template[ts].type = CKA_ID;
      template[ts].pValue = id;
      template[ts].ulValueLen = j;
      ts++;
    }
    rv = fnclist->C_FindObjectsInit(sh,template,ts);
    if(rv != CKR_OK) goto endit;
    rv = fnclist->C_FindObjects(sh,hKeys,MAX_KEYS,(CK_RV *)&ofound);
    if(rv != CKR_OK) goto endit;
    rv = fnclist->C_FindObjectsFinal(sh);
    if(rv != CKR_OK) goto endit;
    if(ofound <= 0) {
      fprintf(stderr,"pkcs11: error: No public keys labeled \"%s\" found\n",p11->label);
      goto endit;
    }
    /*printf("pkcs11: Found %d public keys\n",ofound);*/
    if(ofound > 1) {
      fprintf(stderr,"pkcs11: error: Found %d duplicate keys labeled \"%s\"\n",ofound,p11->label);
      goto endit;
    }
    p11->pub = hKeys[0];

    /* 
     * Get corresponding private key 
     * For this to work it must have the same LABEL and ID
     */
    template[0].type = CKA_CLASS;
    template[0].pValue = &privClass;
    template[0].ulValueLen = sizeof(privClass);
    rv = fnclist->C_FindObjectsInit(sh,template,ts);
    if(rv != CKR_OK) goto endit;
    rv = fnclist->C_FindObjects(sh,hKeys,MAX_KEYS,(CK_RV *)&ofound);
    if(rv != CKR_OK) goto endit;
    rv = fnclist->C_FindObjectsFinal(sh);
    if(rv != CKR_OK) goto endit;
    if(ofound <= 0) {
      fprintf(stderr,"pkcs11: error: No private keys labeled \"%s\" found\n",p11->label);
      goto endit;
    }
    /*printf("pkcs11: Found %d private keys\n",ofound);*/
    if(ofound > 1) {
      fprintf(stderr,"pkcs11: error: Found %d duplicate keys labeled \"%s\"\n",ofound,p11->label);
      goto endit;
    }

    p11->priv = hKeys[0];

    /* extract atributes for this key */
    hPub = p11->pub;
    ts = (int)(sizeof(getattributes)/sizeof(CK_ATTRIBUTE));
    if((rv=fnclist->C_GetAttributeValue(sh,hPub,getattributes,ts)) != CKR_OK) {
      fprintf(stderr,"pkcs11: C_GetAttributeValue: rv = 0x%.8X\n",rv);
      goto endit;
    }
    for(i=0;i<ts;i++) {
      getattributes[i].pValue = malloc(getattributes[i].ulValueLen *sizeof(CK_VOID_PTR));
      if(getattributes[i].pValue == NULL) {
	for(j=0;j<i;j++) free(getattributes[j].pValue);
	printf("pkcs11: Failed to alloc memory...NULL attributes\n");
	goto endit;
      }
    }
    /* Call again to get actual attributes */
    if((rv=fnclist->C_GetAttributeValue(sh,hPub,getattributes,ts)) != CKR_OK) {
      fprintf(stderr,"pkcs11: C_GetAttributeValue: rv = 0x%.8X\n",rv);
      goto endit;
    }
    *modulus_len =  getattributes[1].ulValueLen;
    memcpy(modulus,(uint8 *)getattributes[1].pValue,*modulus_len);
    *pub_exponent_len = getattributes[2].ulValueLen;
    memcpy(pub_exponent,(uint8 *)getattributes[2].pValue,*pub_exponent_len);
    
    for(i=0;i<ts;i++) free(getattributes[i].pValue);
    
    /* all went well */
    key->opaque = (void *)p11;
#ifdef PKCS11_SINGLE_SESSION
    pkcs11_logout(p11);
#endif
    return 0;

  endit:
    pkcs11_logout(p11);
    if(p11->library) free(p11->library);
    if(p11->pin) free(p11->pin);
    if(p11->label) free(p11->label);
    free(p11);
    key->opaque = NULL;
  }
  return ret;
}
static int ispkcs11(const dst_key_t *key)
{
  RSA *rsa = key->opaque;
  if(rsa->d && *(long *)rsa->d == PKCS11_MAGIC) return 1;
  return 0;
}
static void pkcs11_free(void *cb)
{
  pkcs11_cb *p11;
  p11 = (pkcs11_cb *)cb;
  pkcs11_logout(p11);
  free(p11);
}
static int pkcs11_login(pkcs11_cb *p11,char *keystr)
{
  int rv;
  CK_ULONG               ulNumberOfSlots=MAX_SLOTS;
  CK_SLOT_ID             SlotList[MAX_SLOTS];
  CK_SESSION_HANDLE      hSessionHandle;

  if(p11->sh) return 0; /* already logged in */

  if(pkcs11_initlib(NULL)) return -1;

  if((rv=fnclist->C_GetSlotList(TRUE,SlotList,&ulNumberOfSlots)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetSlotList returned 0x%08x\n",rv);
    return -1;
  }
  /*printf("pkcs11: Found %d slots\n",ulNumberOfSlots);*/
  if((rv=fnclist->C_OpenSession(SlotList[p11->slot],CKF_RW_SESSION | CKF_SERIAL_SESSION,NULL,NULL,&hSessionHandle)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_OpenSession returned 0x%08x\n",rv);
    return -1;
  } else {
    /*fprintf(stderr,"pkcs11: C_OpenSession successfull Slot = %d\n",k);*/
  }
  if(p11->pin) { /* login */
    if(strlen(p11->pin) == 0) {
      char buf[80];
      int i;

      while(1) {
	if(keystr) fprintf(stderr,"Please enter PIN for %s token: ",keystr); 
	else fprintf(stderr,"Please enter PIN: ");
	if(fgets(buf,sizeof(buf),stdin)) {
	  buf[sizeof(buf) - 1] = '\0';
	  i = strlen(buf) - 1;
	  buf[i] = '\0';
	} else {
	  printf("PIN input error\n");
	  fnclist->C_CloseSession(hSessionHandle);
	  return -1;
	}
	if((rv=fnclist->C_Login(hSessionHandle,CKU_USER,(unsigned char *)buf,i)) != CKR_OK) {
	  fprintf(stderr,"pkcs11: error: C_Login returned 0x%08X\n",rv);
	} else {
#ifdef PKCS11_SINGLE_SESSION /* security problem */
	  free(p11->pin);
	  p11->pin = strdup(buf); /* remember it */
#endif
	  break;
	}
      }
    } else {
      if((rv = fnclist->C_Login(hSessionHandle,CKU_USER,(unsigned char *)p11->pin,strlen(p11->pin))) != CKR_OK) {
	fprintf(stderr,"pkcs11: error: C_Login returned 0x%08X\n",rv);
	fnclist->C_CloseSession(hSessionHandle); 
	return -1;
      }
    }
  }
  p11->sh = hSessionHandle;

  /*printf("pkcs11: login slot=%d\n",p11->slot);*/

  return 0;
}
static int pkcs11_logout(pkcs11_cb *p11)
{
  int rv;
  CK_SESSION_HANDLE sh;

  if(p11->magic != PKCS11_MAGIC) {
    fprintf(stderr,"pkcs11: error: invalid control block\n");
    return -1;
  }
  sh = p11->sh;

  if(sh == 0) return 0; /* not open */

  if(p11->pin) {
    if((rv=fnclist->C_Logout(sh)) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_Logout returned 0x%08X\n",rv);
    }
  }
  if((rv=fnclist->C_CloseSession(sh)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: %s C_CloseSession returned 0x%08X\n",__func__,rv);
  }

  p11->sh = 0;
  /*printf("pkcs11: logout slot=%d\n",p11->slot);*/
  return 0;
}
static int pkcs11_RSA_sign(dst_key_t *key,unsigned char *message,unsigned int messagelen,unsigned char *sign,unsigned int *slen)
{
  int rv;
  CK_MECHANISM smech;
  CK_SESSION_HANDLE  sh;
  pkcs11_cb *p11;
  int ret;

  ret = -1;

  if(key->opaque == NULL) return ret;
  if(((RSA *)key->opaque)->d == NULL) return ret;
  p11 = (pkcs11_cb *)((RSA *)key->opaque)->d;

#ifdef PKCS11_SINGLE_SESSION
  if(pkcs11_login(p11,NULL)) return ret;
#endif

  sh = p11->sh;
  /*printf("pkcs11: signing using %s/%s\n",p11->label,p11->id);*/

  /*
   * Taken directly from OPENSSL source so that their RSA_verify will
   * accept our pkcs11 C_Sign output.
   */
  {
    X509_SIG xsig;
    ASN1_TYPE parameter;
    int i;
    uint8 *p,tmps[512]; /* good to 4096 bit RSA */
    /*const unsigned char *s = NULL;*/
    unsigned char *s;
    X509_ALGOR algor;
    ASN1_OCTET_STRING digest;

    s = NULL;
    xsig.algor = &algor;
    xsig.algor->algorithm = OBJ_nid2obj(NID_sha1);
    if(xsig.algor->algorithm == NULL) {
      fprintf(stderr,"pkcs11: error: RSA_F_RSA_SIGN,RSA_R_UNKNOWN_ALGORITHM_TYPE\n");
      goto err;
    }
    if(xsig.algor->algorithm->length == 0) {
      fprintf(stderr,"pkcs11: error: RSA_F_RSA_SIGN,RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD\n");
      goto err;
    }
    parameter.type = V_ASN1_NULL;
    parameter.value.ptr = NULL;
    xsig.algor->parameter= &parameter;
    xsig.digest = &digest;
    xsig.digest->data = (unsigned char *)message;
    xsig.digest->length = messagelen;
    i = i2d_X509_SIG(&xsig,NULL);
    if(i > (int)(sizeof(tmps) - RSA_PKCS1_PADDING_SIZE)) {
      fprintf(stderr,"pkcs11: error: RSA_F_RSA_SIGN,RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY\n");
      goto err;
    }
    p = tmps;
    i2d_X509_SIG(&xsig,&p);
    s = tmps;

    smech.mechanism = CKM_RSA_PKCS;
    smech.pParameter = NULL_PTR;
    smech.ulParameterLen = 0;
    if((rv=fnclist->C_SignInit(sh,&smech,p11->priv)) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_SignInit returned 0x%08X\n",rv);
      goto err;
    }
    if((rv=fnclist->C_Sign(sh,(CK_BYTE_PTR)s,(CK_ULONG)i,(CK_BYTE_PTR)sign,(CK_ULONG *)slen)) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_Sign returned 0x%08X\n",rv);
      goto err;
    }
    /*printf("Signed: %d byte signature for %d byte msg\n",*slen,i);*/
  }

  ret = 0;
 err:
#ifdef PKCS11_SINGLE_SESSION
  pkcs11_logout(p11);
#endif
  return ret;
}

int pkcs11_initlib(char *pin)
{
  void *pkcs11_hLib=NULL;
  CK_C_GetFunctionList   pGFL  = 0;
  int rv;

  /* remember command line specificed PIN number location */
  if(pkcs11_pin == NULL && pin) {
    pkcs11_pin = pin; 
  }

  if(fnclist) return 0;  /* already open and associated */

  if(pkcs11_library == NULL || strlen(pkcs11_library) <= 0) {
    /*
     * if defined, then use pkcs11
     *
     * possible locations:
     * "/home/dnssec/AEP/pkcs11.so.3.10",
     * "/usr/lib/opensc-pkcs11.so",
     * "/lib/opensc-pkcs11.so",
     * "/usr/local/lib/opensc-pkcs11.so",
     */
    if((pkcs11_library=getenv("PKCS11_LIBRARY_PATH")) == NULL
       || strlen(pkcs11_library) <= 0) {
      /*fprintf(stderr,"You must set PKCS11_LIBRARY_PATH, e.g.,\n \"export PKCS11_LIBRARY_PATH=/usr/lib/opensc-pkcs11.so\"\n");*/
      use_pkcs11 = 0;
      return -1;
    } else {
      use_pkcs11 = 1;
    }
  }
  pkcs11_hLib = dlopen(pkcs11_library,RTLD_LAZY);
  if(!pkcs11_hLib) {
    fprintf(stderr,"pkcs11: error: Failed to open PKCS11 library %s\n",pkcs11_library);
    return -1;
  }
  if((pGFL=(CK_C_GetFunctionList)dlsym(pkcs11_hLib,"C_GetFunctionList")) == NULL) {
    fprintf(stderr,"pkcs11: error: Cannot find GetFunctionList()\n");
    dlclose(pkcs11_hLib);
    return -1;
  }
  if((rv=pGFL(&fnclist)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetFunctionList returned 0x%08X\n",rv);
    dlclose(pkcs11_hLib);
    fnclist = NULL;
    return -1;
  }
  /*
   * Note: Since we dont know what a vendor is going to do, this might
   * clobber signal handling and other process oriented stuff. So execute
   * this at the begining of main() before we set our own handlers.
   */
  if((rv=fnclist->C_Initialize(NULL)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_Initialize returned 0x%08X\n",rv);
    dlclose(pkcs11_hLib);
    fnclist = NULL;
    return -1;
  }
  return 0;
}

static int pkcs11_genkey(dst_key_t *key,unsigned char *modulus,int *modulus_len,unsigned char *pubexponent,int *pubexponent_len)
{
  int              rv;
  CK_SESSION_HANDLE sh;
  CK_ULONG         nslots=MAX_SLOTS;
  CK_SLOT_ID       slotlist[MAX_SLOTS];
  CK_OBJECT_HANDLE hPub,hPriv;
  CK_OBJECT_CLASS  class_public_key = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS  class_private_key = CKO_PRIVATE_KEY;
  CK_KEY_TYPE      key_type = CKK_RSA;
  CK_BBOOL         bTrue = 1;
  CK_BBOOL         bFalse = 0;
  CK_UTF8CHAR      Plabel8[] = "Ktemp";
  CK_UTF8CHAR      Slabel8[] = "Ktemp";
  CK_UTF8CHAR      Pid8[] = "F";
  CK_UTF8CHAR      Sid8[] = "F";
  CK_ULONG         modulusBits;
  CK_BYTE          rsa_exponent[] = {0x01,0x00,0x01};
  CK_MECHANISM mechanism_gen = {CKM_RSA_PKCS_KEY_PAIR_GEN,NULL_PTR,0};
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_LABEL,Plabel8,sizeof(Plabel8)-1},
    {CKA_ID,Pid8,sizeof(Pid8)-1}, /* arb bytes string */
    {CKA_CLASS,&class_public_key,sizeof(class_public_key)},
    {CKA_KEY_TYPE,&key_type,sizeof(key_type)},
    {CKA_TOKEN,&bTrue,sizeof(CK_BBOOL)}, /* bTrue if put in HSM */
    {CKA_ENCRYPT,&bFalse,sizeof(bTrue)}, /* bTrue */
    {CKA_VERIFY,&bTrue,sizeof(bTrue)},
    {CKA_EXTRACTABLE,&bTrue,sizeof(bTrue)},
    {CKA_MODULUS_BITS,&modulusBits,sizeof(modulusBits)},
    {CKA_PUBLIC_EXPONENT,rsa_exponent,sizeof(rsa_exponent)},
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_LABEL,Slabel8,sizeof(Slabel8)-1},
    {CKA_ID,Sid8,sizeof(Sid8)-1}, /* arb bytes string */
    {CKA_CLASS,&class_private_key,sizeof(class_private_key)},
    {CKA_KEY_TYPE,&key_type,sizeof(key_type)},
    {CKA_TOKEN,&bTrue,sizeof(bTrue)}, /* bTrue if put in HSM */
    {CKA_PRIVATE,&bTrue,sizeof(bTrue)},
    {CKA_SENSITIVE,&bTrue,sizeof(bTrue)},
    {CKA_EXTRACTABLE,&bTrue,sizeof(bTrue)},
    {CKA_DECRYPT,&bFalse,sizeof(bTrue)}, /* bTrue */
    {CKA_SIGN,&bTrue,sizeof(bTrue)},
    {CKA_DERIVE,&bTrue,sizeof(bTrue)},
  };
  CK_ATTRIBUTE getattributes[] = {
    {CKA_MODULUS_BITS, NULL_PTR, 0},
    {CKA_MODULUS, NULL_PTR, 0},
    {CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
    {CKA_ID, NULL_PTR, 0},
    {CKA_LABEL, NULL_PTR, 0}
  };
  CK_ATTRIBUTE setattributes[1];
  int ret,i,k,slot,tsize;
  char *id,*label,buf[128];

  ret = -1;

  if(key->key_alg != DST_ALG_RSASHA1) {
    fprintf(stderr,"pkcs11: error: Unsupported algorithm\n");
    return -1;
  }

  if(pkcs11_initlib(NULL)) return -1;

  modulusBits = key->key_size;

  if((rv = fnclist->C_GetSlotList(TRUE,slotlist,&nslots))!=CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetSlotList returned 0x%08X\n",rv);
    return ret;
  }
  /*printf("pkcs11: Found %d slots\n",nslots);*/
  for(slot=0;slot<(int)nslots;slot++) {
    if((rv=fnclist->C_OpenSession(slotlist[slot],CKF_RW_SESSION | CKF_SERIAL_SESSION,NULL,NULL,&sh)) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: C_OpenSession returned 0x%08X\n",rv);
      continue;
    }

    /* public keys should not need a PIN so no login */
    if(pkcs11_pin && strlen(pkcs11_pin) > 0) {
      strcpy(buf,pkcs11_pin);
    } else {
      fprintf(stderr,"Enter PIN for slot %d if needed: ",slot);
      buf[0] = '\0';
      fgets(buf,sizeof(buf),stdin);
      buf[strlen(buf)-1] = '\0';
    }
    i = strlen(buf);
    if(i > 0) {
      if((rv = fnclist->C_Login(sh,CKU_USER,(uint8 *)buf,i)) != CKR_OK) {
	fprintf(stderr,"pkcs11: error: C_Login returned 0x%08X\n",rv);
	goto enditng;
      }
    }

    /*fprintf(stderr,"Trying to generate a %d bit key\n",(int)modulusBits);*/
    if((rv=fnclist->C_GenerateKeyPair(sh,
			      &mechanism_gen,
			      publicKeyTemplate, 
			      (sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE)),
			      privateKeyTemplate, 
			    (sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE)),
				      &hPub,&hPriv)) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: Slot %d C_GenerateKeyPair returned 0x%08X\n",slot,rv);
      fnclist->C_Logout(sh);
      if((rv=fnclist->C_CloseSession(sh)) != CKR_OK) {
	fprintf(stderr,"pkcs11: error: C_CloseSession returned 0x%08X\n",rv);
      }
      continue;
    }
    break;
  }

  if(slot >= (int)nslots) {
    fprintf(stderr,"pkcs11: error: Unable to generate a new key pair.\n");
    return ret; /* no need to close any sessions */
  }

 reeval:
  tsize = (int)(sizeof(getattributes)/sizeof(CK_ATTRIBUTE));
  if((rv=fnclist->C_GetAttributeValue(sh,hPub,getattributes,tsize)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetAttributeValue returned 0x%08X\n", rv);
    goto enditng;
  }
  /* Allocate memory to hold the data we want */
  for(i=0;i<tsize;i++) { /* +1 for ASCIIZ */
    k = (getattributes[i].ulValueLen + 1)*sizeof(CK_VOID_PTR);
    getattributes[i].pValue = malloc(k);
    memset(getattributes[i].pValue,0,k);
    if(getattributes[i].pValue == NULL) {
      for(k=0;k<i;k++) free(getattributes[k].pValue);
      fprintf(stderr,"pkcs11: Failed to alloc memory...NULL attributes\n");
      continue;
    }
  }
  /* Call again to get actual attributes */
  if((rv=fnclist->C_GetAttributeValue(sh,hPub,getattributes,tsize)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_GetAttributeValue returned 0x%08X\n", rv);
    goto enditng;
  }
  *modulus_len =  getattributes[1].ulValueLen;
  memcpy(modulus,(uint8 *)getattributes[1].pValue,*modulus_len);
  *pubexponent_len = getattributes[2].ulValueLen;
  memcpy(pubexponent,(uint8 *)getattributes[2].pValue,*pubexponent_len);
  id = cnvtid2str(getattributes[3].pValue,getattributes[3].ulValueLen);

  for(i=0;i<tsize;i++) {
    free(getattributes[i].pValue);
    getattributes[i].pValue = NULL_PTR;
    getattributes[i].ulValueLen = 0;
  }

  /* set label/id info for pub and priv key to tagid */
  {
    char tagstr[128];
    isc_buffer_t dnsbuf;
    unsigned char dns_array[DST_KEY_MAXSIZE];
    isc_region_t r;
    char namestr[512];
    RSA *rsa;

    if((rsa=RSA_new()) == NULL) {
      fprintf(stderr,"pkcs11: error: Cannot compute tag id\n");
      goto enditng;
    }
    SET_FLAGS(rsa);
    key->opaque = rsa; /* warning: just for this operation */
    rsa->n = BN_bin2bn(modulus,*modulus_len,NULL);
    rsa->e = BN_bin2bn(pubexponent,*pubexponent_len,NULL);
    isc_buffer_init(&dnsbuf,dns_array,sizeof(dns_array));
    if(dst_key_todns(key,&dnsbuf) != ISC_R_SUCCESS) {
      fprintf(stderr,"pkcs11: error: Cannot compute tag id\n");
      RSA_free(rsa);
      goto enditng;
    }
    isc_buffer_usedregion(&dnsbuf,&r);
    key->key_id = dst_region_computeid(&r,key->key_alg);
    RSA_free(rsa);
    key->opaque = NULL;
    dns_name_format(key->key_name,namestr,sizeof(namestr));

    /*
     * Some HSM's have limited space for labels or can only display
     * a few characters on thier LCD displays.  So for DNSSEC keys
     * we use the 5 digit key tag as the key label.
     * This has a side effect of ensuring that there are no two keys
     * in the HSM with the same computed tag, regardless of domain
     * name or algorithm number.
     */
    sprintf(tagstr,"K%05d",key->key_id);
    if(pkcs11_label_exists(sh,tagstr)) {
      pkcs11_delete_object(sh,hPub);
      pkcs11_delete_object(sh,hPriv);
      fprintf(stderr,"pkcs11: %s exists. Trying to create another %d bit key..\n",tagstr,(int)modulusBits);
      if((rv=fnclist->C_GenerateKeyPair(sh,
		     &mechanism_gen,
		     publicKeyTemplate,
		     (sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE)),
		     privateKeyTemplate,
		     (sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE)),
					&hPub,&hPriv)) != CKR_OK) {
	fprintf(stderr,"pkcs11: error: Slot %d C_GenerateKeyPair returned 0x%08X\n",slot,rv);
	goto enditng;
      }
      goto reeval;
    }
    setattributes[0].type = CKA_LABEL;
    setattributes[0].pValue = tagstr;
    setattributes[0].ulValueLen = strlen(tagstr);
    if((rv=fnclist->C_SetAttributeValue(sh,hPub,setattributes,1)) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: Pub C_SetAttributeValue returned 0x%08X\n",rv);
      goto enditng;
    }
    if((rv=fnclist->C_SetAttributeValue(sh,hPriv,setattributes,1)) != CKR_OK) {
      fprintf(stderr,"pkcs11: error: Priv C_SetAttributeValue returned 0x%08X\n",rv);
      goto enditng;
    }
    /*fprintf(stderr,"Internal Key Label: \"%s\"\n",tagstr);*/
    label = strdup(tagstr);
  }

  /* all went well - store in opaque structure */
  {
    pkcs11_cb *p11;
    if((p11=(pkcs11_cb *)malloc(sizeof(pkcs11_cb))) == NULL) goto enditng;
    memset(p11,0,sizeof(pkcs11_cb));
    p11->magic = PKCS11_MAGIC;
    p11->slot = slot;
    p11->id = id;
    p11->label = label;
    key->opaque = (void *)p11;
  }

  ret = 0;

 enditng:
  fnclist->C_Logout(sh);
  if((rv=fnclist->C_CloseSession(sh)) != CKR_OK) {
    fprintf(stderr,"pkcs11: error: C_CloseSession returned 0x%08X\n",rv);
  }
  return ret;
}


typedef struct {
  int modulus_bits;
  int modulus_len;
  void *modulus;
  int pubexponent_len;
  void *pubexponent;
  int slot;
  char *label;
  char *id;
} pkcs11_key_info;
#define MAX_PKCS11_TOKEN_ENTRIES 200

static int pkcs11_getkey(dst_key_t *key,unsigned char *modulus,int *modulus_len,unsigned char *pubexponent,int *pubexponent_len)
{
  int i,j,k;
  CK_SESSION_HANDLE sh;
  int rv;
  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE template[1];
  CK_OBJECT_HANDLE hKeys[MAX_KEYS];
  int ofound;
  int tsize;
  CK_ATTRIBUTE getattributes[] = {
    {CKA_MODULUS_BITS, NULL_PTR, 0},
    {CKA_MODULUS, NULL_PTR, 0},
    {CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
    {CKA_ID, NULL_PTR, 0},
    {CKA_LABEL, NULL_PTR, 0}
  };
  CK_ULONG               nslots=MAX_SLOTS;
  CK_SLOT_ID             slotlist[MAX_SLOTS];
  int slot,entry;
  char *label,*id;
  char buf[128];
  char pin[128];
  int pinlen,firstpin;
  pkcs11_key_info *info;

  if(pkcs11_initlib(NULL)) return -1;

  k = MAX_PKCS11_TOKEN_ENTRIES*sizeof(pkcs11_key_info);
  if((info=(pkcs11_key_info *)malloc(k)) == NULL) goto enditng;
  memset(info,0,k);

  firstpin = 1;
  pinlen = 0;
  entry = 0;
 retry:
  if((rv = fnclist->C_GetSlotList(TRUE,slotlist,&nslots))!=CKR_OK) {
    fprintf(stderr,"pkcs11: C_GetSlotList failed...error no = 0x%x\n", rv);
    goto enditok;
  }
  /*printf("pkcs11: Found %d slots\n",nslots);*/
  for(i=0;i<entry;i++) { /* if retry, clear old ones */
    if(info[i].modulus) free(info[i].modulus);
    if(info[i].pubexponent) free(info[i].pubexponent);
    if(info[i].label) free(info[i].label);
    if(info[i].id) free(info[i].id);
  }
  entry = 0;

  for(slot=0;slot<(int)nslots;slot++) {
    /* try to find a name for the token/HSM */
    {
      CK_SLOT_INFO slotInfo;
      CK_TOKEN_INFO tokenInfo;
      char *description,*serialno,*label,*manuf;

      if(fnclist->C_GetSlotInfo(slotlist[slot],&slotInfo) == CKR_OK
	 && fnclist->C_GetTokenInfo(slotlist[slot],&tokenInfo) == CKR_OK) {

	description = utf82ascii(slotInfo.slotDescription,sizeof(slotInfo.slotDescription));
	serialno = utf82ascii(tokenInfo.serialNumber,sizeof(tokenInfo.serialNumber));
	label = utf82ascii(tokenInfo.label,sizeof(tokenInfo.label));
	manuf = utf82ascii(tokenInfo.manufacturerID,sizeof(tokenInfo.manufacturerID));
	fprintf(stderr,"slot %d:%s label:%s mfr:%s S/N:%s\n",
		slot,
		description,
		label,
		manuf,
		/*tokenInfo.model,*/
		serialno);
	free(description);
	free(serialno);
	free(label);
	free(manuf);
      }
    }

    if((rv=fnclist->C_OpenSession(slotlist[slot],CKF_RW_SESSION | CKF_SERIAL_SESSION,NULL,NULL,&sh)) != CKR_OK) {
      fprintf(stderr,"pkcs11: C_OpenSession failed...error no = 0x%02x\n",rv);
      continue;
    }

    /* public keys should not need a PIN so no login */
    if(firstpin) {
      if(pkcs11_pin && strlen(pkcs11_pin) > 0) {
	strcpy(buf,pkcs11_pin);
      } else {
	fprintf(stderr,"Enter PIN for slot %d if needed: ",slot);
	buf[0] = '\0';
	fgets(buf,sizeof(buf),stdin);
	buf[strlen(buf)-1] = '\0';
      }
      i = strlen(buf);
      if(i > 0) {
	pinlen = i;
	strcpy(pin,buf);
	if((rv=fnclist->C_Login(sh,CKU_USER,(uint8 *)pin,pinlen)) != CKR_OK) {
	  fprintf(stderr,"pkcs11: C_Login failed...error no = 0x%02x\n",rv);
	  goto endit;
	}
      }
      firstpin = 0;
    } else if(pinlen) {
      if((rv=fnclist->C_Login(sh,CKU_USER,(uint8 *)pin,pinlen)) != CKR_OK) {
	fprintf(stderr,"pkcs11: C_Login failed...error no = 0x%02x\n",rv);
	goto endit;
      }
    }

    template[0].type = CKA_CLASS;
    template[0].pValue = &pubClass;
    template[0].ulValueLen = sizeof(pubClass);
    rv = fnclist->C_FindObjectsInit(sh,template,1);
    if(rv != CKR_OK) goto endit;
    rv = fnclist->C_FindObjects(sh,hKeys,MAX_KEYS,(CK_RV *)&ofound);
    if(rv != CKR_OK) goto endit;
    rv = fnclist->C_FindObjectsFinal(sh);
    if(rv != CKR_OK) goto endit;
    if(ofound <= 0) {
      fprintf(stderr,"pkcs11: No public keys found in slot %d\n",slot);/**/
      goto endit;
    }
    /*printf("pkcs11: Found %d public keys in slot %d\n",ofound,slot);*/
    tsize = (int)(sizeof(getattributes)/sizeof(CK_ATTRIBUTE));
    for(i=0;i<ofound;i++) {
      for(j=0;j<tsize;j++) {
	getattributes[j].pValue = NULL_PTR;
	getattributes[j].ulValueLen = 0;
      }
      rv = fnclist->C_GetAttributeValue(sh,hKeys[i],getattributes,tsize);
      if(rv != CKR_OK) {
	fprintf(stderr,"pkcs11: C_GetAttributeValue: rv = 0x%.8X\n", rv);
	continue;
      }
      /* Allocate memory to hold the data we want */
      for(j=0;j<tsize;j++) { /* +1 for ASCIIZ */
	k = (getattributes[j].ulValueLen + 1)*sizeof(CK_VOID_PTR);
	getattributes[j].pValue = malloc(k);
	memset(getattributes[j].pValue,0,k);
	if(getattributes[j].pValue == NULL) {
	  for(k=0;k<j;k++) free(getattributes[k].pValue);
	  fprintf(stderr,"pkcs11: Failed to alloc memory...NULL attributes\n");
	  continue;
	}
      }
      /* Call again to get actual attributes */
      if((rv=fnclist->C_GetAttributeValue(sh,hKeys[i],getattributes,tsize)) != CKR_OK) {
	fprintf(stderr,"pkcs11: C_GetAttributeValue: rv = 0x%.8X\n",rv);
	continue;
      }

      /* BITS */
      k = *((CK_ULONG_PTR)(getattributes[0].pValue));
      free(getattributes[0].pValue);
      getattributes[0].pValue = NULL_PTR;
      getattributes[0].ulValueLen = 0;
      info[entry].modulus_bits = k;

      info[entry].modulus_len =  getattributes[1].ulValueLen;
      info[entry].modulus = (uint8 *)getattributes[1].pValue;

      info[entry].pubexponent_len = getattributes[2].ulValueLen;
      info[entry].pubexponent = (uint8 *)getattributes[2].pValue;

      info[entry].id = cnvtid2str(getattributes[3].pValue,getattributes[3].ulValueLen);
      free(getattributes[3].pValue);

      info[entry].slot = slot;

      info[entry].label = cnvtlabel2str(getattributes[4].pValue,getattributes[4].ulValueLen);
      free(getattributes[4].pValue);

      fprintf(stderr,"\t%d) \"%s\" SLOT:%d ID:%s BITS:%d\n",entry+1,info[entry].label,slot,info[entry].id,k);

      entry++;
      if(entry >= MAX_PKCS11_TOKEN_ENTRIES) break;
    }
  endit:
    if(pinlen) fnclist->C_Logout(sh);
    if((rv=fnclist->C_CloseSession(sh)) != CKR_OK) {
      fprintf(stderr,"pkcs11: %s C_CloseSession failed error = 0x%04x\n",__func__,rv);
    }
  }

  if(entry == 0) {
    fprintf(stderr,"No keys found. Make sure crypto device is enabled.\n");
    goto enditng;
  }

  fprintf(stderr,"Select one: ");
  if(fgets(buf,sizeof(buf),stdin)) {
    buf[strlen(buf)-1] = '\0';
    i = atoi(buf);
    if(i <= 0 || i > entry) goto retry;
    fprintf(stderr,"You chose key %d\n",i);
    i--;
    *modulus_len =  info[i].modulus_len;
    memcpy(modulus,info[i].modulus,*modulus_len);
    *pubexponent_len = info[i].pubexponent_len;
    memcpy(pubexponent,info[i].pubexponent,*pubexponent_len);
    /*pkcs11_display_pubval(modulus,*modulus_len,pubexponent,*pubexponent_len);*/
    slot = info[i].slot;
    id = strdup(info[i].id);
    label = strdup(info[i].label);

    /*pkcs11_test_keypair_name(slot,label,id);*/

    for(i=0;i<entry;i++) {
      if(info[i].modulus) free(info[i].modulus);
      if(info[i].pubexponent) free(info[i].pubexponent);
      if(info[i].label) free(info[i].label);
      if(info[i].id) free(info[i].id);
    }
    /* no need to zero array since we drop through */
  } else {
    goto retry;
  }

  /* all went well */
  {
    pkcs11_cb *p11;
    if((p11=(pkcs11_cb *)malloc(sizeof(pkcs11_cb))) == NULL) goto enditng;
    memset(p11,0,sizeof(pkcs11_cb));
    p11->magic = PKCS11_MAGIC;
    p11->slot = slot;
    p11->id = id;
    p11->label = label;
    key->opaque = (void *)p11;
  }

 enditok:
  if(info) free(info);
  return 0;
 enditng:
  if(info) free(info);
  return -1;
}
static int pkcs11_writeparams(const dst_key_t *key,char *fname)
{
  FILE *fp;
  pkcs11_cb *p11;

  if(key->opaque == NULL) return -1;
  if(((RSA *)key->opaque)->d == NULL) return -1;
  p11 = (pkcs11_cb *)((RSA *)key->opaque)->d;
  if((fp=fopen(fname,"w")) == NULL) return -1;
  /* 
   * Note: empty "pin:" line forces a PIN to be requested
   * from the operator.  Manually remove line from file
   * if key requires no PIN.
   * Alternatively, manually add pin to line, e.g., "pin:123456",
   * if your security practices find this reasonable.
   */
  fprintf(fp,"Private-key-format: xxx\nslot:%d\npin:\n",p11->slot);
  if(p11->label) fprintf(fp,"id:%s\n",p11->id);
  if(p11->label) fprintf(fp,"label:%s\n",p11->label);
  fclose(fp);
  /*printf("pkcs11: Wrote token parameters to %s\n",fname);*/
  return 0;
}
static int pkcs11_label_exists(CK_SESSION_HANDLE sh,char *label)
{
  int ofound,rv;
  CK_ATTRIBUTE template[2];
  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  CK_OBJECT_HANDLE hKeys[MAX_KEYS];

  if(label == NULL || strlen(label) <= 0) return 0;

  template[0].type = CKA_CLASS;
  template[0].pValue = &pubClass;
  template[0].ulValueLen = sizeof(pubClass);
  template[1].type = CKA_LABEL;
  template[1].pValue = label;
  template[1].ulValueLen = strlen(label);

  rv = fnclist->C_FindObjectsInit(sh,template,2);
  if(rv != CKR_OK) return 0;
  rv = fnclist->C_FindObjects(sh,hKeys,MAX_KEYS,(CK_RV *)&ofound);
  if(rv != CKR_OK) return 0;
  rv = fnclist->C_FindObjectsFinal(sh);
  if(rv != CKR_OK) return 0;
  if(ofound <= 0) return 0;
  return 1;
}
static int pkcs11_delete_object(CK_SESSION_HANDLE sh,CK_OBJECT_HANDLE hObj)
{
  int rv;
  if((rv=fnclist->C_DestroyObject(sh,hObj)) != CKR_OK) {
    fprintf(stderr,"pkcs11: C_DestroyObject failed err=%08X\n",rv);
    return -1;
  }
  /*printf("pkcs11: Deleted object %08x\n",hObj);*/
  return 0;
}
static char *cnvtid2str(uint8 *p,int len)
{
  char *q;
  int i;
  q = (char *)malloc((2*len) + 1);
  q[0] = '\0';
  for(i=0;i<len;i++) {
    sprintf(&q[strlen(q)],"%02x",p[i]);
  }
  return q;
}
static char *cnvtlabel2str(uint8 *p,int len)
{
  char *q;
  q = (char *)malloc(len + 1);
  memcpy(q,p,len);
  q[len] = '\0';
  return q;
}
static char *utf82ascii(uint8 *p,int n)
{
  char *q,*r,*r0;
  int i,un;

  un = 0;
  r0 = r = (char *)malloc(n + 1);
  for(q=(char *)p,i=0;i<n;q++,i++) {
    if( ((*q)&0x80) == 0x80 ) {
      if(un == 0) {
	*r++ = '-';
	un = 1;
      } else {
      }
    } else {
      *r++ = *q;
      un = 0;
    }
  }
  *r = '\0';

  for(q=r0+strlen(r0)-1;q != r0;q--) {
    if(*q != ' ' && *q != '\t') break;
  }
  *(q+1) = '\0';
  return r0;
}
static int hex2i(char c)
{
  if(c >= '0' && c <= '9') return (int)(c - '0');
  if(c >= 'A' && c <= 'F') return (int)((c - 'A') + 10);
  return -1;
}
