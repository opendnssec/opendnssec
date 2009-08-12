/* $Id$ */

/*
 * Copyright (c) 2009 OpenFortress
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

/* hsmbully.c -- Test an HSM for OpenDNSSEC compliance.
 *
 * Test a linked PKCS #11 API (presumably for an HSM) against the tests that
 * have been laid down for OpenDNSSEC.  Make sure to supply an include
 * directory to the compiler from which <pkcs11.h> can be #included.
 *
 * Author: Rick van Rein <rick@openfortress.nl>
 */


#ifndef TOKENLABEL_32CHARS
#  define TOKENLABEL_32CHARS "OpenDNSSEC Token Stress Test    "
#endif


#ifdef QUICK_N_DIRTY
#  define THOUSANDS 10
#  define HUNDRED   8
#  define COUPLE    3
#else
#  define THOUSANDS 2500
#  define HUNDRED   100
#  define COUPLE    10
#endif


/* =============================================================== */


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <dlfcn.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/types.h>

#include <CUnit/Automated.h>


/* =============================================================== */


/* Include PKCS #11 headers -- which is dependent on the OS */

#ifndef WIN32

/* Unix defines for PKCS #11 follow */

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#else

/* WIN32 defines for PKCS #11 follow */

#pragma pack(push, cryptoki, 1)
#define CK_IMPORT_SPEC __declspec(dllimport)
#define CK_EXPORT_SPEC CK_IMPORT_SPEC
#define CK_CALL_SPEC __cdecl
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType CK_EXPORT_SPEC CK_CALL_S
PEC name
#define CK_DECLARE_FUNCTION(returnType, name) returnType CK_EXPORT_SPEC CK_CALL_
SPEC name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType CK_IMPORT_SPEC 
(CK_CALL_SPEC CK_PTR name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (CK_CALL_SPEC CK_PTR n
ame)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#endif

#include <pkcs11.h>


/* =============================================================== */


/* Test functions, reporting back through CUnit */


static int ck_rv = CKR_OK;
static CK_SLOT_ID slotid;

typedef CK_RV p11fn ();
#define P11(fn) ((p11fn *) (dlsym (p11, (fn))))

#define WARN(s) fprintf (stderr, "%s\n", s)
#define GETRV(x) { ck_rv = (x); }
#define TESTRV(s,x) { ck_rv = (x); if (ck_rv!=CKR_OK) { fprintf (stderr, "%s: Error %08x in retval\n", s, ck_rv); } }
// #define TESTRV(s,x) { static char cumsgbuf [1025]; if (ck_rv==CKR_OK) { ck_rv = (x); fprintf (stderr, "Return value %08lx at %s:%d\n", ck_rv, __FILE__, __LINE__); } if (ck_rv==CKR_OK) { printf ("Pass: %s\n", (s)); } else { snprintf (cumsgbuf, sizeof (cumsgbuf)-1, "Return value %08lx is not CKR_OK: %s", ck_rv, (s)); cumsgbuf [sizeof (cumsgbuf)-1] = '\0'; fprintf (stderr, "Fail: %s\n", cumsgbuf); } }
#define MKFATAL() { if (ck_rv != CKR_OK) exit (1); }
#define LASTRVOK() (ck_rv==CKR_OK)


/* =============================================================== */


static void *p11 = NULL;

static CK_MECHANISM_INFO mech_rsa_pkcs_key_pair_gen;
static CK_MECHANISM_INFO mech_sha1_rsa_pkcs;
// static CK_MECHANISM_INFO mech_sha256_rsa_pkcs;	/* for future use */
// static CK_MECHANISM_INFO mech_sha512_rsa_pkcs;	/* for future use */
static CK_MECHANISM_INFO mech_sha_1;
// static CK_MECHANISM_INFO mech_sha256;		/* for future use? */
// static CK_MECHANISM_INFO mech_sha512;		/* for future use? */

/* PIN codes for this test are ASCII, and null-terminated strings */
static char ascii_pin_user [128] = "";
static char ascii_pin_so [128] = "";


/* =============================================================== */


/* Return a pseudo-random number from a _fixed_ range, causing the
 * test results to be evenly scattered, yet reproducable.  The returned
 * values are uniformly distributed within 0 <= randomish(range) < range.
 *
 * Algorithm source: ZX Spectrum, ROM addresses 0x25F8..0x2624
 */
int randomish (int range) {
	static uint32_t seed = 0x1234;
	if (range > 65537) {
		CU_FAIL ("Cannot provide randomish ranges beyond 65536 -- use another PRN");
		exit (1);
	}
	seed = ((seed + 1) * 75) % 65537 - 1;
	return floor (range * ((float) seed - 1.0) / 65536.0);
}

/* A variation on the above, yielding uniformly spread numbers within
 * the range defined by min <= randomish_minmax(min,max) <= max.
 */
int randomish_minmax (int min, int max) {
	return min + randomish (1+max-min);
}


/* =============================================================== */


/* Create a key pair with the given number of modulus bits (which is
 * a multiple of 8) and return CK_RV.  If CK_RV == CKR_OK, the private
 * and public key handles will be filled with proper values.
 */

CK_RV newkeypair (CK_SESSION_HANDLE seshdl,
		  CK_ULONG keybits,
		  CK_OBJECT_HANDLE_PTR pub,
		  CK_OBJECT_HANDLE_PTR priv) {
	CK_BYTE pubexp [] = { 0x01, 0x00, 0x01 }; // anyEndian anagram!
	CK_BBOOL true = TRUE;
	CK_BBOOL false = FALSE;
	CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ATTRIBUTE pubtmpl [] = {
		{ CKA_PRIVATE, &false, sizeof (false) },
		{ CKA_MODULUS_BITS, &keybits, sizeof (keybits) },
		{ CKA_PUBLIC_EXPONENT, &pubexp, sizeof (pubexp) },
		{ CKA_TOKEN, &true, sizeof (true) },
		{ CKA_LOCAL, &true, sizeof (true) },
		{ CKA_MODIFIABLE, &false, sizeof (false) },
		{ CKA_VERIFY, &true, sizeof (true) },
		{ CKA_VERIFY_RECOVER, &false, sizeof (false) },
		{ CKA_WRAP, &false, sizeof (false) },
		{ CKA_DERIVE, &false, sizeof (false) },
		{ CKA_ENCRYPT, &false, sizeof (false) },
	};
	CK_ATTRIBUTE privtmpl [] = {
		{ CKA_PRIVATE, &true, sizeof (true) },
		{ CKA_TOKEN, &true, sizeof (true) },
		{ CKA_MODIFIABLE, &false, sizeof (false) },
		{ CKA_LOCAL, &true, sizeof (true) },
		{ CKA_SENSITIVE, &true, sizeof (true) },
		{ CKA_ALWAYS_SENSITIVE, &true, sizeof (true) },
		{ CKA_EXTRACTABLE, &false, sizeof (false) },
		{ CKA_NEVER_EXTRACTABLE, &true, sizeof (true) },
		{ CKA_SIGN, &true, sizeof (true) },
		{ CKA_SIGN_RECOVER, &false, sizeof (false) },
		{ CKA_DECRYPT, &false, sizeof (false) },
		{ CKA_UNWRAP, &false, sizeof (false) },
		{ CKA_DERIVE, &false, sizeof (false) },
	};
	return P11("C_GenerateKeyPair") (
			seshdl,
			&mech,
			pubtmpl, sizeof (pubtmpl) / sizeof (*pubtmpl),
			privtmpl, sizeof (privtmpl) / sizeof (*privtmpl),
			pub, priv);
}


/* =============================================================== */


/* Test a slot: Given a global slot ID, test the slot given.
 * This particular routine tests if all initiatiation runs well.
 */
void testslot_initiation (void) {
	CK_SESSION_HANDLE seshdl;
	CK_BYTE noappinfo;
	int initestctr;

	/* Complain if user PIN and SO PIN are the same -- this will bring
	 * out more subtlety in the tests to follow.
	 */
	if (strlen (ascii_pin_user) == strlen (ascii_pin_so)) {
		if (!memcmp (ascii_pin_user, ascii_pin_so, strlen (ascii_pin_user))) {
			CU_FAIL ("SO PIN and USER PIN should differ to get the best results from the initiation test");
		}
	}

	/*
	 *  Open RW session with slot
	 */
	TESTRV ("Opening session for initiation test",
		P11("C_OpenSession") (slotid, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				(void *) &noappinfo, NULL_PTR, &seshdl));
	MKFATAL ();

	/*
	 * Possibly setup the user PIN to use.
	 */
#	ifndef NON_DESTRUCTIVE_TESTING
		TESTRV ("Logging into token for setting up PIN",
			P11("C_Login") (seshdl, CKU_SO, (CK_UTF8CHAR_PTR) ascii_pin_so, strlen (ascii_pin_so)));
		TESTRV ("Setting up user PIN",
			P11("C_InitPIN") (seshdl, (CK_UTF8CHAR_PTR) ascii_pin_user, strlen (ascii_pin_user)));
		TESTRV ("Logging out after setting setting up PIN",
			P11("C_Logout") (seshdl));
#	endif

	/*
	 * Close the RW session with the slot
	 */
	TESTRV ("Closing RW SO session for setup of initiation test",
		P11("C_CloseSession") (seshdl));

	/*
	 * Iterate over the actual test, running (distorted) scripts.
	 */
	for (initestctr=0; initestctr < THOUSANDS; initestctr++) {
		/*
  		 * Choices to be made at randomish:
  		 * choice_session==0           =>  fail to open session
  		 * choice_login==0             =>  fail to login
  		 * choice_rw/choice_so         =>  failing combination 0/0
  		 */
		int choice_session = randomish (10);
		int choice_login   = randomish (10);
		int choice_rw      = randomish (2);
		int choice_user    = randomish (2);

		/*
		 *  Open session with slot (with 10% chance of failure).
		 */
		if (choice_session) {
			TESTRV ("Opening session for fragmentation test",
				P11("C_OpenSession") (slotid,
						CKF_SERIAL_SESSION |
					(choice_rw? CKF_RW_SESSION: 0),
						(void *) &noappinfo, NULL_PTR, &seshdl));
			MKFATAL ();
		}

		/*
		 * Login as the token user or SO (with 10% chance of failure).
		 */
		if (choice_login) {
			GETRV (P11("C_Login") (seshdl,
					choice_user? CKU_USER: CKU_SO,
					(CK_UTF8CHAR_PTR) (choice_user? ascii_pin_user: ascii_pin_so),
					choice_user? strlen (ascii_pin_user): strlen (ascii_pin_so)));
			if (choice_session) {
				MKFATAL ();
			} else {
				if (LASTRVOK ()) {
					CU_FAIL ("Incorrectly allowed login on a non-existing session");
				} else {
					CU_PASS ("Properly refused to login on a closed session");
				}
			}
			if ((!choice_rw) && (!choice_user)) {
				if (LASTRVOK ()) {
					CU_FAIL ("Incorrectly allowed to login to RW SO session");
				} else {
					CU_PASS ("Properly refused to login to RW SO session");
				}
			}
		}

		/*
		 * Perform operations that will succeed or fail, depending
		 * on the RW/RO session and SO/USER login.  Test if the
		 * response is what it should be.  Also take choice_session
		 * and choice_login into account.
		 *
		 * The actual operations below are a few that should be
		 * protected, so they are a test that those protective
		 * barriers are in place.  This is not an exhaustive test,
		 * and indeed, not all combinations can actually be tested.
		 * This is just a small set of tests that could be
		 * extended at will.
		 */

		/*
		 * Operation 1.  Initialise the user PIN.
		 * This is only possible during an SO RW session.
		 */
		GETRV (P11("C_InitPIN") (seshdl, (CK_UTF8CHAR_PTR) ascii_pin_user, strlen (ascii_pin_user)));
		if (choice_session && choice_login && choice_rw && !choice_user) {
			if (LASTRVOK ()) {
				CU_PASS ("Properly accepted operation #1 during initiation test");
			} else {
				CU_FAIL ("Incorrectly rejected operation #1 during initiation test");
			}
		} else {
			if (LASTRVOK ()) {
				CU_FAIL ("Incorrectly accepted operation #1 during initiation test");
			} else {
				CU_PASS ("Properly rejected operation #1 during initiation test");
			}
		}

		/*
		 * Operation 2.  Set another user PIN.
		 * This is only possible during an RW session.
		 * Login need not have succeeded for this to work.
		 */
		GETRV (P11("C_SetPIN") (seshdl,
			(CK_UTF8CHAR_PTR) (choice_login && !choice_user)? ascii_pin_so: ascii_pin_user,
			(CK_ULONG) (choice_login && !choice_user)? strlen (ascii_pin_so): strlen (ascii_pin_user),
			(CK_UTF8CHAR_PTR) (choice_login && !choice_user)? ascii_pin_so: ascii_pin_user,
			(CK_ULONG) (choice_login && !choice_user)? strlen (ascii_pin_so): strlen (ascii_pin_user)));
		if (choice_session && choice_login && choice_rw) {
			if (LASTRVOK ()) {
				CU_PASS ("Properly accepted operation #2 during initiation test");
			} else {
				CU_FAIL ("Incorrectly rejected operation #2 during initiation test");
			}
		} else {
			if (LASTRVOK ()) {
				CU_FAIL ("Incorrectly accepted operation #2 during initiation test");
			} else {
				CU_PASS ("Properly rejected operation #2 during initiation test");
			}
		}

		/*
		 * Logout from the current session.  Note errors and check
		 * if they are rightfully reported.
		 */
		GETRV (P11("C_Logout") (seshdl));
		if (LASTRVOK ()) {
			if (choice_session && choice_login) {
				CU_PASS ("Properly accepted logout in initiation test");
			} else {
				CU_FAIL ("Incorrectly rejected operation #2 during initiation test");
			}
		} else {
			if (LASTRVOK ()) {
				CU_FAIL ("Incorrectly accepted operation #2 during initiation test");
			} else {
				CU_PASS ("Properly rejected operation #2 during initiation test");
			}
		}

		/*
		 * Logout from the current session.  Note errors and check
		 * if they are rightfully reported.
		 */
		GETRV (P11("C_Logout") (seshdl));
		if (! LASTRVOK ()) {
			if (choice_session && choice_login) {
				CU_FAIL ("Incorrectly failed logout in initiation test");
			}
		}

		/*
		 * Close the current session.  Note errors and check if they
		 * are rightfully reported.
		 */
		GETRV (P11("C_CloseSession") (seshdl));
		if (LASTRVOK ()) {
			if (choice_session) {
				CU_PASS ("Properly accepted session close in initiation test");
			} else {
				CU_FAIL ("Incorrectly accepted session close in initiation test");
			}
		} else {
			if (choice_session) {
				CU_FAIL ("Incorrectly failed session close in initiation test");
			} else {
				CU_PASS ("Properly failed session close in initiation test");
			}
		}
		
		/*
		 * End of loop for a single initiation test.
		 */
	}

	/*
	 * End of initiation test, comprising of thousands of tests.
	 */
}


/* =============================================================== */


/* Test a slot: Given a global slot ID, test the slot given.
 * This particular routine tests for fragmentation of the token memory.
 */
void testslot_fragmentation (void) {
	CK_SESSION_HANDLE seshdl;
	CK_BYTE noappinfo;

	struct key {
		CK_OBJECT_HANDLE pub;
		CK_OBJECT_HANDLE priv;
		CK_ULONG modbits;
	} *keys = NULL;
	int keypairs = 0, kp;

	int minbytes, maxbytes;

	int testctr;
	CK_RV retval;

	/*
	 *  Open RW session with slot
	 */
	TESTRV ("Opening session for fragmentation test",
		P11("C_OpenSession") (slotid, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				(void *) &noappinfo, NULL_PTR, &seshdl));
	MKFATAL ();

	/*
	 * Login to token as USER (possibly after setting up the PIN to use)
	 */
#	ifndef NON_DESTRUCTIVE_TESTING
		TESTRV ("Logging into token for setting up PIN",
			P11("C_Login") (seshdl, CKU_SO, (CK_UTF8CHAR_PTR) ascii_pin_so, strlen (ascii_pin_so)));
		TESTRV ("Setting up user PIN",
			P11("C_InitPIN") (seshdl, (CK_UTF8CHAR_PTR) ascii_pin_user, strlen (ascii_pin_user)));
		TESTRV ("Logging out after setting setting up PIN",
			P11("C_Logout") (seshdl));
#	endif
	TESTRV ("Logging into token for fragmentation test",
		P11("C_Login") (seshdl, CKU_USER, (CK_UTF8CHAR_PTR) ascii_pin_user, strlen (ascii_pin_user)));
	MKFATAL ();

	/*
	 * Fetch supported key sizes for this token.  Count in bytes, not
	 * bits, to simplify later randomisation of key sizes.
	 */
	CU_ASSERT_EQUAL (mech_sha1_rsa_pkcs.ulMinKeySize % 8, 0);
	CU_ASSERT_EQUAL (mech_sha1_rsa_pkcs.ulMaxKeySize % 8, 0);
	CU_ASSERT (mech_sha1_rsa_pkcs.ulMinKeySize <= mech_sha1_rsa_pkcs.ulMaxKeySize);
	CU_ASSERT (mech_sha1_rsa_pkcs.ulMinKeySize <= 512);
	CU_ASSERT (mech_sha1_rsa_pkcs.ulMaxKeySize >= 2048);
	minbytes = mech_sha1_rsa_pkcs.ulMinKeySize / 8;
	maxbytes = mech_sha1_rsa_pkcs.ulMaxKeySize / 8;

	/*
	 * Fill the token with key pairs.  Loop until memory runs out, and
	 * there's no more chances for filling up any further by lowering
	 * the maximum key size.
	 */
	retval = CKR_OK;
	while ( retval == CKR_OK ) {
		CK_ULONG keybits;

#ifdef QUICK_N_DIRTY
#ifdef MAX_KEYS_GEN
		if (keypairs == MAX_KEYS_GEN) {
			CU_FAIL ("Hit preset MAX_KEYS_GEN upper limit before the device's memory was full");
			break;
		}
#endif
#endif

		keybits = 8 * randomish_minmax (minbytes, maxbytes);
		keys = realloc (keys, sizeof (keys [0]) * (keypairs+1));
		CU_ASSERT_PTR_NOT_NULL_FATAL (keys);
		keys [keypairs].modbits = keybits;

		retval = newkeypair (
			seshdl,
			keys [keypairs].modbits, 
			&keys [keypairs].pub, 
			&keys [keypairs].priv); 

		if (retval == CKR_OK) {
			// Succeeded creating a key pair.  Increase counter.
			keypairs++;
		}
		if (retval != CKR_DEVICE_MEMORY) {
			TESTRV ("Key pair generation", retval);
		} else {
			CU_PASS ("Key pair generation sequence is running into memory limits");
			maxbytes = ( keybits / 8 ) - 1;
			if (minbytes <= maxbytes) {
				// It is still possible to squeeze something in
				retval = CKR_OK;
			}
		}
	}

	/*
	 * Pick random keys, remove and create a new one of the same size.
	 * If memory does not fragment, this should always succeed.
	 * Repeat this test thousands of times (say, 2500x).
	 */
	for (testctr = 0; testctr < THOUSANDS; testctr++) {
		int victim = randomish (keypairs);
		TESTRV ("Removing a private key for fragmentation testing",
			 P11("C_DestroyObject") (seshdl, keys [victim].priv));
		TESTRV ("Removing a public key for fragmentation testing",
			 P11("C_DestroyObject") (seshdl, keys [victim].pub));
		TESTRV ("Creating new key pair that ought to just fit in prior deleted key storage space",
			newkeypair (
				seshdl,
				keys [victim].modbits,
				&keys [victim].pub,
				&keys [victim].priv)
			);
	}

	/*
	 * Cleanup: Destroy all key pairs, logout, close session.
	 */
	for (kp=0; kp<keypairs; kp++) {
		TESTRV ("Removing a private key after fragmentation test",
			 P11("C_DestroyObject") (seshdl, keys [kp].priv));
		TESTRV ("Removing a public key after fragmentation test",
			 P11("C_DestroyObject") (seshdl, keys [kp].pub));
	}
	if (keys) {
		free (keys);
		keys = NULL;
	}
	TESTRV ("Logging out after fragmentation test",
		 P11("C_Logout") (seshdl));
	TESTRV ("Closing session after fragmentation test",
		 P11("C_CloseSession") (seshdl));
}


/* Test a slot: Given a global slot ID, test the slot given.
 * This particular routine tests if keys are created at proper sizes.
 * Note that the PKCS #1 standard defines modulus bit sizes as multiples
 * of 8, and that it defines the number of modulus bits by rounding up
 * the actual number of bits used to an eightfold value.  So if the prime
 * product of the modulus counts 1021 bits, it counts as a 1024 bit key.
 */
void testslot_keysizing (void) {
	CK_SESSION_HANDLE seshdl;
	CK_BYTE noappinfo;

	CK_ULONG minbytes, maxbytes, curbytes;

	CK_RV retval;

	/*
	 *  Open RW session with slot
	 */
	TESTRV ("Opening session for fragmentation test",
		P11("C_OpenSession") (slotid, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				(void *) &noappinfo, NULL_PTR, &seshdl));
	MKFATAL ();

	/*
	 * Login to token as USER (possibly after setting up the PIN to use)
	 */
#	ifndef NON_DESTRUCTIVE_TESTING
		TESTRV ("Logging into token for setting up PIN",
			P11("C_Login") (seshdl, CKU_SO, (CK_UTF8CHAR_PTR) ascii_pin_so, strlen (ascii_pin_so)));
		TESTRV ("Setting up user PIN",
			P11("C_InitPIN") (seshdl, (CK_UTF8CHAR_PTR) ascii_pin_user, strlen (ascii_pin_user)));
		TESTRV ("Logging out after setting setting up PIN",
			P11("C_Logout") (seshdl));
#	endif
	TESTRV ("Logging into token for keysizing test",
		P11("C_Login") (seshdl, CKU_USER, (CK_UTF8CHAR_PTR) ascii_pin_user, strlen (ascii_pin_user)));
	MKFATAL ();

	/*
	 * Fetch supported key sizes for this token.  Count in bytes, not
	 * bits, to simplify later randomisation of key sizes.
	 */
	CU_ASSERT_EQUAL (mech_sha1_rsa_pkcs.ulMinKeySize % 8, 0);
	CU_ASSERT_EQUAL (mech_sha1_rsa_pkcs.ulMaxKeySize % 8, 0);
	CU_ASSERT (mech_sha1_rsa_pkcs.ulMinKeySize <= mech_sha1_rsa_pkcs.ulMaxKeySize);
	CU_ASSERT (mech_sha1_rsa_pkcs.ulMinKeySize <= 512);
	CU_ASSERT (mech_sha1_rsa_pkcs.ulMaxKeySize >= 2048);
	minbytes = mech_sha1_rsa_pkcs.ulMinKeySize / 8;
	maxbytes = mech_sha1_rsa_pkcs.ulMaxKeySize / 8;

	/*
	 * Iterate over key pair lengths, checking the modulus size of each.
	 */
	curbytes = minbytes;
	while (curbytes <= maxbytes) {
		int ok = 1;
		CK_ULONG modbits = curbytes * 8;
		CK_OBJECT_HANDLE pub, priv;
		CK_ATTRIBUTE templ [] = {
			{ CKA_MODULUS, NULL_PTR, 0 },
		};
		uint8_t *modulus;
		retval = newkeypair (seshdl, modbits, &pub, &priv);
		TESTRV ("Creating key pair in modulus size test", retval);
		ok = ok && (retval == CKR_OK);
		if (ok) {
			TESTRV ("Obtaining length of modulus attribute field",
				P11("C_GetAttributeValue") (seshdl, pub, templ, sizeof (templ) / sizeof (*templ)));
			ok = ok && LASTRVOK ();
		}
		if (ok) {
			CU_ASSERT_NOT_EQUAL ((CK_ULONG) templ [0].ulValueLen, (CK_ULONG) -1);
			modulus = malloc (templ [0].ulValueLen);
			CU_ASSERT_PTR_NOT_NULL (modulus);
			templ [0].pValue = (CK_VOID_PTR) modulus;
			TESTRV ("Obtaining modulus attribute field",
				P11("C_GetAttributeValue") (seshdl, pub, templ, sizeof (templ) / sizeof (*templ)));
			ok = ok && LASTRVOK ();
			CU_ASSERT_NOT_EQUAL_FATAL ((CK_ULONG) templ [0].ulValueLen, (CK_ULONG) -1);
			while ((templ [0].ulValueLen > 0) && (*modulus == 0x00)) {
				modulus++;
				templ [0].ulValueLen--;
			}
			if (modulus) {
				free (modulus);
				modulus = NULL;
			}
			CU_ASSERT_EQUAL (curbytes * 8, templ [0].ulValueLen * 8);
			if (templ [0].ulValueLen == curbytes) {
				CU_PASS ("Modulus size matches expactations");
			} else {
				CU_FAIL ("Modulus size diverted from expectations");
			}
		}
		if (retval == CKR_OK) {
			TESTRV ("Destroying private key in modulus size test",
				 P11("C_DestroyObject") (seshdl, priv));
			TESTRV ("Destroying public key in modulus size test",
				 P11("C_DestroyObject") (seshdl, pub));
		}
		curbytes++;
	}

	/*
	 * Cleanup.
	 */
	TESTRV ("Logging out after modulus size test",
		 P11("C_Logout") (seshdl));
	TESTRV ("Closing session after modulus size test",
		 P11("C_CloseSession") (seshdl));

}


/* =============================================================== */


/* Test a slot: Given a global slot ID, test the slot given.
 * This particular routine tests if signatures are correctly made.
 */
void testslot_signing (void) {
	CK_SESSION_HANDLE seshdl;
	CK_BYTE noappinfo;

	int minbytes, maxbytes;

	int keytestctr, sigtestctr;

	/*
	 *  Open RW session with slot
	 */
	TESTRV ("Opening session for fragmentation test",
		P11("C_OpenSession") (slotid, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				(void *) &noappinfo, NULL_PTR, &seshdl));
	MKFATAL ();

	/*
	 * Login to token as USER (possibly after setting up the PIN to use)
	 */
#	ifndef NON_DESTRUCTIVE_TESTING
		TESTRV ("Logging into token for setting up PIN",
			P11("C_Login") (seshdl, CKU_SO, (CK_UTF8CHAR_PTR) ascii_pin_so, strlen (ascii_pin_so)));
		TESTRV ("Setting up user PIN",
			P11("C_InitPIN") (seshdl, (CK_UTF8CHAR_PTR) ascii_pin_user, strlen (ascii_pin_user)));
		TESTRV ("Logging out after setting setting up PIN",
			P11("C_Logout") (seshdl));
#	endif
	TESTRV ("Logging into token for signing test",
		P11("C_Login") (seshdl, CKU_USER, (CK_UTF8CHAR_PTR) ascii_pin_user, strlen (ascii_pin_user)));
	MKFATAL ();

	/*
	 * Fetch supported key sizes for this token.  Count in bytes, not
	 * bits, to simplify later randomisation of key sizes.
	 */
	CU_ASSERT_EQUAL (mech_sha1_rsa_pkcs.ulMinKeySize % 8, 0);
	CU_ASSERT_EQUAL (mech_sha1_rsa_pkcs.ulMaxKeySize % 8, 0);
	CU_ASSERT (mech_sha1_rsa_pkcs.ulMinKeySize <= mech_sha1_rsa_pkcs.ulMaxKeySize);
	CU_ASSERT (mech_sha1_rsa_pkcs.ulMinKeySize <= 512);
	CU_ASSERT (mech_sha1_rsa_pkcs.ulMaxKeySize >= 2048);
	minbytes = mech_sha1_rsa_pkcs.ulMinKeySize / 8;
	maxbytes = mech_sha1_rsa_pkcs.ulMaxKeySize / 8;

	/*
	 * Iterate over keys a couple of times, creating a new key pair for
	 * each iteration.
	 */
	for (keytestctr = 0; keytestctr < COUPLE; keytestctr++) {

		int modbits = 8 * randomish_minmax (minbytes, maxbytes);
		CK_OBJECT_HANDLE pub, priv;

		TESTRV ("Creating a new key pair for signature tests",
			newkeypair (seshdl, modbits, &pub, &priv));
		if (! LASTRVOK () ) {
			// Failure makes the rest of this loop dysfunctional
			continue;
		}

		/* Iterate over signatures about a hundred times.  Create
		 * a signature and verify it.
		 */
		for (sigtestctr = 0; sigtestctr < HUNDRED; sigtestctr++) {
			CK_BYTE data [] = "tralala-en-hopsasa";
			CK_BYTE *sig = malloc (maxbytes);
			CK_ULONG siglen;
			CK_MECHANISM mech = { CKM_SHA1_RSA_PKCS, NULL_PTR, 0 };
			if (sig == NULL) {
				CU_FAIL ("Out of memory allocating for signature test");
				break;
			}
			siglen = maxbytes;
			TESTRV ("Initiating signature",
				P11("C_SignInit") (seshdl, &mech, priv));
			TESTRV ("Constructing signature",
				P11("C_Sign") (seshdl, data, sizeof (data), sig, &siglen));
			if (siglen * 8 != (CK_ULONG) modbits) {
				CU_FAIL ("Signature length differs from promised length in signing test");
			} else {
				CU_PASS ("Signature length matches promised length in signing test");
			}
			TESTRV ("Initiating signature verification",
				P11("C_VerifyInit") (seshdl, &mech, pub));
			TESTRV ("Performing signature verification",
				P11("C_Verify") (seshdl, data, sizeof (data), sig, siglen));
			if (! LASTRVOK () ) {
				CU_FAIL ("Signature was incorrectly made in signing test");
			} else {
				CU_PASS ("Signature was correctly made in signing test");
			}
			free (sig);
		}

		/* Destroy the key pair used in this test iteration.
		 */
		TESTRV ("Destroying private key in modulus size test",
			 P11("C_DestroyObject") (seshdl, priv));
		TESTRV ("Destroying public key in modulus size test",
			 P11("C_DestroyObject") (seshdl, pub));
	}

	/*
	 * Cleanup.
	 */
	TESTRV ("Logging out after modulus size test",
		 P11("C_Logout") (seshdl));
	TESTRV ("Closing session after modulus size test",
		 P11("C_CloseSession") (seshdl));
}


/* =============================================================== */


/* Bail out is the routine that does some cleaning up upon exit().
 */
void bailout (void) {
	TESTRV ("Finalising PKCS #11 library",
		 P11("C_Finalize") (NULL_PTR));
	if (p11) {
		dlclose (p11);
		p11 = NULL;
	}
	CU_cleanup_registry ();
}


/* Initialise the token.
 */
void inittoken (void) {
#	ifndef NON_DESTRUCTIVE_TESTING
		TESTRV ("Formatting the token",
			 P11("C_InitToken") (slotid, (CK_UTF8CHAR_PTR) ascii_pin_so, strlen (ascii_pin_so), (CK_UTF8CHAR_PTR) TOKENLABEL_32CHARS));
#	else
	CU_PASS ("Skipping token initialisation in non-destructive test mode.  Existing USER/SO PIN values must be as set in source.");
#	endif
}


/* Commandline options */
static const char *opts = "hp:s:l:";	// t:
static const struct option longopts[] = {
	{ "help", 0, NULL, 'h' },
	{ "pin", 1, NULL, 'p' },
	{ "so-pin", 1, NULL, 's' },
	{ "pkcs11lib",1, NULL, 'l' },
	// { "token", 1, NULL, 't' },
	{ NULL, 0, NULL, 0 }
};


/* Sanity check a PIN to see if it is:
 *  - only ASCII
 *  - null-terminated but not longer than the available space
 *  - not yet set in previous options
 */
void storepin (char *kind, char *newval, char *dest, size_t maxstrlen) {
	char *this;
	if (*dest) {
		fprintf (stderr, "You should not provide multiple %s PIN codes\n", kind);
		exit (1);
	}
	if (! *newval) {
		fprintf (stderr, "The %s PIN should not be empty\n", kind);
		exit (1);
	}
	if (strlen (newval) > maxstrlen) {
		fprintf (stderr, "The %s PIN should not exceed %d characters\n", kind, maxstrlen);
		exit (1);
	}
	this = newval;
	while (*this) {
		if ((*this < 32) || (*this >= 127)) {
			fprintf (stderr, "The %s PIN should not contain characters outside the printable ASCII range\n", kind);
			exit (1);
		}
		this++;
	}
	strcpy (dest, newval);
}


/* Main routine: Initialise the PKCS #11 interface and find a slot ID to test.
 */
typedef void (*slottestfn_t) (void);
int main (int argc, char *argv []) {
	CK_SLOT_ID slotlist [2];
	CK_ULONG slotcount = 2;
	CU_pSuite st [4];
	int opt;
	int todo;
	extern char *optarg;

	/*
	 * Test arguments.
	 */
	todo = 1;
	while (todo && (opt = getopt_long (argc, argv, opts, longopts, NULL))) {
		switch (opt) {
		case 'p':	// --pin
			storepin ("user", optarg, ascii_pin_user, sizeof (ascii_pin_user) - 1);
			break;
			
		case 's':	// --so-pin
			storepin ("SO", optarg, ascii_pin_so, sizeof (ascii_pin_so) - 1);
			break;
		case 'l':	// --pkcs1llib
			if (p11) {
				fprintf (stderr, "You should not open multiple PKCS #11 libraries\n");
				exit (1);
			}
			if (strstr (argv [1], "softhsm")) {
				fprintf (stderr, "WARNING -- It appears you are using the SoftHSM library.\nIt may not constrain memory size, causing this test to run extremely long.\n");
			}
			p11 = dlopen (optarg, RTLD_NOW | RTLD_GLOBAL);
			if (!p11) {
				fprintf (stderr, "%s\n", dlerror ());
				exit (1);
			}
			break;
		// case 't':
		// Token?
		case -1:		// Done -- but are we, really?
			if ((*ascii_pin_user) && (*ascii_pin_so) && p11) {
				todo = 0;
				break;
			}
			// else continue...
			fprintf (stderr, "Please set all values required.\n");
		case 'h':
		case ':':
		case '?':
			fprintf (stderr, "Usage: %s --pin 1234 --so-pin 4321 --pkcs11lib /path/to/libpkcs11.so\n", argv [0]);
			exit (opt != 'h');
		}
	}

	/*
 	 * Register test suites and tests.
	 */
	if (CU_initialize_registry () != CUE_SUCCESS) {
		fprintf (stderr, "Failed to initialise test registry -- this is abnormal\n");
		exit (1);
	}
	st [0] = CU_add_suite ("Test if slot initiation works properly", NULL, NULL);
	st [1] = CU_add_suite ("Test if memory does not get fragmented", NULL, NULL);
	st [2] = CU_add_suite ("Test if key sizes work as desired", NULL, NULL);
	st [3] = CU_add_suite ("Test if signatures are made correctly", NULL, NULL);
	if (! (st [0] && st [1] && st [2] && st [3])) {
		fprintf (stderr, "Failed to allocate all test suites -- this is abnormal\n");
		exit (1);
	}
	if (! CU_add_test (st [0], "Initiation test", testslot_initiation)) {
		fprintf (stderr, "Failed to register test #0 -- this is abnormal\n");
		exit (1);
	}
	if (! CU_add_test (st [1], "Fragmentation test", testslot_fragmentation)) {
		fprintf (stderr, "Failed to register test #1 -- this is abnormal\n");
		exit (1);
	}
	if (! CU_add_test (st [2], "Key sizing test", testslot_keysizing)) {
		fprintf (stderr, "Failed to register test #2 -- this is abnormal\n");
		exit (1);
	}
	if (! CU_add_test (st [3], "Signing test", testslot_signing)) {
		fprintf (stderr, "Failed to register test #3 -- this is abnormal\n");
		exit (1);
	}

	/*
	 * Initialise the library and demand only one slot with a token.
	 */
	TESTRV ("Initialising PKCS #11 library",
		 P11("C_Initialize") (NULL_PTR));
	MKFATAL ();
	atexit (bailout);
	TESTRV ("Obtaining list of slots",
		 P11("C_GetSlotList") (TRUE, slotlist, &slotcount));
	if (slotcount != 1) {
		fprintf (stderr, "Number of slots is %d, so not equal to 1 -- unsure which to test\n", (int) slotcount);
		exit (1);
	}
	slotid = slotlist [0];

	/*
	 * Obtain mechanism information from the token.
 	 */
	TESTRV ("Getting number of mechanisms from token",
		 P11("C_GetMechanismInfo") (slotid, CKM_RSA_PKCS_KEY_PAIR_GEN, &mech_rsa_pkcs_key_pair_gen));
	MKFATAL ();
	TESTRV ("Getting number of mechanisms from token",
		 P11("C_GetMechanismInfo") (slotid, CKM_SHA1_RSA_PKCS, &mech_sha1_rsa_pkcs));
	MKFATAL ();
	TESTRV ("Getting number of mechanisms from token",
		 P11("C_GetMechanismInfo") (slotid, CKM_SHA_1, &mech_sha_1));
	MKFATAL ();

	/*
	 * Format the token and run a test.
	 * Do we need an "are you sure?" warning here?
	 */
	if (strlen (TOKENLABEL_32CHARS) != 32) {
		CU_FAIL_FATAL ("Token labels must be 32 characters long -- fix TOKENLABEL_32CHARS and recompile");
	}

	/*
	 * Automatically run all the tests that were registered
	 */
	CU_list_tests_to_file ();
	CU_automated_run_tests ();

	/*
	 * Unload the PKCS #11 library
	 */
	if (p11) {
		dlclose (p11);
		p11 = NULL;
	}

	/*
	 * Terminate without error-reporting return value.
	 */
	CU_cleanup_registry ();
	exit (0);
}

/* End of program */
