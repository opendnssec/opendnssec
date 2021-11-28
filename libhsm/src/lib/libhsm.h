/*
 * Copyright (c) 2009 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2009 NLNet Labs.
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

#ifndef HSM_H
#define HSM_H 1

#include <stdint.h>
#include <ldns/common.h>
#include <ldns/rbtree.h>
#include <pthread.h>

#define HSM_MAX_SESSIONS 100
/* 
 * Note that currently the MySQL kasp schema limits the number of HSMs to 
 * 127; so to increase it beyond that requires some database changes similar
 * to when keypairs(id) was increased, see svn r4465.
 *
 * Note that this constant also determines the size of the shared PIN memory.
 * Increasing this size requires any existing memory to be removed and should
 * be part of a migration script.
 */
#define HSM_MAX_SESSIONS 100

#define HSM_MAX_ALGONAME 16

#define HSM_ERROR_MSGSIZE 512

/* TODO: depends on type and key, or just leave it at current
 * maximum? */
#define HSM_MAX_SIGNATURE_LENGTH 512

/* Note that this constant also determines the size of the shared PIN memory.
 * Increasing this size requires any existing memory to be removed and should
 * be part of a migration script.
 */
#define HSM_MAX_PIN_LENGTH 255

/*! Return codes for some of the functions */
/*! These should be different than the list of CKR_ values defined
 * by pkcs11 (for easier debugging purposes of calling applications)
 */
#define HSM_OK                    0
#define HSM_ERROR                 0x10000001
#define HSM_PIN_INCORRECT         0x10000002
#define HSM_CONFIG_FILE_ERROR     0x10000003
#define HSM_REPOSITORY_NOT_FOUND  0x10000004
#define HSM_NO_REPOSITORIES       0x10000005
#define HSM_MODULE_NOT_FOUND      0x10000006

/*! The mode for the PIN callback functions */
#define HSM_PIN_FIRST	0	/* Used when getting the PIN for the first time. */
#define HSM_PIN_RETRY	1	/* Used when we failed to login the first time. */
#define HSM_PIN_SAVE	2	/* The latest PIN can be saved for future use. Called
				   after a successful login. */

#if (LDNS_REVISION >= ((1<<16)|(8<<8)|(0)))
#  define USE_ED25519 LDNS_BUILD_CONFIG_USE_ED25519
#  define USE_ED448 LDNS_BUILD_CONFIG_USE_ED448
#elif (LDNS_REVISION >= ((1<<16)|(7<<8)|(0)))
#  define USE_ED25519 1
#  define USE_ED448 1
#else
#  define USE_ED25519 0
#  define USE_ED448 0
#endif

/*! HSM configuration */
typedef struct {
    unsigned int use_pubkey;     /*!< Maintain public keys in HSM */
    unsigned int allow_extract;  /*!< Generate CKA_EXTRACTABLE private keys */
} hsm_config_t;

/*! Data type to describe an HSM */
typedef struct {
    unsigned int id;             /*!< HSM numerical identifier */
    char         *name;          /*!< name of repository */
    char         *token_label;   /*!< label of the token */
    char         *path;          /*!< path to PKCS#11 library */
    void         *handle;        /*!< handle from dlopen()*/
    void         *sym;           /*!< Function list from dlsym */
    hsm_config_t *config;        /*!< optional per HSM configuration */
} hsm_module_t;

/*! HSM Session */
typedef struct {
    hsm_module_t  *module;
    unsigned long session;
} hsm_session_t;

/*! HSM Key Pair */
typedef struct {
    char *modulename;   /*!< name of the module, as in hsm_session_t.module.name */
    unsigned long      private_key;  /*!< private key within module */
    unsigned long      public_key;   /*!< public key within module */
} libhsm_key_t;

/*! HSM Key Pair Information */
typedef struct {
  char          *id;             /*!< key id */
  unsigned long algorithm;       /*!< key algorithm (cast from CKK_*)*/
  char          *algorithm_name; /*!< key algorithm name */
  unsigned long keysize;         /*!< key size */
} libhsm_key_info_t;

/*! HSM Repositories */
typedef struct hsm_repository_struct hsm_repository_t;
struct hsm_repository_struct {
    hsm_repository_t* next; /*!< next repository > */
    char    *name;          /*!< name */
    char    *module;        /*!< PKCS#11 module */
    char    *tokenlabel;    /*!< PKCS#11 token label */
    char    *pin;           /*!< PKCS#11 login credentials */
    uint8_t require_backup; /*!< require a backup of keys before using new keys */
    uint8_t use_pubkey;     /*!< use public keys in repository? */
    unsigned int allow_extract;  /*!< Generate CKA_EXTRACTABLE private keys */
};

/*! HSM context to keep track of sessions */
typedef struct {
    hsm_session_t *session[HSM_MAX_SESSIONS];  /*!< HSM sessions */
    size_t        session_count;               /*!< number of configured HSMs */

    /*!< non-zero if the last operation failed (only the first error will be set) */
    int error;

   /*!< static string describing the action we were trying to do
        when the first error happened */
    const char *error_action;

    /*!< static string describing the first error */
    char error_message[HSM_ERROR_MSGSIZE];
    
    ldns_rbtree_t* keycache;
    pthread_mutex_t *keycache_lock;
} hsm_ctx_t;


/*! Set HSM Context Error

If the ctx is given, and it's error value is still 0, the value will be
set to 'error', and the error_message and error_action will be set to
the given strings.

\param ctx      HSM context
\param error    error code
\param action   action for which the error occured
\param message  error message format string
*/
extern void
hsm_ctx_set_error(hsm_ctx_t *ctx, int error, const char *action,
                 const char *message, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 4, 5)))
#endif
     ;

/*! Open HSM library

\param rlist Repository list.
\param pin_callback This function will be called for tokens that have
                    no PIN configured. The default hsm_prompt_pin() can
                    be used. If this value is NULL, these tokens will
                    be skipped.
\return 0 if successful, !0 if failed

Attaches all HSMs in the repository list, querying for PINs (using the given
callback function) if not known.
Also creates initial sessions (not part of any context; every API
function that takes a context can be passed NULL, in which case the
global context will be used) and log into each HSM.
*/
extern int
hsm_open2(hsm_repository_t* rlist,
         char *(pin_callback)(unsigned int, const char *, unsigned int));


/*! Create new repository as specified in conf.xml.

\param name           Repository name.
\param module         PKCS#11 module.
\param tokenlabel     PKCS#11 token label.
\param pin            PKCS#11 login credentials.
\param use_pubkey     Whether to store the public key in the HSM.
\return The created repository.
*/
hsm_repository_t *
hsm_repository_new(char* name, char* module, char* tokenlabel, char* pin,
    uint8_t use_pubkey, uint8_t allowextract, uint8_t require_backup);

/*! Free configured repositories.

\param r Repository list.
*/
void
hsm_repository_free(hsm_repository_t* r);

/*! Function that queries for a PIN, can be used as callback
    for hsm_open(). Stores the PIN in the shared memory.

\param id Used for identifying the repository. Will have a value between zero and
          HSM_MAX_SESSIONS.
\param repository The repository name will be included in the prompt
\param mode The type of mode the function should run in.
\return The string the user enters
*/
extern char *
hsm_prompt_pin(unsigned int id, const char *repository, unsigned int mode);


/*! Function that will check if there is a PIN in the shared memory and returns it.

\param id Used for identifying the repository. Will have a value between zero and
          HSM_MAX_SESSIONS.
\param repository The repository name will be included in the prompt
\param mode The type of mode the function should run in.
\return The string the user enters
*/
extern char *
hsm_check_pin(unsigned int id, const char *repository, unsigned int mode);


/*! Logout

    Function that will logout the user by deleting the shared memory and
    semaphore. Any authenticated process will still be able to interact
    with the HSM.
*/
extern int
hsm_logout_pin(void);


/*! Close HSM library

    Log out and detach from all configured HSMs
    This cleans up all data for libhsm, and should be the last function
    called.
*/
extern void
hsm_close(void);


/*! Create new HSM context

Creates a new session for each attached HSM. The returned hsm_ctx_t *
can be freed with hsm_destroy_context()
*/
extern hsm_ctx_t *
hsm_create_context(void);


/*! Check HSM context

Check if the associated sessions are still alive.
If they are not alive, then try re-open libhsm.

\param context HSM context
\return 0 if successful, !0 if failed
*/
extern int
hsm_check_context();


/*! Destroy HSM context

\param context HSM context

Also destroys any associated sessions.
*/
extern void
hsm_destroy_context(hsm_ctx_t *context);

extern void
libhsm_key_free(libhsm_key_t *key);

/*! List all known keys in all attached HSMs

After the function has run, the value at count contains the number
of keys found.

The resulting key list can be freed with libhsm_key_list_free()
Alternatively, each individual key structure in the list could be
freed with libhsm_key_free()

\param context HSM context
\param count location to store the number of keys found
*/
extern libhsm_key_t **
hsm_list_keys(hsm_ctx_t *context, size_t *count);


/*! List all known keys in a HSM

After the function has run, the value at count contains the number
of keys found.

The resulting key list can be freed with libhsm_key_list_free()
Alternatively, each individual key structure in the list could be
freed with libhsm_key_free()

\param context HSM context
\param count location to store the number of keys found
\param repository repository to list the keys in
*/
extern libhsm_key_t **
hsm_list_keys_repository(hsm_ctx_t *context,
                         size_t *count,
                         const char *repository);



/*! Find a key pair by CKA_ID (as hex string)

The returned key structure can be freed with libhsm_key_free()

\param context HSM context
\param id CKA_ID of key to find (null-terminated 
          string of hex characters)
\return key identifier or NULL if not found (or invalid input)
*/
extern libhsm_key_t *
hsm_find_key_by_id(hsm_ctx_t *context,
                   const char *id);

/*! Generate new key pair in HSM

Keys generated by libhsm will have a 16-byte identifier set as CKA_ID
and the hexadecimal representation of it set as CKA_LABEL.
Other stuff, like exponent, may be needed here as well.

The returned key structure can be freed with libhsm_key_free()

\param context HSM context
\param repository repository in where to create the key
\param keysize Size of RSA key
\return return key identifier or NULL if key generation failed
*/
extern libhsm_key_t *
hsm_generate_rsa_key(hsm_ctx_t *context,
                     const char *repository,
                     unsigned long keysize);

/*! Generate new key pair in HSM

Keys generated by libhsm will have a 16-byte identifier set as CKA_ID
and the hexadecimal representation of it set as CKA_LABEL.

The returned key structure can be freed with libhsm_key_free()

\param context HSM context
\param repository repository in where to create the key
\param keysize Size of DSA key
\return return key identifier or NULL if key generation failed
*/
extern libhsm_key_t *
hsm_generate_dsa_key(hsm_ctx_t *context,
                     const char *repository,
                     unsigned long keysize);

/*! Generate new key pair in HSM

Keys generated by libhsm will have a 16-byte identifier set as CKA_ID
and the hexadecimal representation of it set as CKA_LABEL.

The returned key structure can be freed with libhsm_key_free()

\param context HSM context
\param repository repository in where to create the key
\return return key identifier or NULL if key generation failed
*/
extern libhsm_key_t *
hsm_generate_gost_key(hsm_ctx_t *context,
                     const char *repository);

/*! Generate new key pair in HSM

Keys generated by libhsm will have a 16-byte identifier set as CKA_ID
and the hexadecimal representation of it set as CKA_LABEL.

The returned key structure can be freed with libhsm_key_free()

\param context HSM context
\param repository repository in where to create the key
\param curve which curve to use
\return return key identifier or NULL if key generation failed
*/
extern libhsm_key_t *
hsm_generate_ecdsa_key(hsm_ctx_t *context,
                       const char *repository,
                       const char *curve);

/*! Generate new key pair in HSM

Keys generated by libhsm will have a 16-byte identifier set as CKA_ID
and the hexadecimal representation of it set as CKA_LABEL.

The returned key structure can be freed with libhsm_key_free()

\param context HSM context
\param repository repository in where to create the key
\param curve which curve to use
\return return key identifier or NULL if key generation failed
*/
libhsm_key_t *
hsm_generate_eddsa_key(hsm_ctx_t *context,
                       const char *repository,
                       const char *curve);

/*! Remove a key pair from HSM

When a key is removed, the module pointer is set to NULL, and
the public and private key handles are set to 0. The structure still
needs to be freed.

\param context HSM context
\param key Key pair to be removed
\return 0 if successful, !0 if failed
*/
extern int
hsm_remove_key(hsm_ctx_t *context, libhsm_key_t *key);


/*! Free the memory of an array of key structures, as returned by
hsm_list_keys()

\param key_list The array of keys to free
\param count The number of keys in the array
*/
extern void
libhsm_key_list_free(libhsm_key_t **key_list, size_t count);


/*! Get id as null-terminated hex string using key identifier

The returned id is allocated data, and must be free()d by the caller

\param context HSM context
\param key Key pair to get the ID from
\return id of key pair
*/
extern char *
hsm_get_key_id(hsm_ctx_t *context,
               const libhsm_key_t *key);


/*! Get extended key information

The returned id is allocated data, and must be freed by the caller
With libhsm_key_info_free()

\param context HSM context
\param key Key pair to get information about
\return key information
*/
extern libhsm_key_info_t *
hsm_get_key_info(hsm_ctx_t *context,
                 const libhsm_key_t *key);


/*! Frees the libhsm_key_info_t structure

\param key_info The structure to free
*/
extern void
libhsm_key_info_free(libhsm_key_info_t *key_info);

/*! Fill a buffer with random data from any attached HSM

\param context HSM context
\param buffer Buffer to fill with random data
\param length Size of random buffer
\return 0 if successful, !0 if failed

*/
extern int
hsm_random_buffer(hsm_ctx_t *ctx,
                  unsigned char *buffer,
                  unsigned long length);


/*! Return unsigned 32-bit random number from any attached HSM
\param context HSM context
\return 32-bit random number, or 0 if no HSM with a random generator is
               attached
*/
extern uint32_t
hsm_random32(hsm_ctx_t *ctx);


/*! Return unsigned 64-bit random number from any attached HSM
\param context HSM context
\return 64-bit random number, or 0 if no HSM with a random generator is
               attached
*/
extern uint64_t
hsm_random64(hsm_ctx_t *ctx);



/*
 * Additional functions for debugging, and non-general use-cases.
 */

/*! Attached a named HSM using a PKCS#11 shared library and
   optional credentials (may be NULL, but then undefined)
   This function changes the global state, and is not threadsafe

\param repository the name of the repository
\param token_label the name of the token to attach
\param path the path of the shared PKCS#11 library
\param pin the PIN to log into the token
\param config optional configuration
\return 0 on success, -1 on error
*/
extern int
hsm_attach(const char *repository,
           const char *token_name,
           const char *path,
           const char *pin,
           const hsm_config_t *config);

/*! Check whether a named token has been initialized in this context
\param ctx HSM context
\param token_name The name of the token
\return 1 if the token is attached, 0 if not found
*/
extern int
hsm_token_attached(hsm_ctx_t *ctx,
                   const char *repository);

/*! Return the current error message

The returned message is allocated data, and must be free()d by the caller

\param ctx HSM context
\return error message string
*/

extern char *
hsm_get_error(hsm_ctx_t *gctx);

/* a few debug functions for applications */
extern void hsm_print_session(hsm_session_t *session);
extern void hsm_print_ctx(hsm_ctx_t *ctx);
extern void hsm_print_key(hsm_ctx_t *ctx, libhsm_key_t *key);
extern void hsm_print_error(hsm_ctx_t *ctx);
extern void hsm_print_tokeninfo(hsm_ctx_t *ctx);

/* implementation of a key cache per context, needs changing see
 * OPENDNSSEC-799.
 */
extern void keycache_create(hsm_ctx_t* ctx);
extern void keycache_destroy(hsm_ctx_t* ctx);
extern const libhsm_key_t* keycache_lookup(hsm_ctx_t* ctx, const char* locator);

#endif /* HSM_H */
