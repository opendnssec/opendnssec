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

#define HSM_MAX_SESSIONS 100
/* 
 * Note that currently the MySQL kasp schema limits the number of HSMs to 
 * 127; so to increase it beyond that requires some database changes similar
 * to when keypairs(id) was increased, see svn r4465.
 */
#define HSM_MAX_ALGONAME 16

#define HSM_ERROR_MSGSIZE 512

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


/*! HSM configuration */
typedef struct {
    unsigned int use_pubkey;     /*!< Maintain public keys in HSM */
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
    const hsm_module_t *module;      /*!< pointer to module */
    unsigned long      private_key;  /*!< private key within module */
    unsigned long      public_key;   /*!< public key within module */
} hsm_key_t;

/*! HSM Key Pair Information */
typedef struct {
  char          *id;             /*!< key id */
  unsigned long algorithm;       /*!< key algorithm (cast from CKK_*)*/
  char          *algorithm_name; /*!< key algorithm name */
  unsigned long keysize;         /*!< key size */
} hsm_key_info_t;

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
} hsm_ctx_t;


/*! Open HSM library

\param config path to OpenDNSSEC XML configuration file
\param pin_callback This function will be called for tokens that have
                    no PIN configured. The default hsm_prompt_pin() can
                    be used. If this value is NULL, these tokens will
                    be skipped
\param data optional data that will be directly passed to the callback
            function
\return 0 if successful, !0 if failed

Attaches all configured HSMs, querying for PINs (using the given
callback function) if not known.
Also creates initial sessions (not part of any context; every API
function that takes a context can be passed NULL, in which case the
global context will be used) and log into each HSM.
*/
int
hsm_open(const char *config,
         char *(pin_callback)(const char *repository, void *),
         void *data);


/*! Function that queries for a PIN, can be used as callback
    for hsm_open()

\param repository The repository name will be included in the prompt
\param data This value is unused
\return The string the user enters
*/
char *
hsm_prompt_pin(const char *repository, void *data);


/*! Close HSM library

    Log out and detach from all configured HSMs
    This cleans up all data for libhsm, and should be the last function
    called.
*/
int
hsm_close();


/*! Create new HSM context

Creates a new session for each attached HSM. The returned hsm_ctx_t *
can be freed with hsm_destroy_context()
*/
hsm_ctx_t *
hsm_create_context(void);

/*! Check HSM context

Check if the associated sessions are still alive.
If they are not alive, then try re-open libhsm.

\param context HSM context
\return 0 if successful, !0 if failed
*/
int
hsm_check_context(hsm_ctx_t *context);


/*! Destroy HSM context

\param context HSM context

Also destroys any associated sessions.
*/
void
hsm_destroy_context(hsm_ctx_t *context);


/*! List all known keys in all attached HSMs

After the function has run, the value at count contains the number
of keys found.

The resulting key list can be freed with hsm_key_list_free()
Alternatively, each individual key structure in the list could be
freed with hsm_key_free()

\param context HSM context
\param count location to store the number of keys found
*/
hsm_key_t **
hsm_list_keys(hsm_ctx_t *context, size_t *count);


/*! List all known keys in a HSM

After the function has run, the value at count contains the number
of keys found.

The resulting key list can be freed with hsm_key_list_free()
Alternatively, each individual key structure in the list could be
freed with hsm_key_free()

\param context HSM context
\param count location to store the number of keys found
\param repository repository to list the keys in
*/
hsm_key_t **
hsm_list_keys_repository(hsm_ctx_t *context,
                         size_t *count,
                         const char *repository);


/*! Count all known keys in all attached HSMs

\param context HSM context
*/
size_t
hsm_count_keys(hsm_ctx_t *context);


/*! Count all known keys in a HSM

\param context HSM context
\param repository repository in where to count the keys
*/
size_t
hsm_count_keys_repository(hsm_ctx_t *context,
                          const char *repository);



/*! Find a key pair by CKA_ID (as hex string)

The returned key structure can be freed with hsm_key_free()

\param context HSM context
\param id CKA_ID of key to find (null-terminated 
          string of hex characters)
\return key identifier or NULL if not found (or invalid input)
*/
hsm_key_t *
hsm_find_key_by_id(hsm_ctx_t *context,
                   const char *id);

/*! Generate new key pair in HSM

Keys generated by libhsm will have a 16-byte identifier set as CKA_ID
and the hexadecimal representation of it set as CKA_LABEL.
Other stuff, like exponent, may be needed here as well.

The returned key structure can be freed with hsm_key_free()

\param context HSM context
\param repository repository in where to create the key
\param keysize Size of RSA key
\return return key identifier or NULL if key generation failed
*/
hsm_key_t *
hsm_generate_rsa_key(hsm_ctx_t *context,
                     const char *repository,
                     unsigned long keysize);


/*! Remove a key pair from HSM

When a key is removed, the module pointer is set to NULL, and
the public and private key handles are set to 0. The structure still
needs to be freed.

\param context HSM context
\param key Key pair to be removed
\return 0 if successful, !0 if failed
*/
int
hsm_remove_key(hsm_ctx_t *context, hsm_key_t *key);


/*! Free the memory for a key structure.

\param key The key structure to free
*/
void
hsm_key_free(hsm_key_t *key);


/*! Free the memory of an array of key structures, as returned by
hsm_list_keys()

\param key_list The array of keys to free
\param count The number of keys in the array
*/
void
hsm_key_list_free(hsm_key_t **key_list, size_t count);


/*! Get id as null-terminated hex string using key identifier

The returned id is allocated data, and must be free()d by the caller

\param context HSM context
\param key Key pair to get the ID from
\return id of key pair
*/
char *
hsm_get_key_id(hsm_ctx_t *context,
               const hsm_key_t *key);


/*! Get extended key information

The returned id is allocated data, and must be freed by the caller
With hsm_key_info_free()

\param context HSM context
\param key Key pair to get information about
\return key information
*/
hsm_key_info_t *
hsm_get_key_info(hsm_ctx_t *context,
                 const hsm_key_t *key);


/*! Frees the hsm_key_info_t structure

\param key_info The structure to free
*/
void
hsm_key_info_free(hsm_key_info_t *key_info);

/*! Fill a buffer with random data from any attached HSM

\param context HSM context
\param buffer Buffer to fill with random data
\param length Size of random buffer
\return 0 if successful, !0 if failed

*/
int
hsm_random_buffer(hsm_ctx_t *ctx,
                  unsigned char *buffer,
                  unsigned long length);


/*! Return unsigned 32-bit random number from any attached HSM
\param context HSM context
\return 32-bit random number, or 0 if no HSM with a random generator is
               attached
*/
uint32_t
hsm_random32(hsm_ctx_t *ctx);


/*! Return unsigned 64-bit random number from any attached HSM
\param context HSM context
\return 64-bit random number, or 0 if no HSM with a random generator is
               attached
*/
uint64_t
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
int
hsm_attach(const char *repository,
           const char *token_name,
           const char *path,
           const char *pin,
           const hsm_config_t *config);

/*! Detach a named HSM
   This function changes the global state, and is not threadsafe
\param token_name the token to detach
\return 0 on success, -1 on error
*/
int
hsm_detach(const char *repository);

/*! Check whether a named token has been initialized in this context
\param ctx HSM context
\param token_name The name of the token
\return 1 if the token is attached, 0 if not found
*/
int
hsm_token_attached(hsm_ctx_t *ctx,
                   const char *repository);

/*! Return the current error message

The returned message is allocated data, and must be free()d by the caller

\param ctx HSM context
\return error message string
*/

char *
hsm_get_error(hsm_ctx_t *gctx);

/* a few debug functions for applications */
void hsm_print_session(hsm_session_t *session);
void hsm_print_ctx(hsm_ctx_t *gctx);
void hsm_print_key(hsm_key_t *key);
void hsm_print_error(hsm_ctx_t *ctx);
void hsm_print_tokeninfo(hsm_ctx_t *gctx);

#endif /* HSM_H */