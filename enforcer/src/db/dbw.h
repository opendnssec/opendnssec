#ifndef DBW_H
#define DBW_H

#include <time.h>

struct db_connection_struct;
typedef struct db_connection_struct db_connection_t;

db_connection_t* db_connection_new(const char* database, const char* hostname, const char*username, const char*password);
int db_connection_free(db_connection_t*conn);

#define dbw_FIND(T,V,F,C,K)  __extension__  ({ T R=NULL; for (int I=0; I<C; I++) { if(V[I]->F == K) { R = V[I]; break; } } R; })
#define dbw_FINDSTR(T,V,F,C,K) __extension__  ({ T R=NULL; for (int I=0; I<C; I++) { if(!strcmp(V[I]->F, K)) { R = V[I]; break; } } R; })

typedef enum key_data_role {
  KEY_DATA_ROLE_INVALID = -1,
  KEY_DATA_ROLE_KSK = 1,
  KEY_DATA_ROLE_ZSK = 2,
  KEY_DATA_ROLE_CSK = 3
} key_data_role_t;

typedef enum policy_key_role {
  POLICY_KEY_ROLE_INVALID = -1,
  POLICY_KEY_ROLE_KSK = 1,
  POLICY_KEY_ROLE_ZSK = 2,
  POLICY_KEY_ROLE_CSK = 3
} policy_key_role_t;

typedef enum policy_denial_type {
  POLICY_DENIAL_TYPE_INVALID = -1,
  POLICY_DENIAL_TYPE_NSEC = 0,
  POLICY_DENIAL_TYPE_NSEC3 = 1
} policy_denial_type_t;

typedef enum hsm_key_key_type {
  HSM_KEY_KEY_TYPE_INVALID = -1,
  HSM_KEY_KEY_TYPE_RSA = 1
} hsm_key_key_type_t;

#define DBW_CLEAN    0
#define DBW_DELETE   1
#define DBW_INSERT   2
#define DBW_UPDATE   3

#define DBW_MINIMIZE_NONE   0
#define DBW_MINIMIZE_RRSIG  1
#define DBW_MINIMIZE_DNSKEY 2
#define DBW_MINIMIZE_DS     4
#define DBW_MINIMIZE_DS_RRSIG (DBW_MINIMIZE_DS | DBW_MINIMIZE_RRSIG)

enum dbw_key_role {
    /* Values chosen such that CSK = KSK|ZSK */
    DBW_KSK = 1,
    DBW_ZSK = 2,
    DBW_CSK = 3
};

extern const char *dbw_key_role_txt[];

enum dbw_keystate_type {
    DBW_DS          = 0,
    DBW_RRSIG       = 1,
    DBW_DNSKEY      = 2,
    DBW_RRSIGDNSKEY = 3
};

extern const char *dbw_keystate_type_txt[];

enum dbw_keystate_state {
    DBW_HIDDEN      = 0,
    DBW_RUMOURED    = 1,
    DBW_OMNIPRESENT = 2,
    DBW_UNRETENTIVE = 3,
    DBW_NA          = 4
};

extern const char *dbw_keystate_state_txt[];

enum dbw_ds_at_parent {
    DBW_DS_AT_PARENT_UNSUBMITTED = 0,
    DBW_DS_AT_PARENT_SUBMIT      = 1,
    DBW_DS_AT_PARENT_SUBMITTED   = 2,
    DBW_DS_AT_PARENT_SEEN        = 3,
    DBW_DS_AT_PARENT_RETRACT     = 4,
    DBW_DS_AT_PARENT_RETRACTED   = 5,
    DBW_DS_AT_PARENT_GONE        = 6
};

extern const char *dbw_ds_at_parent_txt[];

enum dbw_hsmkey_state {
    DBW_HSMKEY_UNUSED  = 1,
    DBW_HSMKEY_PRIVATE = 2,
    DBW_HSMKEY_SHARED  = 3,
    DBW_HSMKEY_DELETE  = 4
};

enum dbw_backup {
    DBW_BACKUP_NO_BACKUP = 0,
    DBW_BACKUP_REQUIRED  = 1,
    DBW_BACKUP_REQUESTED = 2,
    DBW_BACKUP_DONE      = 3
};

extern const char *dbw_backup_txt[];

enum dbw_soa_serial {
    DBW_SOA_SERIAL_COUNTER     = 0,
    DBW_SOA_SERIAL_DATECOUNTER = 1,
    DBW_SOA_SERIAL_UNIXTIME    = 2,
    DBW_SOA_SERIAL_KEEP        = 3
};

extern const char *dbw_soa_serial_txt[];

enum dbw_denial_type {
    DBW_NSEC = 0,
    DBW_NSEC3 = 1
};

extern const char *dbw_denial_type_txt[];

/* Returns static string representation of constant.
 * \param c: array of strings indexed by constant
 * \param n: constant from matching enum
 * @return: static string
 */
const char * dbw_enum2txt(const char *c[], int n);

/* Found value for a given string txt in set c, case insensitive.
 * \param c: array of strings indexed by constant
 * \param txt: Text to look for. Must be an exact, case insensitive, match.
 * @return enum value or -1 on failure.
 */
int dbw_txt2enum(const char *c[], const char *txt);

struct dbw_policykey {
    long id;
    struct dbw_policy *policy;
    char* repository;
    unsigned int role;
    unsigned int algorithm;
    unsigned int bits;
    unsigned int lifetime;
    unsigned int standby;
    unsigned int manual_rollover;
    unsigned int rfc5011;
    unsigned int minimize;
};

struct dbw_policy {
    long id;
    int scratch;
    int policykey_count;
    struct dbw_policykey **policykey;
    int hsmkey_count;
    struct dbw_hsmkey **hsmkey;
    int zone_count;
    struct dbw_zone **zone;

    char *name;
    char *description;
    char* denial_salt;
    unsigned int passthrough;
    unsigned int signatures_resign;
    unsigned int signatures_refresh;
    unsigned int signatures_jitter;
    unsigned int signatures_inception_offset;
    unsigned int signatures_validity_default;
    unsigned int signatures_validity_denial;
    unsigned int signatures_validity_keyset;
    unsigned int signatures_max_zone_ttl;
    unsigned int denial_type;
    unsigned int denial_optout;
    unsigned int denial_ttl;
    unsigned int denial_resalt;
    unsigned int denial_algorithm;
    unsigned int denial_iterations;
    unsigned int denial_salt_length;
    unsigned int denial_salt_last_change;
    unsigned int keys_ttl;
    unsigned int keys_retire_safety;
    unsigned int keys_publish_safety;
    unsigned int keys_shared;
    unsigned int keys_purge_after;
    unsigned int zone_propagation_delay;
    unsigned int zone_soa_ttl;
    unsigned int zone_soa_minimum;
    unsigned int zone_soa_serial;
    unsigned int parent_registration_delay;
    unsigned int parent_propagation_delay;
    unsigned int parent_ds_ttl;
    unsigned int parent_soa_ttl;
    unsigned int parent_soa_minimum;
};

struct dbw_key {
    long id;
    struct dbw_zone *zone; /** Only valid when joined */
    struct dbw_hsmkey *hsmkey; /** Only valid when joined */
    int keystate_count;
    struct dbw_keystate **keystate;
    int from_keydependency_count;
    struct dbw_keydependency **from_keydependency;
    int to_keydependency_count;
    struct dbw_keydependency **to_keydependency;

    unsigned int role;
    unsigned int ds_at_parent;
    unsigned int algorithm;
    time_t inception;
    unsigned int introducing;
    unsigned int should_revoke;
    unsigned int standby;
    unsigned int active_zsk;
    unsigned int active_ksk;
    unsigned int publish;
    unsigned int keytag;
    unsigned int minimize;
};

struct dbw_keystate {
    long id;
    struct dbw_key *key;
    unsigned int type; // should this be the enum
    unsigned int state;
    time_t last_change;
    unsigned int minimize;
    unsigned int ttl;
};

struct dbw_keydependency {
    int id;
    struct dbw_key *fromkey; /** Only valid when joined */
    struct dbw_key *tokey; /** Only valid when joined */
    unsigned int type;
};

struct dbw_hsmkey {
    long id;
    int key_count;
    struct dbw_key **key;

    char *locator;
    char *repository;
    unsigned int state;
    unsigned int bits;
    unsigned int algorithm;
    unsigned int role;
    time_t inception;
    unsigned int is_revoked;
    unsigned int key_type;
    unsigned int backup;
};

struct dbw_zone {
    long id;
    int scratch;
    int policy_id;
    struct dbw_policy *policy; /** Only valid when joined */
    int key_count;
    struct dbw_key **key;
    int keydependency_count;

    char *name;
    time_t next_change;
    char *signconf_path;
    char *input_adapter_uri;
    char *input_adapter_type;
    char *output_adapter_uri;
    char *output_adapter_type;
    time_t next_ksk_roll;
    time_t next_zsk_roll;
    time_t next_csk_roll;
    unsigned int signconf_needs_writing;
    time_t ttl_end_ds;
    time_t ttl_end_dk;
    time_t ttl_end_rs;
    unsigned int roll_ksk_now;
    unsigned int roll_zsk_now;
    unsigned int roll_csk_now;
};

struct dbw_db {
    int npolicies;
    struct dbw_policy** policies;
    int nzones;
    struct dbw_zone** zones;
};

/* DB operations */

/**
 * Read the entire database to memory. No further access to the database is
 * required for reading or modifying. Guarded by a R/W lock.
 *
 * return NULL on failure
 */
struct dbw_db *dbw_fetch(db_connection_t *conn, ...);

/**
 * Commit changes to the database. Guarded by a R/W lock. Only records marked
 * as dirty will be considered for writing.
 *
 * return 0 on success. 1 otherwise.
 */
int dbw_commit(struct dbw_db *db);

/**
 * Deep free this structure
 */
void dbw_free(struct dbw_db *db);

/**
 * Mark database object as dirty. Clean objects will never be written to the
 * database
 */
void dbw_mark_dirty(void *obj);

int database_version_get_version(db_connection_t* connection);

void dbw_add(void*array,int*count,void*item);

#endif /*DBW_H*/
