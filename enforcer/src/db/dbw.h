#ifndef DBW_H
#define DBW_H

#include <time.h>

#include "db/db_connection.h"
#include "db/zone_db.h"

#define DBW_CLEAN    0
#define DBW_DELETE   1
#define DBW_INSERT   2
#define DBW_UPDATE   3

enum dbw_key_role {
    /* Values choosen such that CSK = KSK|ZSK */
    DBW_KSK = 1,
    DBW_ZSK = 2,
    DBW_CSK = 3
};

static const char * dbw_key_role_txt[] = {
    "(void)", "KSK", "ZSK", "CSK", NULL
};

enum dbw_keystate_type {
    DBW_DS          = 0,
    DBW_RRSIG       = 1,
    DBW_DNSKEY      = 2,
    DBW_RRSIGDNSKEY = 3
};

static const char * dbw_keystate_type_txt[] = {
    "DS", "RRSIG", "DNSKEY", "RRSIGDNSKEY", NULL
};

enum dbw_keystate_state {
    DBW_HIDDEN      = 0,
    DBW_RUMOURED    = 1,
    DBW_OMNIPRESENT = 2,
    DBW_UNRETENTIVE = 3,
    DBW_NA          = 4
};

static const char * dbw_keystate_state_txt[] = {
    "hidden", "rumoured", "omnipresent", "unretentive", "NA", NULL
};

enum dbw_ds_at_parent {
    DBW_DS_AT_PARENT_UNSUBMITTED = 0,
    DBW_DS_AT_PARENT_SUBMIT      = 1,
    DBW_DS_AT_PARENT_SUBMITTED   = 2,
    DBW_DS_AT_PARENT_SEEN        = 3,
    DBW_DS_AT_PARENT_RETRACT     = 4,
    DBW_DS_AT_PARENT_RETRACTED   = 5
};

static const char * dbw_ds_at_parent_txt[] = {
    "unsubmitted", "submit", "submitted", "seen", "retract", "retracted", NULL
};

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

static const char * dbw_backup_txt[] = {
    "Not Required", "Required", "Prepared", "Done", NULL
};

enum dbw_soa_serial {
    DBW_SOA_SERIAL_COUNTER     = 0,
    DBW_SOA_SERIAL_DATECOUNTER = 1,
    DBW_SOA_SERIAL_UNIXTIME    = 2,
    DBW_SOA_SERIAL_KEEP        = 3
};

static const char * dbw_soa_serial_txt[] = {
    "counter", "datecounter", "unixtime", "keep", NULL
};

const char * dbw_enum2txt(const char *c[], int n);
int dbw_txt2enum(const char *c[], const char *txt);

/* This is a bit icky - sorry
 * In my defense: this is temporary code.
 *
 * This structure corespondents with each row of any table. The first int is
 * the primary id for the row. The following 3 (int, ptr) tuples either mean
 * (foreign key, pointer to parent dbrow object) or (count, pointer to list of
 * of dbrow objects). In the latter case these are actually pointer pointers.
 *
 * This is the base object the merge and filter functions operate on. Anywhere
 * else in the program the dbw_* structs are used.
 */
struct dbrow {
    int id;
    int dirty;
    int revision;
    int int0;   /* In derived structs these are padded if unused to ensure */
    void *ptr0; /* each is at least as big as a struct dbrow */
    int int1;
    void *ptr1;
    int int2;
    void *ptr2;
    int int3;
    void *ptr3;
    int int4;
    void *ptr4;
};

struct dbw_policykey {
    int id;
    int dirty;
    int revision;
    int policy_id;
    struct dbw_policy *policy;
    int _padding1; void *__padding1;
    int _padding2; void *__padding2;
    int _padding3; void *__padding3;
    int _padding4; void *__padding4;

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
    int id;
    int dirty;
    int revision;
    int policykey_count;
    struct dbw_policykey **policykey;
    int hsmkey_count;
    struct dbw_hsmkey **hsmkey;
    int zone_count;
    struct dbw_zone **zone;
    int _padding3; void *__padding3;
    int _padding4; void *__padding4;

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
    int id;
    int dirty;
    int revision;
    int zone_id;
    struct dbw_zone *zone; /** Only valid when joined */
    int hsmkey_id;
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
    unsigned int inception;
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
    int id;
    int dirty;
    int revision;
    int key_id;
    struct dbw_key *key; /** Only valid when joined */
    int _padding1; void *__padding1;
    int _padding2; void *__padding2;
    int _padding3; void *__padding3;
    int _padding4; void *__padding4;

    unsigned int type;
    unsigned int state;
    unsigned int last_change;
    unsigned int minimize;
    unsigned int ttl;
};

struct dbw_keydependency {
    int id;
    int dirty;
    int revision;
    int zone_id;
    struct dbw_zone *zone; /** Only valid when joined */
    int fromkey_id;
    struct dbw_key *fromkey; /** Only valid when joined */
    int tokey_id;
    struct dbw_key *tokey; /** Only valid when joined */
    int _padding3; void *__padding3;
    int _padding4; void *__padding4;

    unsigned int type;
};

struct dbw_hsmkey {
    int id;
    int dirty;
    int revision;
    int policy_id;
    struct dbw_policy *policy; /** Only valid when joined */
    int key_count;
    struct dbw_key **key;
    int _padding2; void *__padding2;
    int _padding3; void *__padding3;
    int _padding4; void *__padding4;

    char *locator;
    char *repository;
    unsigned int state;
    unsigned int bits;
    unsigned int algorithm;
    unsigned int role;
    unsigned int inception;
    unsigned int is_revoked;
    unsigned int key_type;
    unsigned int backup;
};

struct dbw_zone {
    int id;
    int dirty;
    int revision;
    int policy_id;
    struct dbw_policy *policy; /** Only valid when joined */
    int key_count;
    struct dbw_key **key;
    int keydependency_count;
    struct dbw_keydependency **keydependency;
    int _padding3; void *__padding3;
    int _padding4; void *__padding4;

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

struct dbw_list {
    struct dbrow **set;
    size_t n;
    void (*free)(struct dbrow *);
    int (*update)(const db_connection_t *, struct dbrow *);
    int (*revision)(const db_connection_t *, struct db_value *);
};

struct dbw_db {
    const db_connection_t *conn;
    struct dbw_list *policies;
    struct dbw_list *policykeys;
    struct dbw_list *zones;
    struct dbw_list *keys;
    struct dbw_list *hsmkeys;
    struct dbw_list *keystates;
    struct dbw_list *keydependencies;
};

/* DB operations */

/**
 * The two following functions are the only two operations that will access
 * the database.
 */

/**
 * Read the entire database to memory. No further access to the database is
 * required for reading or modifying. Guarded by a R/W lock.
 *
 * return NULL on failure
 */
struct dbw_db *dbw_fetch(db_connection_t *conn);

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
void dbw_mark_dirty(struct dbrow *row);

/**
 * convenience functions to get a specific zone or policy from a fetched
 * database.
 *
 * Return NULL if no such object exists
 */
struct dbw_zone * dbw_get_zone(struct dbw_db *db, char const *zonename);
struct dbw_policy * dbw_get_policy(struct dbw_db *db, char const *policyname);
struct dbw_keystate * dbw_get_keystate(struct dbw_key *key, int type);

/* TODO functions below this need to be cleaned up / evaluated*/

void dbw_zone_free(struct dbrow *row);

int dbw_add_keystate(struct dbw_db *db, struct dbw_key *key, struct dbw_keystate *keystate);
int dbw_add_zone(struct dbw_db *db, struct dbw_policy *policy, struct dbw_zone *zone);
int dbw_add_hsmkey(struct dbw_db *db, struct dbw_policy *policy, struct dbw_hsmkey *hsmkey);

struct dbw_keydependency * dbw_new_keydependency(struct dbw_db *db,
    struct dbw_key *fromkey, struct dbw_key *tokey, int type,
    struct dbw_zone *zone);
struct dbw_key * dbw_new_key(struct dbw_db *db, struct dbw_zone *zone,
    struct dbw_hsmkey *hsmkey);

/** ALL */

int dbw_zone_exists(db_connection_t *dbconn, char const *zonename);

void dbw_policies_add_hsmkey(struct dbw_list *policies, struct dbw_hsmkey *hsmkey);
void dbw_policies_add_zone(struct dbw_list *policies, struct dbw_zone *zone);

#endif /*DBW_H*/
