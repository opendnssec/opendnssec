#define _GNU_SOURCE 
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>

#include "db/dbw.h"
#include "log.h"
#include "utilities.h"

static pthread_rwlock_t db_lock = PTHREAD_RWLOCK_INITIALIZER;

const char * dbw_key_role_txt[] = {
    "(void)", "KSK", "ZSK", "CSK", NULL
};

const char * dbw_keystate_type_txt[] = {
    "DS", "RRSIG", "DNSKEY", "RRSIGDNSKEY", NULL
};

const char * dbw_keystate_state_txt[] = {
    "hidden", "rumoured", "omnipresent", "unretentive", "NA", NULL
};

const char * dbw_ds_at_parent_txt[] = {
    "unsubmitted", "submit", "submitted", "seen", "retract", "retracted", "gone"
, NULL
};

const char * dbw_backup_txt[] = {
    "Not Required", "Required", "Prepared", "Done", NULL
};

const char * dbw_denial_type_txt[] = {
    "NSEC", "NSEC3"
};

const char * dbw_soa_serial_txt[] = {
    "counter", "datecounter", "unixtime", "keep", NULL
};

struct dbsimple_definition dbw_datadefinition;
struct dbsimple_definition dbw_policydefinition;
struct dbsimple_definition dbw_policykeydefinition;
struct dbsimple_definition dbw_hsmkeydefinition;
struct dbsimple_definition dbw_zonedefinition;
struct dbsimple_definition dbw_keydefinition;
struct dbsimple_definition dbw_keystatedefinition;
struct dbsimple_definition dbw_keydependencydefinition;
struct dbsimple_definition dbw_keystatedefinition;
struct dbsimple_definition dbw_keydependencydefinition;

struct dbsimple_field dbw_datafields[] = {
    { dbsimple_MASTERREFERENCES, &dbw_policydefinition,    offsetof(struct dbw_db, policies),   offsetof(struct dbw_db, npolicies) },
    { dbsimple_STUBREFERENCES,   &dbw_policykeydefinition, -1, -1},
    { dbsimple_MASTERREFERENCES, &dbw_hsmkeydefinition,    offsetof(struct dbw_db, hsmkeys),    offsetof(struct dbw_db, nhsmkeys) },
    { dbsimple_MASTERREFERENCES, &dbw_zonedefinition,      offsetof(struct dbw_db, zones),      offsetof(struct dbw_db, nzones) },
};

struct dbsimple_field dbw_policyfields[] = {
    { dbsimple_LONGINT,        &dbw_policydefinition,    offsetof(struct dbw_policy, id),                          -1 },
    { dbsimple_INT,            NULL,                     -1, -1 }, // [rev]
    { dbsimple_STRING,         &dbw_policydefinition,    offsetof(struct dbw_policy, name),                        -1 },
    { dbsimple_STRING,         &dbw_policydefinition,    offsetof(struct dbw_policy, description),                 -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, passthrough),                 -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, signatures_resign),           -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, signatures_refresh),          -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, signatures_jitter),           -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, signatures_inception_offset), -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, signatures_validity_default), -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, signatures_validity_denial),  -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, signatures_validity_keyset),  -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, signatures_max_zone_ttl),     -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, denial_type),                 -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, denial_optout),               -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, denial_ttl),                  -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, denial_resalt),               -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, denial_algorithm),            -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, denial_iterations),           -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, denial_salt_length),          -1 },
    { dbsimple_STRING,         &dbw_policydefinition,    offsetof(struct dbw_policy, denial_salt),                 -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, denial_salt_last_change),     -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, keys_ttl),                    -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, keys_retire_safety),          -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, keys_publish_safety),         -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, keys_shared),                 -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, keys_purge_after),            -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, zone_propagation_delay),      -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, zone_soa_ttl),                -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, zone_soa_minimum),            -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, zone_soa_serial),             -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, parent_registration_delay),   -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, parent_propagation_delay),    -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, parent_ds_ttl),               -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, parent_soa_ttl),              -1 },
    { dbsimple_UINT,           &dbw_policydefinition,    offsetof(struct dbw_policy, parent_soa_minimum),          -1 },
    { dbsimple_BACKREFERENCE,  &dbw_datadefinition,      offsetof(struct dbw_db, policies),      offsetof(struct dbw_db, npolicies) },
    { dbsimple_OPENREFERENCES, &dbw_policykeydefinition, offsetof(struct dbw_policy, policykey), offsetof(struct dbw_policy, policykey_count) },
    { dbsimple_OPENREFERENCES, &dbw_hsmkeydefinition,    offsetof(struct dbw_policy, hsmkey),    offsetof(struct dbw_policy, hsmkey_count) },
    { dbsimple_OPENREFERENCES, &dbw_zonedefinition,      offsetof(struct dbw_policy, zone),      offsetof(struct dbw_policy, zone_count) },
};

struct dbsimple_field dbw_policykeyfields[] = {
    { dbsimple_LONGINT,        &dbw_policykeydefinition,    offsetof(struct dbw_policykey, id),              -1 },
    { dbsimple_INT,            NULL,                     -1, -1 }, // [rev]
    { dbsimple_REFERENCE,      &dbw_policykeydefinition,    offsetof(struct dbw_policykey, policy),          -1 },
    { dbsimple_BACKREFERENCE,  &dbw_policydefinition,       offsetof(struct dbw_policy,    policykey),       offsetof(struct dbw_policy, policykey_count) },
    { dbsimple_STRING,         &dbw_policykeydefinition,    offsetof(struct dbw_policykey, repository),      -1 },
    { dbsimple_UINT,           &dbw_policykeydefinition,    offsetof(struct dbw_policykey, role),            -1 },
    { dbsimple_UINT,           &dbw_policykeydefinition,    offsetof(struct dbw_policykey, algorithm),       -1 },
    { dbsimple_UINT,           &dbw_policykeydefinition,    offsetof(struct dbw_policykey, bits),            -1 },
    { dbsimple_UINT,           &dbw_policykeydefinition,    offsetof(struct dbw_policykey, lifetime),        -1 },
    { dbsimple_UINT,           &dbw_policykeydefinition,    offsetof(struct dbw_policykey, manual_rollover), -1 },
    { dbsimple_UINT,           &dbw_policykeydefinition,    offsetof(struct dbw_policykey, rfc5011),         -1 },
    { dbsimple_UINT,           &dbw_policykeydefinition,    offsetof(struct dbw_policykey, standby),         -1 },
    { dbsimple_UINT,           &dbw_policykeydefinition,    offsetof(struct dbw_policykey, minimize),        -1 }
};

struct dbsimple_field dbw_hsmkeyfields[] = {
    { dbsimple_LONGINT,        &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, id),                 -1 },
    { dbsimple_INT,            NULL,                     -1, -1 }, // [rev]
    { dbsimple_STRING,         &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, locator),            -1 },
    { dbsimple_STRING,         &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, repository),         -1 },
    { dbsimple_UINT,           &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, state),              -1 },
    { dbsimple_UINT,           &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, bits),               -1 },
    { dbsimple_UINT,           &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, algorithm),          -1 },
    { dbsimple_UINT,           &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, role),               -1 },
    { dbsimple_LONGINT,        &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, inception),          -1 },
    { dbsimple_UINT,           &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, is_revoked),         -1 },
    { dbsimple_UINT,           &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, key_type),           -1 },
    { dbsimple_UINT,           &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, backup),             -1 },
    { dbsimple_BACKREFERENCE,  &dbw_policydefinition,       offsetof(struct dbw_policy, hsmkey),             offsetof(struct dbw_policy, hsmkey_count) },
    { dbsimple_BACKREFERENCE,  &dbw_datadefinition,         offsetof(struct dbw_db,   hsmkeys),              offsetof(struct dbw_db, nhsmkeys) },
    { dbsimple_OPENREFERENCES, &dbw_hsmkeydefinition,       offsetof(struct dbw_hsmkey, key),                -1 },
};

struct dbsimple_field dbw_zonefields[] = {
    { dbsimple_LONGINT,        &dbw_zonedefinition,       offsetof(struct dbw_zone, id),                     -1 },
    { dbsimple_INT,            NULL,                     -1, -1 }, // [rev]
    { dbsimple_REFERENCE,      &dbw_policydefinition,     offsetof(struct dbw_zone, policy),                 -1 },
    { dbsimple_BACKREFERENCE,  &dbw_policydefinition,     offsetof(struct dbw_policy, zone),                 offsetof(struct dbw_policy, zone_count) },
    { dbsimple_OPENREFERENCES, &dbw_zonedefinition,       offsetof(struct dbw_zone, key),                    offsetof(struct dbw_zone, key_count) },
    { dbsimple_STRING,         &dbw_zonedefinition,       offsetof(struct dbw_zone, name),                   -1 },
    { dbsimple_LONGINT,        &dbw_zonedefinition,       offsetof(struct dbw_zone, next_change),            -1 },
    { dbsimple_STRING,         &dbw_zonedefinition,       offsetof(struct dbw_zone, signconf_path),          -1 },
    { dbsimple_STRING,         &dbw_zonedefinition,       offsetof(struct dbw_zone, input_adapter_uri),      -1 },
    { dbsimple_STRING,         &dbw_zonedefinition,       offsetof(struct dbw_zone, input_adapter_type),     -1 },
    { dbsimple_STRING,         &dbw_zonedefinition,       offsetof(struct dbw_zone, output_adapter_uri),     -1 },
    { dbsimple_STRING,         &dbw_zonedefinition,       offsetof(struct dbw_zone, output_adapter_type),    -1 },
    { dbsimple_LONGINT,        &dbw_zonedefinition,       offsetof(struct dbw_zone, next_ksk_roll),          -1 },
    { dbsimple_LONGINT,        &dbw_zonedefinition,       offsetof(struct dbw_zone, next_zsk_roll),          -1 },
    { dbsimple_LONGINT,        &dbw_zonedefinition,       offsetof(struct dbw_zone, next_csk_roll),          -1 },
    { dbsimple_UINT,           &dbw_zonedefinition,       offsetof(struct dbw_zone, signconf_needs_writing), -1 },
    { dbsimple_LONGINT,        &dbw_zonedefinition,       offsetof(struct dbw_zone, ttl_end_ds),             -1 },
    { dbsimple_LONGINT,        &dbw_zonedefinition,       offsetof(struct dbw_zone, ttl_end_dk),             -1 },
    { dbsimple_LONGINT,        &dbw_zonedefinition,       offsetof(struct dbw_zone, ttl_end_rs),             -1 },
    { dbsimple_UINT,           &dbw_zonedefinition,       offsetof(struct dbw_zone, roll_ksk_now),           -1 },
    { dbsimple_UINT,           &dbw_zonedefinition,       offsetof(struct dbw_zone, roll_zsk_now),           -1 },
    { dbsimple_UINT,           &dbw_zonedefinition,       offsetof(struct dbw_zone, roll_csk_now),           -1 },
    { dbsimple_BACKREFERENCE,  &dbw_datadefinition,       offsetof(struct dbw_db, zones),                    offsetof(struct dbw_db, nzones) },
};

struct dbsimple_field dbw_keyfields[] = {
    { dbsimple_LONGINT,        &dbw_keydefinition,           offsetof(struct dbw_key, id),                     -1 },
    { dbsimple_INT,            NULL, -1, -1 }, // [rev]
    { dbsimple_REFERENCE,      &dbw_zonedefinition,          offsetof(struct dbw_key, zone),                -1 },
    { dbsimple_BACKREFERENCE,  &dbw_zonedefinition,          offsetof(struct dbw_zone, key),                offsetof(struct dbw_zone, key_count) },
    { dbsimple_REFERENCE,      &dbw_hsmkeydefinition,        offsetof(struct dbw_key, hsmkey),              -1 },
    { dbsimple_OPENREFERENCES, &dbw_keystatedefinition,      offsetof(struct dbw_key, keystate),            offsetof(struct dbw_key, keystate_count) },
    { dbsimple_OPENREFERENCES, &dbw_keydependencydefinition, offsetof(struct dbw_key, from_keydependency),  offsetof(struct dbw_key, from_keydependency_count) },
    { dbsimple_OPENREFERENCES, &dbw_keydependencydefinition, offsetof(struct dbw_key, to_keydependency),    offsetof(struct dbw_key, to_keydependency_count) },
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, algorithm),           -1 },
    { dbsimple_LONGINT,        &dbw_keydefinition,           offsetof(struct dbw_key, inception),           -1 },
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, role),                -1 },
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, introducing),         -1 },
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, should_revoke),       -1 },
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, standby),             -1 },
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, active_zsk),          -1 },
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, publish),             -1 },
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, active_ksk),          -1 },    
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, ds_at_parent),        -1 },
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, keytag),              -1 },
    { dbsimple_UINT,           &dbw_keydefinition,           offsetof(struct dbw_key, minimize),            -1 },
};

struct dbsimple_field dbw_keystatefields[] = {
    { dbsimple_LONGINT,        &dbw_keystatedefinition, offsetof(struct dbw_keystate, id),          -1 },
    { dbsimple_INT,            NULL, -1, -1 }, // [rev]
    { dbsimple_BACKREFERENCE,  &dbw_keydefinition,      offsetof(struct dbw_key,  keystate),        offsetof(struct dbw_key, keystate_count) },
    { dbsimple_UINT,           &dbw_keystatedefinition, offsetof(struct dbw_keystate, type),        -1 },
    { dbsimple_UINT,           &dbw_keystatedefinition, offsetof(struct dbw_keystate, state),       -1 },
    { dbsimple_LONGINT,        &dbw_keystatedefinition, offsetof(struct dbw_keystate, last_change), -1 },
    { dbsimple_UINT,           &dbw_keystatedefinition, offsetof(struct dbw_keystate, minimize),    -1 },
    { dbsimple_UINT,           &dbw_keystatedefinition, offsetof(struct dbw_keystate, ttl),         -1 },
};

struct dbsimple_field dbw_keydependencyfields[] = {
    { dbsimple_INT,            &dbw_keydependencydefinition, offsetof(struct dbw_keydependency, id),      -1 },
    { dbsimple_INT,            NULL, -1, -1 }, // [rev]
    { dbsimple_REFERENCE,      &dbw_keydefinition,           offsetof(struct dbw_keydependency, fromkey), -1 },
    { dbsimple_BACKREFERENCE,  &dbw_keydefinition,           offsetof(struct dbw_key, zone),              offsetof(struct dbw_key, from_keydependency_count) },
    { dbsimple_REFERENCE,      &dbw_keydefinition,           offsetof(struct dbw_keydependency, tokey),   -1 },
    { dbsimple_BACKREFERENCE,  &dbw_keydefinition,           offsetof(struct dbw_key, zone),              offsetof(struct dbw_key, to_keydependency_count) },
    { dbsimple_UINT,           &dbw_keydependencydefinition, offsetof(struct dbw_keydependency, type),    -1 },
};

struct dbsimple_definition dbw_datadefinition =          { "dbw_data",          sizeof(struct dbw_db),            dbsimple_FLAG_SINGLETON,   sizeof(dbw_datafields)/sizeof(struct dbsimple_field),          dbw_datafields };
struct dbsimple_definition dbw_policydefinition =        { "dbw_policy",        sizeof(struct dbw_policy),        dbsimple_FLAG_HASREVISION, sizeof(dbw_policyfields)/sizeof(struct dbsimple_field),        dbw_policyfields,  };
struct dbsimple_definition dbw_policykeydefinition =     { "dbw_policykey",     sizeof(struct dbw_policykey),     dbsimple_FLAG_HASREVISION, sizeof(dbw_policykeyfields)/sizeof(struct dbsimple_field),     dbw_policykeyfields };
struct dbsimple_definition dbw_zonedefinition =          { "dbw_zone",          sizeof(struct dbw_zone),          dbsimple_FLAG_HASREVISION, sizeof(dbw_zonefields)/sizeof(struct dbsimple_field),          dbw_zonefields };
struct dbsimple_definition dbw_keydefinition =           { "dbw_key",           sizeof(struct dbw_key),           dbsimple_FLAG_HASREVISION, sizeof(dbw_keyfields)/sizeof(struct dbsimple_field),           dbw_keyfields };
struct dbsimple_definition dbw_keystatedefinition =      { "dbw_keystate",      sizeof(struct dbw_keystate),      dbsimple_FLAG_HASREVISION, sizeof(dbw_keystatefields)/sizeof(struct dbsimple_field),      dbw_keystatefields };
struct dbsimple_definition dbw_keydependencydefinition = { "dbw_keydependency", sizeof(struct dbw_keydependency), 0,                         sizeof(dbw_keydependencyfields)/sizeof(struct dbsimple_field), dbw_keydependencyfields };
struct dbsimple_definition dbw_hsmkeydefinition =        { "dbw_hsmkey",        sizeof(struct dbw_hsmkey),        dbsimple_FLAG_HASREVISION, sizeof(dbw_hsmkeyfields)/sizeof(struct dbsimple_field),        dbw_hsmkeyfields };

static struct dbsimple_definition* dbw_definitions[] = {
    &dbw_datadefinition,
    &dbw_hsmkeydefinition,
    &dbw_policydefinition,
    &dbw_policykeydefinition,
    &dbw_zonedefinition,
    &dbw_keydefinition,
    &dbw_keystatedefinition,
    &dbw_keydependencydefinition
};

extern dbsimple_fetchplan_reference fetchplanQschema;
extern dbsimple_fetchplan_reference fetchplanSchema;
extern dbsimple_fetchplan_reference fetchplanProbe;
extern dbsimple_fetchplan_reference fetchplanDefault;

static dbsimple_fetchplan_type qschema      = NULL;
static dbsimple_fetchplan_type schema       = NULL;
static dbsimple_fetchplan_type probe        = NULL;
static dbsimple_fetchplan_type defaultfetch = NULL;

static dbsimple_fetchplan_array fetchplans = {
    &qschema, &schema, &probe, &defaultfetch
};

dbsimple_fetchplan_reference fetchplanQschema  = &fetchplans[0];
dbsimple_fetchplan_reference fetchplanSchema   = &fetchplans[1];
dbsimple_fetchplan_reference fetchplanProbe    = &fetchplans[2];
dbsimple_fetchplan_reference fetchplanDefault  = &fetchplans[3];

#include "sqlstmts_sqlite3.inc"

const char *
dbw_enum2txt(const char *c[], int n)
{
    return c[n];
}

int
dbw_txt2enum(const char *c[], const char *txt)
{
    int i = 0;
    do {
        if (!strcasecmp(txt, c[i])) return i;
    } while (c[++i]);
    return -1;
}

struct dbw_db *
dbw_fetch(db_connection_t *conn, ...)
{
    struct dbw_db *db;
    db = dbsimple_fetch(conn, fetchplanDefault);
    db->session = conn;
    return db;
}

int
dbw_end_commit(struct dbw_db** db)
{
    if(!db || !*db)
        return 0;
    if (pthread_rwlock_wrlock(&db_lock)) {
        ods_log_error("[dbw_commit] Unable to obtain database write lock.");
        return 1;
    }
    // commit
    (void)pthread_rwlock_unlock(&db_lock);
    return 0;
}

void
dbw_end_unmodified(struct dbw_db** db)
{
    if(!db || !*db)
        return;
}

void
dbw_end_rollback(struct dbw_db** db)
{
    if(!db || !*db)
        return;
    dbsimple_free((*db)->session);
    *db = NULL;
}

void
dbw_mark_dirty(struct dbw_db *db, void *ptr)
{
    assert(db);
    dbsimple_dirty(db->session, ptr);
}

void
dbw_add(struct dbw_db *db, void* array, int* count, void* ptr)
{
    assert(db);
    if(!alloc(array, sizeof(void*), count, (*count)+1)) {
        ((void***)array)[(*count) - 1] = ptr;
        dbsimple_dirty(db->session, ptr);
    }
}

int
probe_database(engine_type* engine)
{
    return 0;
}

static dbsimple_connection_type connection = NULL;

db_connection_t*
get_database_connection(engine_type* engine)
{
    int rcode;
    char* location = NULL;
    dbsimple_session_type session;

    if(!connection) {
        // FIXME needs mutex or different set-up
        dbsimple_initialize();
        dbsimple_sqlite3_initialize();
        switch(engine->config->db_type) {
            case ENFORCER_DATABASE_TYPE_SQLITE:
                asprintf(&location, "sqlite3:%s", (engine->config->datastore ? engine->config->datastore : "kasp"));
                break;
            case ENFORCER_DATABASE_TYPE_MYSQL:
                if(engine->config->db_port > 0) {
                    asprintf(&location, "mysql:%s%s%s%s%s:%d/%s",
                         (engine->config->db_username ? engine->config->db_username : ""),
                         (engine->config->db_password ? "#" : ""),
                         (engine->config->db_password ? engine->config->db_password : ""),
                         ((engine->config->db_username||engine->config->db_password) ? "@" : ""),
                         (engine->config->db_host ? engine->config->db_host : ""),
                         engine->config->db_port,
                         (engine->config->datastore ? engine->config->datastore : "kasp"));
                } else {
                    asprintf(&location, "mysql:%s%s%s%s%s%s%s",
                         (engine->config->db_username ? engine->config->db_username : ""),
                         (engine->config->db_password ? "#" : ""),
                         (engine->config->db_password ? engine->config->db_password : ""),
                         ((engine->config->db_username||engine->config->db_password) ? "@" : ""),
                         (engine->config->db_host ? engine->config->db_host : ""),
                         (engine->config->db_host ? "/" : ""),
                         (engine->config->datastore ? engine->config->datastore : "kasp"));
                }
                break;
            case ENFORCER_DATABASE_TYPE_NONE:
                return NULL;
        }
        rcode = dbsimple_openconnection(location, sizeof(fetchplans)/sizeof(dbsimple_fetchplan_reference), fetchplans,
                                        sizeof(dbw_definitions)/sizeof(struct dbsimple_definition*), dbw_definitions, &connection);
        dbsimple_fetchplan(&qschema,      connection, "sqlite3", sqlstmts_sqlite3_qschema_);
        dbsimple_fetchplan(&schema,       connection, "sqlite3", sqlstmts_sqlite3_schema_);
        dbsimple_fetchplan(&probe,        connection, "sqlite3", sqlstmts_sqlite3_probe_);
        dbsimple_fetchplan(&defaultfetch, connection, "sqlite3", sqlstmts_sqlite3_default_);
        if(!rcode)
            return NULL;
    }
    if(location)
        free(location);
    if(dbsimple_opensession(connection, &session)) {
        return NULL;
    }

    return session;
}

void
release_database_connection(db_connection_t* dbconn)
{
    dbsimple_closesession(dbconn);
}
