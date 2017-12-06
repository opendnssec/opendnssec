#include <string.h>
#include <pthread.h>

#include "config.h"

#include "log.h"
#include "db/zone_db.h"
#include "db/policy.h"
#include "db/db_connection.h"

#include "db/dbw.h"

static pthread_rwlock_t db_lock = PTHREAD_RWLOCK_INITIALIZER;

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

static void
dbw_list_free(struct dbw_list *dbw_list)
{
    if (!dbw_list) return;
    for (size_t i = 0; i < dbw_list->n; i++) {
        dbw_list->free(dbw_list->set[i]);
    }
    free(dbw_list->set);
    free(dbw_list);
}

static void
dbw_policy_free(struct dbrow *row)
{
    struct dbw_policy *policy = (struct dbw_policy *)row;
    if (!policy) return;

    free(policy->policykey);
    free(policy->hsmkey);
    free(policy->zone);

    free(policy->name);
    free(policy->description);
    free(policy->denial_salt);
    free(policy);
}

static void
dbw_policykey_free(struct dbrow *row)
{
    struct dbw_policykey *policykey = (struct dbw_policykey *)row;
    if (!policykey) return;
    free(policykey->repository);
    free(policykey);
}

void
dbw_zone_free(struct dbrow *row)
{
    struct dbw_zone *zone = (struct dbw_zone *)row;
    if (!zone) return;
    free(zone->key);
    free(zone->keydependency);

    free(zone->name);
    free(zone->signconf_path);
    free(zone->input_adapter_uri);
    free(zone->input_adapter_type);
    free(zone->output_adapter_uri);
    free(zone->output_adapter_type);
    free(zone);
}

static void
dbw_key_free(struct dbrow *row)
{
    struct dbw_key *key = (struct dbw_key *)row;
    if (!key) return;
    free(key->keystate);
    free(key->from_keydependency);
    free(key->to_keydependency);

    free(key);
}

static void
dbw_keystate_free(struct dbrow *row)
{
    struct dbw_keystate *keystate = (struct dbw_keystate *)row;
    if (!keystate) return;

    free(keystate);
}

static void
dbw_keydependency_free(struct dbrow *row)
{
    struct dbw_keydependency *keydependency = (struct dbw_keydependency *)row;
    if (!keydependency) return;

    free(keydependency);
}

static void
dbw_hsmkey_free(struct dbrow *row)
{
    struct dbw_hsmkey *hsmkey = (struct dbw_hsmkey *)row;
    if (!hsmkey) return;
    free(hsmkey->key);

    free(hsmkey->locator);
    free(hsmkey->repository);
    free(hsmkey);
}

static int
dbxvalue2int(struct db_value const *val)
{
    switch (val->type) {
        case DB_TYPE_INT32:  return (int)val->int32;
        case DB_TYPE_UINT32: return (int)val->uint32;
        case DB_TYPE_INT64:  return (int)val->int64;
        case DB_TYPE_UINT64: return (int)val->uint64;
        default: return -1;
    }
}

static int dbw_policy_revision(const db_connection_t *dbconn, struct db_value *id)
{
    policy_t *dbx_obj = policy_new(dbconn);
    int rev = -1;
    if (dbx_obj && !policy_get_by_id(dbx_obj, id))
        rev = dbxvalue2int(&dbx_obj->rev);
    policy_free(dbx_obj);
    return rev;
}

static int dbw_policykey_revision(const db_connection_t *dbconn, struct db_value *id)
{
    policy_key_t *dbx_obj = policy_key_new(dbconn);
    int rev = -1;
    if (dbx_obj && !policy_key_get_by_id(dbx_obj, id))
        rev = dbxvalue2int(&dbx_obj->rev);
    policy_key_free(dbx_obj);
    return rev;
}

static int dbw_zone_revision(const db_connection_t *dbconn, struct db_value *id)
{
    zone_db_t *dbx_obj = zone_db_new(dbconn);
    int rev = -1;
    if (dbx_obj && !zone_db_get_by_id(dbx_obj, id))
        rev = dbxvalue2int(&dbx_obj->rev);
    zone_db_free(dbx_obj);
    return rev;
}

static int dbw_key_revision(const db_connection_t *dbconn, struct db_value *id)
{
    key_data_t *dbx_obj = key_data_new(dbconn);
    int rev = -1;
    if (dbx_obj && !key_data_get_by_id(dbx_obj, id))
        rev = dbxvalue2int(&dbx_obj->rev);
    key_data_free(dbx_obj);
    return rev;
}

static int dbw_keystate_revision(const db_connection_t *dbconn, struct db_value *id)
{
    key_state_t *dbx_obj = key_state_new(dbconn);
    int rev = -1;
    if (dbx_obj && !key_state_get_by_id(dbx_obj, id))
        rev = dbxvalue2int(&dbx_obj->rev);
    key_state_free(dbx_obj);
    return rev;
}

static int dbw_keydependency_revision(const db_connection_t *dbconn, struct db_value *id)
{
    key_dependency_t *dbx_obj = key_dependency_new(dbconn);
    int rev = -1;
    if (dbx_obj && !key_dependency_get_by_id(dbx_obj, id))
        rev = dbxvalue2int(&dbx_obj->rev);
    key_dependency_free(dbx_obj);
    return rev;
}

static int dbw_hsmkey_revision(const db_connection_t *dbconn, struct db_value *id)
{
    hsm_key_t *dbx_obj = hsm_key_new(dbconn);
    int rev = -1;
    if (dbx_obj && !hsm_key_get_by_id(dbx_obj, id))
        rev = dbxvalue2int(&dbx_obj->rev);
    hsm_key_free(dbx_obj);
    return rev;
}

static int
dbw_policy_update(const db_connection_t *dbconn, struct dbrow *row)
{
    struct db_value id;
    policy_t *dbx_obj;
    struct dbw_policy *policy = (struct dbw_policy *)row;
    int ret;

    memset(&id, 0, sizeof (id));
    if (!(dbx_obj = policy_new(dbconn))) {
        return 1;
    }

    switch (row->dirty) {
        case DBW_DELETE:
            if (db_value_from_int32(&id, row->id) || policy_get_by_id(dbx_obj, &id))
                return 1;
            ret = policy_delete(dbx_obj);
            policy_free(dbx_obj);
            return ret;
        case DBW_UPDATE:
            if (db_value_from_int32(&id, row->id) || policy_get_by_id(dbx_obj, &id))
                return 1;
            free(dbx_obj->name);
            free(dbx_obj->description);
        case DBW_INSERT: /* fall through intentional */
            free(dbx_obj->denial_salt);
    }

    dbx_obj->name                           = strdup(policy->name);
    dbx_obj->description                    = strdup(policy->description);
    dbx_obj->denial_salt                    = strdup(policy->denial_salt);

    if (!dbx_obj->name || !dbx_obj->description || !dbx_obj->denial_salt) {
        policy_free(dbx_obj);
        return 1;
    }
    dbx_obj->passthrough                    = policy->passthrough;
    dbx_obj->signatures_resign              = policy->signatures_resign;
    dbx_obj->signatures_refresh             = policy->signatures_refresh;
    dbx_obj->signatures_jitter              = policy->signatures_jitter;
    dbx_obj->signatures_inception_offset    = policy->signatures_inception_offset;
    dbx_obj->signatures_validity_default    = policy->signatures_validity_default;
    dbx_obj->signatures_validity_denial     = policy->signatures_validity_denial;
    dbx_obj->signatures_validity_keyset     = policy->signatures_validity_keyset;
    dbx_obj->signatures_max_zone_ttl        = policy->signatures_max_zone_ttl;
    dbx_obj->denial_type                    = policy->denial_type;
    dbx_obj->denial_optout                  = policy->denial_optout;
    dbx_obj->denial_ttl                     = policy->denial_ttl;
    dbx_obj->denial_resalt                  = policy->denial_resalt;
    dbx_obj->denial_algorithm               = policy->denial_algorithm;
    dbx_obj->denial_iterations              = policy->denial_iterations;
    dbx_obj->denial_salt_length             = policy->denial_salt_length;
    dbx_obj->denial_salt_last_change        = policy->denial_salt_last_change;
    dbx_obj->keys_ttl                       = policy->keys_ttl;
    dbx_obj->keys_retire_safety             = policy->keys_retire_safety;
    dbx_obj->keys_publish_safety            = policy->keys_publish_safety;
    dbx_obj->keys_shared                    = policy->keys_shared;
    dbx_obj->keys_purge_after               = policy->keys_purge_after;
    dbx_obj->zone_propagation_delay         = policy->zone_propagation_delay;
    dbx_obj->zone_soa_ttl                   = policy->zone_soa_ttl;
    dbx_obj->zone_soa_minimum               = policy->zone_soa_minimum;
    dbx_obj->zone_soa_serial                = policy->zone_soa_serial;
    dbx_obj->parent_registration_delay      = policy->parent_registration_delay;
    dbx_obj->parent_propagation_delay       = policy->parent_propagation_delay;
    dbx_obj->parent_ds_ttl                  = policy->parent_ds_ttl;
    dbx_obj->parent_soa_ttl                 = policy->parent_soa_ttl;
    dbx_obj->parent_soa_minimum             = policy->parent_soa_minimum;

    if (row->dirty == DBW_UPDATE) {
        ret = policy_update(dbx_obj);
    } else {
        ret = policy_create(dbx_obj);
        policy->id = dbx_obj->dbo->last_row_id;
    }
    policy_free(dbx_obj);
    return ret;
}

static int
dbw_policykey_update(const db_connection_t *dbconn, struct dbrow *row)
{
    struct db_value id;
    policy_key_t *dbx_obj;
    struct dbw_policykey *policykey = (struct dbw_policykey *)row;
    int ret;

    memset(&id, 0, sizeof (id));
    if (!(dbx_obj = policy_key_new(dbconn))) {
        return 1;
    }

    switch (row->dirty) {
        case DBW_DELETE:
            if (db_value_from_int32(&id, row->id) || policy_key_get_by_id(dbx_obj, &id))
                return 1;
            ret = policy_key_delete(dbx_obj);
            policy_key_free(dbx_obj);
            return ret;
        case DBW_UPDATE:
            if (db_value_from_int32(&id, row->id) || policy_key_get_by_id(dbx_obj, &id))
                return 1;
            free(dbx_obj->repository);
        case DBW_INSERT: /* fall through intentional */
            {/*pass*/}
    }

    dbx_obj->policy_id.type = DB_TYPE_INT32;
    dbx_obj->policy_id.int32 = policykey->policy->id;
    ods_log_assert(!policykey->policy->dirty);

    dbx_obj->repository          = strdup(policykey->repository);
    dbx_obj->role                = policykey->role;
    dbx_obj->algorithm           = policykey->algorithm;
    dbx_obj->bits                = policykey->bits;
    dbx_obj->lifetime            = policykey->lifetime;
    dbx_obj->standby             = policykey->standby;
    dbx_obj->manual_rollover     = policykey->manual_rollover;
    dbx_obj->rfc5011             = policykey->rfc5011;
    dbx_obj->minimize            = policykey->minimize;

    if (row->dirty == DBW_UPDATE) {
        ods_log_assert(0); /* NOT IMPL! */
        /*ret = policy_key_update(dbx_obj);*/
        ret = 1;
    } else {
        ret = policy_key_create(dbx_obj);
        policykey->id = dbx_obj->dbo->last_row_id;
    }
    policy_key_free(dbx_obj);
    return ret;
}

static int
dbw_zone_update(const db_connection_t *dbconn, struct dbrow *row)
{
    struct db_value id;
    zone_db_t *dbx_obj;
    struct dbw_zone *zone = (struct dbw_zone *)row;
    int ret;

    memset(&id, 0, sizeof (id));
    if (!(dbx_obj = zone_db_new(dbconn))) {
        return 1;
    }

    switch (row->dirty) {
        case DBW_DELETE:
            if (db_value_from_int32(&id, row->id) || zone_db_get_by_id(dbx_obj, &id))
                return 1;
            ret = zone_db_delete(dbx_obj);
            zone_db_free(dbx_obj);
            return ret;
        case DBW_UPDATE:
            if (db_value_from_int32(&id, row->id) || zone_db_get_by_id(dbx_obj, &id))
                return 1;
            free(dbx_obj->name);
            free(dbx_obj->signconf_path);
            free(dbx_obj->input_adapter_uri);
            free(dbx_obj->output_adapter_uri);
        case DBW_INSERT: /* fall through intentional */
            free(dbx_obj->input_adapter_type);
            free(dbx_obj->output_adapter_type);
    }

    dbx_obj->policy_id.type = DB_TYPE_INT32;
    dbx_obj->policy_id.int32 = zone->policy->id;
    ods_log_assert(!zone->policy->dirty);

    dbx_obj->name                           = strdup(zone->name);
    dbx_obj->input_adapter_type             = strdup(zone->input_adapter_type);
    dbx_obj->input_adapter_uri              = strdup(zone->input_adapter_uri);
    dbx_obj->output_adapter_type            = strdup(zone->output_adapter_type);
    dbx_obj->output_adapter_uri             = strdup(zone->output_adapter_uri);
    dbx_obj->signconf_path                  = strdup(zone->signconf_path);
    dbx_obj->next_change                    = zone->next_change;
    dbx_obj->signconf_needs_writing         = zone->signconf_needs_writing;
    dbx_obj->ttl_end_ds                     = zone->ttl_end_ds;
    dbx_obj->ttl_end_dk                     = zone->ttl_end_dk;
    dbx_obj->ttl_end_rs                     = zone->ttl_end_rs;
    dbx_obj->roll_ksk_now                   = zone->roll_ksk_now;
    dbx_obj->roll_zsk_now                   = zone->roll_zsk_now;
    dbx_obj->roll_csk_now                   = zone->roll_csk_now;
    dbx_obj->next_ksk_roll                  = zone->next_ksk_roll;
    dbx_obj->next_zsk_roll                  = zone->next_zsk_roll;
    dbx_obj->next_csk_roll                  = zone->next_csk_roll;

    if (row->dirty == DBW_UPDATE) {
        ret = zone_db_update(dbx_obj);
    } else {
        ret = zone_db_create(dbx_obj);
        zone->id = dbx_obj->dbo->last_row_id;
    }
    zone_db_free(dbx_obj);
    return ret;
}

static int
dbw_key_update(const db_connection_t *dbconn, struct dbrow *row)
{
    struct db_value id;
    key_data_t *dbx_obj;
    struct dbw_key *key = (struct dbw_key *)row;
    int ret;

    memset(&id, 0, sizeof (id));
    if (!(dbx_obj = key_data_new(dbconn))) {
        return 1;
    }

    switch (row->dirty) {
        case DBW_DELETE:
            if (db_value_from_int32(&id, row->id) || key_data_get_by_id(dbx_obj, &id))
                return 1;
            ret = key_data_delete(dbx_obj);
            key_data_free(dbx_obj);
            return ret;
        case DBW_UPDATE:
            if (db_value_from_int32(&id, row->id) || key_data_get_by_id(dbx_obj, &id))
                return 1;
        case DBW_INSERT: /* fall through intentional */
            {/* pass */}
    }

    dbx_obj->zone_id.type = DB_TYPE_INT32;
    dbx_obj->zone_id.int32 = key->zone->id;
    dbx_obj->hsm_key_id.type = DB_TYPE_INT32;
    dbx_obj->hsm_key_id.int32 = key->hsmkey->id;
    ods_log_assert(!key->zone->dirty);
    ods_log_assert(!key->hsmkey->dirty);

    dbx_obj->role                  = key->role;
    dbx_obj->ds_at_parent          = key->ds_at_parent;
    dbx_obj->algorithm             = key->algorithm;
    dbx_obj->inception             = key->inception;
    dbx_obj->introducing           = key->introducing;
    dbx_obj->should_revoke         = key->should_revoke;
    dbx_obj->standby               = key->standby;
    dbx_obj->active_zsk            = key->active_zsk;
    dbx_obj->active_ksk            = key->active_ksk;
    dbx_obj->publish               = key->publish;
    dbx_obj->keytag                = key->keytag;
    dbx_obj->minimize              = key->minimize;

    if (row->dirty == DBW_UPDATE) {
        ret = key_data_update(dbx_obj);
    } else {
        ret = key_data_create(dbx_obj);
        key->id = dbx_obj->dbo->last_row_id;
    }
    key_data_free(dbx_obj);
    return ret;
}

static int
dbw_keystate_update(const db_connection_t *dbconn, struct dbrow *row)
{
    struct db_value id;
    key_state_t *dbx_obj;
    struct dbw_keystate *keystate = (struct dbw_keystate *)row;
    int ret;

    memset(&id, 0, sizeof (id));
    if (!(dbx_obj = key_state_new(dbconn))) {
        return 1;
    }

    switch (row->dirty) {
        case DBW_DELETE:
            if (db_value_from_int32(&id, row->id) || key_state_get_by_id(dbx_obj, &id))
                return 1;
            ret = key_state_delete(dbx_obj);
            key_state_free(dbx_obj);
            return ret;
        case DBW_UPDATE:
            if (db_value_from_int32(&id, row->id) || key_state_get_by_id(dbx_obj, &id))
                return 1;
        case DBW_INSERT: /* fall through intentional */
            {/* pass */}
    }

    dbx_obj->key_data_id.type = DB_TYPE_INT32;
    dbx_obj->key_data_id.int32 = keystate->key->id;
    ods_log_assert(!keystate->key->dirty);

    dbx_obj->type                = keystate->type;
    dbx_obj->state               = keystate->state;
    dbx_obj->last_change         = keystate->last_change;
    dbx_obj->minimize            = keystate->minimize;
    dbx_obj->ttl                 = keystate->ttl;

    if (row->dirty == DBW_UPDATE) {
        ret = key_state_update(dbx_obj);
    } else {
        ret = key_state_create(dbx_obj);
        keystate->id = dbx_obj->dbo->last_row_id;
    }

    key_state_free(dbx_obj);
    return ret;
}

static int
dbw_keydependency_update(const db_connection_t *dbconn, struct dbrow *row)
{
    struct db_value id;
    key_dependency_t *dbx_obj;
    struct dbw_keydependency *keydependency = (struct dbw_keydependency *)row;
    int ret;

    memset(&id, 0, sizeof (id));
    dbx_obj = key_dependency_new(dbconn);
    switch (row->dirty) {
        case DBW_DELETE:
            if (db_value_from_int32(&id, row->id) || key_dependency_get_by_id(dbx_obj, &id))
                return 1;
            ret = key_dependency_delete(dbx_obj);
            key_dependency_free(dbx_obj);
            return ret;
        case DBW_UPDATE:
            if (db_value_from_int32(&id, row->id) || key_dependency_get_by_id(dbx_obj, &id))
                return 1;
            ods_log_assert(0); //Update had never existed.
        case DBW_INSERT: /* fall through intentional */
            {/* pass */}
    }

    dbx_obj->zone_id.type             = DB_TYPE_INT32;
    dbx_obj->zone_id.int32            = keydependency->zone->id;
    ods_log_assert(!keydependency->zone->dirty);

    dbx_obj->from_key_data_id.type    = DB_TYPE_INT32;
    dbx_obj->from_key_data_id.int32   = keydependency->fromkey->id;
    dbx_obj->to_key_data_id.type      = DB_TYPE_INT32;
    dbx_obj->to_key_data_id.int32     = keydependency->tokey->id;
    dbx_obj->type                     = keydependency->type;

    ret = key_dependency_create(dbx_obj);
    keydependency->id = dbx_obj->dbo->last_row_id;
    key_dependency_free(dbx_obj);
    return ret;
}

static int
dbw_hsmkey_update(const db_connection_t *dbconn, struct dbrow *row)
{
    struct db_value id;
    hsm_key_t *dbx_obj;
    struct dbw_hsmkey *hsmkey = (struct dbw_hsmkey *)row;
    int ret;

    memset(&id, 0, sizeof (id));
    if (!(dbx_obj = hsm_key_new(dbconn))) {
        return 1;
    }

    switch (row->dirty) {
        case DBW_DELETE:
            if (db_value_from_int32(&id, row->id) || hsm_key_get_by_id(dbx_obj, &id))
                return 1;
            ret = hsm_key_delete(dbx_obj);
            hsm_key_free(dbx_obj);
            return ret;
        case DBW_UPDATE:
            if (db_value_from_int32(&id, row->id) || hsm_key_get_by_id(dbx_obj, &id))
                return 1;
            free(dbx_obj->locator);
            free(dbx_obj->repository);
        case DBW_INSERT: /* fall through intentional */
            {/* pass */}
    }

    dbx_obj->locator             = strdup(hsmkey->locator);
    dbx_obj->repository          = strdup(hsmkey->repository);

    if (!dbx_obj->locator || !dbx_obj->repository) {
        hsm_key_free(dbx_obj);
        return 1;
    }
    dbx_obj->policy_id.type      = DB_TYPE_INT32;
    dbx_obj->policy_id.int32     = hsmkey->policy->id;
    ods_log_assert(!hsmkey->policy->dirty);

    dbx_obj->state               = hsmkey->state;
    dbx_obj->bits                = hsmkey->bits;
    dbx_obj->algorithm           = hsmkey->algorithm;
    dbx_obj->role                = hsmkey->role;
    dbx_obj->inception           = hsmkey->inception;
    dbx_obj->is_revoked          = hsmkey->is_revoked;
    dbx_obj->key_type            = hsmkey->key_type;
    dbx_obj->backup              = hsmkey->backup;

    int r;
    if (row->dirty == DBW_UPDATE) {
        r = hsm_key_update(dbx_obj);
    } else {
        r = hsm_key_create(dbx_obj);
        hsmkey->id = dbx_obj->dbo->last_row_id;
    }
    hsm_key_free(dbx_obj);
    return r;
}

#define GT(x)   ((x)>0)
#define LTE(x)   ((x)<=0)
/**
 * cmp -,0,+: lt, eq, gt
 */
static void
quicksort(struct dbrow **row, int first, int last,
    int (*cmp)(struct dbrow*, struct dbrow*))
{
    /** not very efficient for already sorted lists! */
    int pivot, j, i;
    struct dbrow *temp;
    if(first >= last) return;
    pivot = i = first;
    j = last;
    while (i < j) {
        while (i < last && LTE(cmp(row[i], row[pivot]))) i++;
        while (GT(cmp(row[j], row[pivot]))) j--;
        if (i < j) {
            temp = row[i];
            row[i] = row[j];
            row[j] = temp;
        }
    }
    temp = row[pivot];
    row[pivot] = row[j];
    row[j] = temp;
    quicksort(row, first, j-1, cmp);
    quicksort(row, j+1, last, cmp);
}
static int cmp_id(struct dbrow *l, struct dbrow *r) { return l->id - r->id; }
static int cmp_int0(struct dbrow *l, struct dbrow *r) { return l->int0 - r->int0; }
static int cmp_int1(struct dbrow *l, struct dbrow *r) { return l->int1 - r->int1; }
static int cmp_int2(struct dbrow *l, struct dbrow *r) { return l->int2 - r->int2; }
static void sort_list(struct dbw_list *list, int (*cmp)(struct dbrow*, struct dbrow*))
{
    quicksort(list->set, 0, list->n-1, cmp);
}
static void sort_list_by_parent_id(struct dbw_list *list, int pidx)
{
    switch (pidx) {
        case 0: sort_list(list, cmp_int0);return;
        case 1: sort_list(list, cmp_int1);return;
        case 2: sort_list(list, cmp_int2);return;
    }
    ods_log_assert(0);
}

static void
sort_by_id(struct dbw_list *list)
{
    quicksort(list->set, 0, list->n-1, cmp_id);
}


static void
get_ref(struct dbrow *r, int ci, int **val, void **ptr)
{
    switch (ci) {
        case 0: 
            *ptr = &r->ptr0;
            *val = &r->int0;
            return;
        case 1:
            *ptr = &r->ptr1;
            *val = &r->int1;
            return;
        case 2:
            *ptr = &r->ptr2;
            *val = &r->int2;
            return;
        case 3:
            *ptr = &r->ptr3;
            *val = &r->int3;
            return;
        case 4:
            *ptr = &r->ptr4;
            *val = &r->int4;
            return;
    }
    ods_log_assert(0);
}
/**
 * left -> right: one to many
 * right -> left: many to one
 * right is now owned by left.
 */
static void
merge(struct dbw_list *parents, int pi, struct dbw_list *children, int ci)
{
    sort_list_by_parent_id(children, ci);
    sort_by_id(parents);
    /* now loop over every parent gobble up every child and point children
     * back to parent */
    size_t np = 0;
    size_t nc = 0;
    while (np < parents->n && nc < children->n) {
        struct dbrow *parent = parents->set[np];
        struct dbrow *child = children->set[nc];

        int *childcount = NULL;
        void **childlist = NULL;
        get_ref(parent, pi, &childcount, (void **)&childlist);
        int *parent_id = NULL;
        void *parentptr = NULL;
        get_ref(child, ci, &parent_id, &parentptr);
        if (parent->id < *parent_id) {
            np++;
            continue;
        } else if (parent->id > *parent_id) {
            /* No parent found for this child. Assert for testing */
            ods_log_assert(0);
            nc++;
            continue;
        }
        /*child matches parent, connect them*/
        /** I sincerely apologise for this code. */
        *(void **)parentptr = parent;
        (*childcount)++;
        *childlist = realloc(*childlist, *childcount * sizeof(struct dbrow *));
        (*(void ***)childlist)[(*childcount) - 1] = child;
        nc++;
    }
}
static void merge_pl_pk(struct dbw_list *l, struct dbw_list *r) { merge(l, 0, r, 0); }
static void merge_pl_hk(struct dbw_list *l, struct dbw_list *r) { merge(l, 1, r, 0); }
static void merge_pl_zn(struct dbw_list *l, struct dbw_list *r) { merge(l, 2, r, 0); }
static void merge_zn_kd(struct dbw_list *l, struct dbw_list *r) { merge(l, 1, r, 0); }
static void merge_kd_ks(struct dbw_list *l, struct dbw_list *r) { merge(l, 2, r, 0); }
static void merge_hk_kd(struct dbw_list *l, struct dbw_list *r) { merge(l, 1, r, 1); }
static void merge_zn_dp(struct dbw_list *l, struct dbw_list *r) { merge(l, 2, r, 0); }
static void merge_kf_dp(struct dbw_list *l, struct dbw_list *r) { merge(l, 3, r, 1); }
static void merge_kt_dp(struct dbw_list *l, struct dbw_list *r) { merge(l, 4, r, 2); }

/**
 *  DBX to DBW conversions
 *
 */

static struct dbw_zone *
zone_dbx_to_dbw(const zone_db_t *dbx_item)
{
    struct dbw_zone *row = calloc(1, sizeof (struct dbw_zone));
    if (!row) return NULL;

    row->id                  = dbxvalue2int(&dbx_item->id);
    row->revision            = dbxvalue2int(&dbx_item->rev);
    row->policy_id           = dbxvalue2int(&dbx_item->policy_id);
    row->policy              = NULL;

    row->name                = strdup(dbx_item->name);
    row->next_change         = (time_t)dbx_item->next_change;
    row->signconf_needs_writing = dbx_item->signconf_needs_writing;
    row->signconf_path       = strdup(dbx_item->signconf_path);
    row->input_adapter_uri   = strdup(dbx_item->input_adapter_uri);
    row->input_adapter_type  = strdup(dbx_item->input_adapter_type);
    row->output_adapter_uri  = strdup(dbx_item->output_adapter_uri);
    row->output_adapter_type = strdup(dbx_item->output_adapter_type);
    row->next_ksk_roll       = dbx_item->next_ksk_roll;
    row->next_zsk_roll       = dbx_item->next_zsk_roll;
    row->next_csk_roll       = dbx_item->next_csk_roll;
    row->ttl_end_ds          = dbx_item->ttl_end_ds;
    row->ttl_end_dk          = dbx_item->ttl_end_dk;
    row->ttl_end_rs          = dbx_item->ttl_end_rs;
    row->roll_ksk_now        = dbx_item->roll_ksk_now;
    row->roll_zsk_now        = dbx_item->roll_zsk_now;
    row->roll_csk_now        = dbx_item->roll_csk_now;

    if (!row->name || !row->signconf_path ||
        !row->input_adapter_uri || !row->input_adapter_type ||
        !row->output_adapter_uri || !row->output_adapter_type)
    {
        free(row->name);
        free(row->signconf_path);
        free(row->input_adapter_uri);
        free(row->input_adapter_type);
        free(row->output_adapter_uri);
        free(row->output_adapter_type);
        free(row);
        return NULL;
    }
    return row;
}

static struct dbw_policykey *
policykey_dbx_to_dbw(const policy_key_t *dbx_item)
{
    struct dbw_policykey *row = calloc(1, sizeof (struct dbw_policykey));
    if (!row) return NULL;

    row->id                             = dbxvalue2int(&dbx_item->id);
    row->revision                       = dbxvalue2int(&dbx_item->rev);
    row->policy_id                      = dbxvalue2int(&dbx_item->policy_id);
    row->policy                         = NULL;

    row->repository                     = strdup(dbx_item->repository);

    if (!row->repository) {
        free(row);
        return NULL;
    }
    row->role                           = dbx_item->role;
    row->algorithm                      = dbx_item->algorithm;
    row->bits                           = dbx_item->bits;
    row->lifetime                       = dbx_item->lifetime;
    row->standby                        = dbx_item->standby;
    row->manual_rollover                = dbx_item->manual_rollover;
    row->rfc5011                        = dbx_item->rfc5011;
    row->minimize                       = dbx_item->minimize;

    return row;
}

static struct dbw_policy *
policy_dbx_to_dbw(const policy_t *dbx_item)
{
    struct dbw_policy *row = calloc(1, sizeof (struct dbw_policy));
    if (!row) return NULL;

    row->id                  = dbxvalue2int(&dbx_item->id);
    row->revision            = dbxvalue2int(&dbx_item->rev);

    row->name                = strdup(dbx_item->name);
    row->description          = strdup(dbx_item->description);
    row->denial_salt          = strdup(dbx_item->denial_salt);

    if (!row->name || !row->description || !row->denial_salt) {
        free(row->name);
        free(row->description);
        free(row->denial_salt);
        free(row);
        return NULL;
    }
    row->passthrough                    = dbx_item->passthrough;
    row->signatures_resign              = dbx_item->signatures_resign;
    row->signatures_refresh             = dbx_item->signatures_refresh;
    row->signatures_jitter              = dbx_item->signatures_jitter;
    row->signatures_inception_offset    = dbx_item->signatures_inception_offset;
    row->signatures_validity_default    = dbx_item->signatures_validity_default;
    row->signatures_validity_denial     = dbx_item->signatures_validity_denial;
    row->signatures_validity_keyset     = dbx_item->signatures_validity_keyset;
    row->signatures_max_zone_ttl        = dbx_item->signatures_max_zone_ttl;
    row->denial_type                    = dbx_item->denial_type;
    row->denial_optout                  = dbx_item->denial_optout;
    row->denial_ttl                     = dbx_item->denial_ttl;
    row->denial_resalt                  = dbx_item->denial_resalt;
    row->denial_algorithm               = dbx_item->denial_algorithm;
    row->denial_iterations              = dbx_item->denial_iterations;
    row->denial_salt_length             = dbx_item->denial_salt_length;
    row->denial_salt_last_change        = dbx_item->denial_salt_last_change;
    row->keys_ttl                       = dbx_item->keys_ttl;
    row->keys_retire_safety             = dbx_item->keys_retire_safety;
    row->keys_publish_safety            = dbx_item->keys_publish_safety;
    row->keys_shared                    = dbx_item->keys_shared;
    row->keys_purge_after               = dbx_item->keys_purge_after;
    row->zone_propagation_delay         = dbx_item->zone_propagation_delay;
    row->zone_soa_ttl                   = dbx_item->zone_soa_ttl;
    row->zone_soa_minimum               = dbx_item->zone_soa_minimum;
    row->zone_soa_serial                = dbx_item->zone_soa_serial;
    row->parent_registration_delay      = dbx_item->parent_registration_delay;
    row->parent_propagation_delay       = dbx_item->parent_propagation_delay;
    row->parent_ds_ttl                  = dbx_item->parent_ds_ttl;
    row->parent_soa_ttl                 = dbx_item->parent_soa_ttl;
    row->parent_soa_minimum             = dbx_item->parent_soa_minimum;
    return row;
}

static struct dbw_key *
key_dbx_to_dbw(const key_data_t *dbx_item)
{
    struct dbw_key *row = calloc(1, sizeof (struct dbw_key));
    if (!row) return NULL;

    row->id                  = dbxvalue2int(&dbx_item->id);
    row->revision            = dbxvalue2int(&dbx_item->rev);
    row->zone_id             = dbxvalue2int(&dbx_item->zone_id);
    row->zone                = NULL;
    row->hsmkey_id           = dbxvalue2int(&dbx_item->hsm_key_id);
    row->hsmkey              = NULL;

    row->role                = dbx_item->role;
    row->ds_at_parent        = dbx_item->ds_at_parent;
    row->algorithm           = dbx_item->algorithm;
    row->inception           = dbx_item->inception;
    row->introducing         = dbx_item->introducing;
    row->should_revoke       = dbx_item->should_revoke;
    row->standby             = dbx_item->standby;
    row->active_zsk          = dbx_item->active_zsk;
    row->active_ksk          = dbx_item->active_ksk;
    row->publish             = dbx_item->publish;
    row->keytag              = dbx_item->keytag;
    row->minimize            = dbx_item->minimize;
    return row;
}

static struct dbw_keystate *
keystate_dbx_to_dbw(const key_state_t *dbx_item)
{
    struct dbw_keystate *row = calloc(1, sizeof (struct dbw_keystate));
    if (!row) return NULL;

    row->id                  = dbxvalue2int(&dbx_item->id);
    row->revision            = dbxvalue2int(&dbx_item->rev);
    row->key_id              = dbxvalue2int(&dbx_item->key_data_id);
    row->key                 = NULL;

    row->type                = dbx_item->type;
    row->state               = dbx_item->state;
    row->last_change         = dbx_item->last_change;
    row->minimize            = dbx_item->minimize;
    row->ttl                 = dbx_item->ttl;
    return row;
}

static struct dbw_keydependency *
keydependency_dbx_to_dbw(const key_dependency_t *dbx_item)
{
    struct dbw_keydependency *row = calloc(1, sizeof (struct dbw_keydependency));
    if (!row) return NULL;

    row->id                  = dbxvalue2int(&dbx_item->id);
    row->revision            = dbxvalue2int(&dbx_item->rev);
    row->zone_id             = dbxvalue2int(&dbx_item->zone_id);
    row->zone                = NULL;
    row->fromkey_id          = dbxvalue2int(&dbx_item->from_key_data_id);
    row->fromkey             = NULL;
    row->tokey_id            = dbxvalue2int(&dbx_item->to_key_data_id);
    row->tokey               = NULL;

    row->type                = dbx_item->type;
    return row;
}

static struct dbw_hsmkey *
hsmkey_dbx_to_dbw(const hsm_key_t *dbx_item)
{
    struct dbw_hsmkey *row = calloc(1, sizeof (struct dbw_hsmkey));
    if (!row) return NULL;

    row->id                  = dbxvalue2int(&dbx_item->id);
    row->revision            = dbxvalue2int(&dbx_item->rev);
    row->policy_id           = dbxvalue2int(&dbx_item->policy_id);
    row->policy              = NULL;
    
    row->locator             = strdup(dbx_item->locator);
    row->repository          = strdup(dbx_item->repository);

    if (!row->locator || !row->repository) {
        free(row->locator);
        free(row->repository);
        free(row);
        return NULL;
    }
    row->state               = dbx_item->state;
    row->bits                = dbx_item->bits;
    row->algorithm           = dbx_item->algorithm;
    row->role                = dbx_item->role;
    row->inception           = dbx_item->inception;
    row->is_revoked          = dbx_item->is_revoked;
    row->key_type            = dbx_item->key_type;
    row->backup              = dbx_item->backup;
    return row;
}

/**
 *  BASIC FETCHES
 *
 */

static struct dbw_list *
dbw_zones(db_connection_t *dbconn, int fetch)
{
    zone_list_db_t* dbx_list = NULL;
    size_t n = 0;
    if (fetch) {
        dbx_list = zone_list_db_new_get(dbconn);
        if (!dbx_list) return NULL;
        n = zone_list_db_size(dbx_list);
    }
    struct dbw_list *list = calloc(1, sizeof (struct dbw_list));
    if (!list) {
        zone_list_db_free(dbx_list);
        return NULL;
    }
    list->free = dbw_zone_free;
    list->update = dbw_zone_update;
    list->revision = dbw_zone_revision;
    if (fetch) {
        list->set = calloc(n, sizeof (struct dbw_zone *));
        if (!list->set) {
            dbw_list_free(list);
            zone_list_db_free(dbx_list);
            return NULL;
        }
        const zone_db_t* dbx_item;
        while ((dbx_item = zone_list_db_next(dbx_list)) != NULL && list->n < n) {
            struct dbrow *row = (struct dbrow *)zone_dbx_to_dbw(dbx_item);
            if (!row) {
                dbw_list_free(list);
                zone_list_db_free(dbx_list);
                return NULL;
            }
            list->set[list->n++] = row;
        }
        zone_list_db_free(dbx_list);
    }
    return list;
}

static struct dbw_list *
dbw_keys(db_connection_t *dbconn, int fetch)
{
    key_data_list_t* dbx_list = NULL;
    size_t n = 0;
    if (fetch) {
        dbx_list = key_data_list_new_get(dbconn);
        if (!dbx_list) return NULL;
        n = key_data_list_size(dbx_list);
    }
    struct dbw_list *list = calloc(1, sizeof (struct dbw_list));
    if (!list) {
        key_data_list_free(dbx_list);
        return NULL;
    }
    list->free = dbw_key_free;
    list->update = dbw_key_update;
    list->revision = dbw_key_revision;
    if (fetch) {
        list->set = calloc(n, sizeof (struct dbw_key *));
        if (!list->set) {
            dbw_list_free(list);
            key_data_list_free(dbx_list);
            return NULL;
        }
        const key_data_t* dbx_item;
        while ((dbx_item = key_data_list_next(dbx_list)) != NULL && list->n < n) {
            struct dbrow *row = (struct dbrow *)key_dbx_to_dbw(dbx_item);
            if (!row) {
                dbw_list_free(list);
                key_data_list_free(dbx_list);
                return NULL;
            }
            list->set[list->n++] = row;
        }
        key_data_list_free(dbx_list);
    }
    return list;
}

static struct dbw_list *
dbw_keystates(db_connection_t *dbconn, int fetch)
{
    key_state_list_t* dbx_list = NULL;
    size_t n = 0;
    if (fetch) {
        dbx_list = key_state_list_new_get(dbconn);
        if (!dbx_list) return NULL;
        n = key_state_list_size(dbx_list);
    }
    struct dbw_list *list = calloc(1, sizeof (struct dbw_list));
    if (!list) {
        key_state_list_free(dbx_list);
        return NULL;
    }
    list->free = dbw_keystate_free;
    list->update = dbw_keystate_update;
    list->revision = dbw_keystate_revision;
    if (fetch) {
        list->set = calloc(n, sizeof (struct dbw_keystate *));
        if (!list->set) {
            dbw_list_free(list);
            key_state_list_free(dbx_list);
            return NULL;
        }
        const key_state_t* dbx_item;
        while ((dbx_item = key_state_list_next(dbx_list)) != NULL && list->n < n) {
            struct dbrow *row = (struct dbrow *)keystate_dbx_to_dbw(dbx_item);
            if (!row) {
                dbw_list_free(list);
                key_state_list_free(dbx_list);
                return NULL;
            }
            list->set[list->n++] = row;
        }
        key_state_list_free(dbx_list);
    }
    return list;
}

static struct dbw_list *
dbw_keydependencies(db_connection_t *dbconn, int fetch)
{
    key_dependency_list_t* dbx_list = NULL;
    size_t n = 0;
    if (fetch) {
        dbx_list = key_dependency_list_new_get(dbconn);
        if (!dbx_list) return NULL;
        n = key_dependency_list_size(dbx_list);
    }
    struct dbw_list *list = calloc(1, sizeof (struct dbw_list));
    if (!list) {
        key_dependency_list_free(dbx_list);
        return NULL;
    }
    list->free = dbw_keydependency_free;
    list->update = dbw_keydependency_update;
    list->revision = dbw_keydependency_revision;
    if (fetch) {
    list->set = calloc(n, sizeof (struct dbw_keydependency *));
        if (!list->set) {
            dbw_list_free(list);
            key_dependency_list_free(dbx_list);
            return NULL;
        }
        const key_dependency_t* dbx_item;
        while ((dbx_item = key_dependency_list_next(dbx_list)) != NULL && list->n < n) {
            struct dbrow *row = (struct dbrow *)keydependency_dbx_to_dbw(dbx_item);
            if (!row) {
                dbw_list_free(list);
                key_dependency_list_free(dbx_list);
                return NULL;
            }
            list->set[list->n++] = row;
        }
        key_dependency_list_free(dbx_list);
    }
    return list;
}

static struct dbw_list *
dbw_hsmkeys(db_connection_t *dbconn, int fetch)
{
    hsm_key_list_t* dbx_list = NULL;
    size_t n = 0;
    if (fetch) {
        dbx_list = hsm_key_list_new_get(dbconn);
        if (!dbx_list) return NULL;
        n = hsm_key_list_size(dbx_list);
    }
    struct dbw_list *list = calloc(1, sizeof (struct dbw_list));
    if (!list) {
        hsm_key_list_free(dbx_list);
        return NULL;
    }
    list->free = dbw_hsmkey_free;
    list->update = dbw_hsmkey_update;
    list->revision = dbw_hsmkey_revision;
    if (fetch) {
        list->set = calloc(n, sizeof (struct dbw_hsmkey *));
        if (!list->set) {
            dbw_list_free(list);
            hsm_key_list_free(dbx_list);
            return NULL;
        }
        const hsm_key_t* dbx_item;
        while ((dbx_item = hsm_key_list_next(dbx_list)) != NULL && list->n < n) {
            struct dbrow *row = (struct dbrow *)hsmkey_dbx_to_dbw(dbx_item);
            if (!row) {
                dbw_list_free(list);
                hsm_key_list_free(dbx_list);
                return NULL;
            }
            list->set[list->n++] = row;
        }
        hsm_key_list_free(dbx_list);
    }
    return list;
}


static struct dbw_list *
dbw_policies(db_connection_t *dbconn, int fetch)
{
    policy_list_t* dbx_list = NULL;
    size_t n = 0;
    if (fetch) {
        dbx_list = policy_list_new_get(dbconn);
        if (!dbx_list) return NULL;
        n = policy_list_size(dbx_list);
    }
    struct dbw_list *list = calloc(1, sizeof (struct dbw_list));
    if (!list) {
        policy_list_free(dbx_list);
        return NULL;
    }
    list->free = dbw_policy_free;
    list->update = dbw_policy_update;
    list->revision = dbw_policy_revision;
    if (fetch) {
        list->set = calloc(n, sizeof (struct dbw_policy *));
        if (!list->set) {
            dbw_list_free(list);
            policy_list_free(dbx_list);
            return NULL;
        }
        const policy_t* dbx_item;
        while ((dbx_item = policy_list_next(dbx_list)) != NULL && list->n < n) {
            struct dbrow *row = (struct dbrow *)policy_dbx_to_dbw(dbx_item);
            if (!row) {
                dbw_list_free(list);
                policy_list_free(dbx_list);
                return NULL;
            }
            list->set[list->n++] = row;
        }
        policy_list_free(dbx_list);
    }
    return list;
}

static struct dbw_list *
dbw_policykeys(db_connection_t *dbconn, int fetch)
{
    policy_key_list_t* dbx_list = NULL;
    size_t n = 0;
    if (fetch) {
        dbx_list = policy_key_list_new_get(dbconn);
        if (!dbx_list) return NULL;
        n = policy_key_list_size(dbx_list);
    }
    struct dbw_list *list = calloc(1, sizeof (struct dbw_list));
    if (!list) {
        policy_key_list_free(dbx_list);
        return NULL;
    }
    list->free = dbw_policykey_free;
    list->update = dbw_policykey_update;
    list->revision = dbw_policykey_revision;
    if (fetch) {
        list->set = calloc(n, sizeof (struct dbw_policykey *));
        if (!list->set) {
            dbw_list_free(list);
            policy_key_list_free(dbx_list);
            return NULL;
        }
        const policy_key_t* dbx_item;
        while ((dbx_item = policy_key_list_next(dbx_list)) != NULL && list->n < n) {
            struct dbrow *row = (struct dbrow *)policykey_dbx_to_dbw(dbx_item);
            if (!row) {
                dbw_list_free(list);
                policy_key_list_free(dbx_list);
                return NULL;
            }
            list->set[list->n++] = row;
        }
        policy_key_list_free(dbx_list);
    }
    return list;
}

void
dbw_free(struct dbw_db *db)
{
    dbw_list_free(db->policies);
    dbw_list_free(db->zones);
    dbw_list_free(db->keys);
    dbw_list_free(db->keystates);
    dbw_list_free(db->hsmkeys);
    dbw_list_free(db->policykeys);
    dbw_list_free(db->keydependencies);
    free(db);
}

struct dbw_db *
dbw_fetch_filtered(db_connection_t *conn, int mask)
{
    struct dbw_db *db = calloc(1, sizeof(struct dbw_db));
    if (!db) {
        ods_log_error("[dbw_fetch] Memory allocation failure.");
        return NULL;
    }

    if (pthread_rwlock_rdlock(&db_lock)) {
        ods_log_error("[dbw_fetch] Unable to obtain database read lock.");
        free(db);
        return NULL;
    }
    db->conn            = conn;
    db->policies        = dbw_policies(conn, mask&DBW_F_POLICY);
    db->zones           = dbw_zones(conn, mask&DBW_F_ZONE);
    db->keys            = dbw_keys(conn, mask&DBW_F_KEY);
    db->keystates       = dbw_keystates(conn, mask&DBW_F_KEYSTATE);
    db->hsmkeys         = dbw_hsmkeys(conn, mask&DBW_F_HSMKEY);
    db->policykeys      = dbw_policykeys(conn, mask&DBW_F_POLICYKEY);
    db->keydependencies = dbw_keydependencies(conn, mask&DBW_F_KEYDEPENDENCY);
    (void)pthread_rwlock_unlock(&db_lock);

    if (!db->policies || !db->zones || !db->keys || !db->keystates ||
            !db->hsmkeys || !db->policykeys || !db->keydependencies)
    {
        dbw_free(db);
        ods_log_error("[dbw_fetch] Failed to read from database.");
        return NULL;
    }
    merge_pl_pk(db->policies, db->policykeys);
    merge_pl_hk(db->policies, db->hsmkeys);
    merge_pl_zn(db->policies, db->zones);
    merge_zn_kd(db->zones,    db->keys);
    merge_kd_ks(db->keys,     db->keystates);
    merge_hk_kd(db->hsmkeys,  db->keys);
    merge_zn_dp(db->zones,    db->keydependencies);
    merge_kt_dp(db->keys,     db->keydependencies);
    merge_kf_dp(db->keys,     db->keydependencies);
    return db;
}

struct dbw_db *
dbw_fetch(db_connection_t *conn)
{
    return dbw_fetch_filtered(conn, DBW_F_ALL);
}

static int
dbw_commit_list(const db_connection_t *conn, struct dbw_list *list)
{
    for (size_t i = 0; i < list->n; i++) {
        struct dbrow *row = list->set[i];
        if (!row->dirty) continue;
        int r = list->update(conn, row);
        if (r) return r;
        /* TODO: if successful, DELETED rows will be clean and dbw_db
         * structure will not be safe to reuse. We should remove these items
         * completely (see lookahead_cmd.c) */
        row->dirty = DBW_CLEAN;
    }
    return 0;
}

static int
dbw_verify_list_revisions(const db_connection_t *conn, struct dbw_list *list)
{
    struct db_value id;
    memset(&id, 0, sizeof(struct db_value));
    id.type = DB_TYPE_INT64;
    for (size_t i = 0; i < list->n; i++) {
        struct dbrow *row = list->set[i];
        if (row->dirty != DBW_UPDATE) continue;
        id.int64 = row->id;
        if (list->revision(conn, &id) != row->revision) {
            ods_log_debug("[dbw_verify_revisions] collision detected on id %d", row->id);
            return 1;
        }
    }
    return 0;
}


static int
dbw_verify_revisions(struct dbw_db *db)
{
    int r = 0;
    ods_log_debug("[dbw_verify_revisions] verifying policies");
    r |= dbw_verify_list_revisions(db->conn, db->policies);
    ods_log_debug("[dbw_verify_revisions] verifying policykeys");
    r |= dbw_verify_list_revisions(db->conn, db->policykeys);
    ods_log_debug("[dbw_verify_revisions] verifying zones");
    r |= dbw_verify_list_revisions(db->conn, db->zones);
    ods_log_debug("[dbw_verify_revisions] verifying hsmkeys");
    r |= dbw_verify_list_revisions(db->conn, db->hsmkeys);
    ods_log_debug("[dbw_verify_revisions] verifying keys");
    r |= dbw_verify_list_revisions(db->conn, db->keys);
    ods_log_debug("[dbw_verify_revisions] verifying keystates");
    r |= dbw_verify_list_revisions(db->conn, db->keystates);
    ods_log_debug("[dbw_verify_revisions] verifying keydependencies");
    r |= dbw_verify_list_revisions(db->conn, db->keydependencies);
    return r;
}

int
dbw_commit(struct dbw_db *db)
{
    if (pthread_rwlock_wrlock(&db_lock)) {
        ods_log_error("[dbw_commit] Unable to obtain database write lock.");
        return 1;
    }
    if (dbw_verify_revisions(db)) {
        ods_log_error("[dbw_commit] Some records are stale, can't commit to database.");
        (void)pthread_rwlock_unlock(&db_lock);
        return 1;
    }
    int r = 0;
    r |= dbw_commit_list(db->conn, db->policies);
    r |= dbw_commit_list(db->conn, db->policykeys);
    r |= dbw_commit_list(db->conn, db->zones);
    r |= dbw_commit_list(db->conn, db->hsmkeys);
    r |= dbw_commit_list(db->conn, db->keys);
    r |= dbw_commit_list(db->conn, db->keystates);
    r |= dbw_commit_list(db->conn, db->keydependencies);
    (void)pthread_rwlock_unlock(&db_lock);
    return r;
}

struct dbw_zone *
dbw_get_zone(struct dbw_db *db, char const *zonename)
{
    struct dbw_list *list = db->zones;
    for (size_t n = 0; n < list->n; n++) {
        struct dbw_zone *zone = (struct dbw_zone *)list->set[n];
        if (!strcmp(zone->name, zonename)) return zone;
    }
    return NULL;
}

struct dbw_policy *
dbw_get_policy(struct dbw_db *db, char const *policyname)
{
    struct dbw_list *list = db->policies;
    for (size_t n = 0; n < list->n; n++) {
        struct dbw_policy *policy = (struct dbw_policy *)list->set[n];
        if (!strcmp(policy->name, policyname)) return policy;
    }
    return NULL;
}

struct dbw_policykey *
dbw_get_policykey(struct dbw_db *db, int id)
{
    struct dbw_list *list = db->policykeys;
    for (size_t n = 0; n < list->n; n++) {
        struct dbw_policykey *policykey = (struct dbw_policykey *)list->set[n];
        if (id == policykey->id) return policykey;
    }
    return NULL;
}


struct dbw_keystate *
dbw_get_keystate(struct dbw_key *key, int type)
{
    for (size_t n = 0; n < key->keystate_count; n++) {
        if (key->keystate[n]->type == type)
            return key->keystate[n];
    }
    return NULL;
}

struct dbw_hsmkey *
dbw_get_hsmkey(struct dbw_db *db, char const *locator)
{
    struct dbw_list *list = db->hsmkeys;
    for (size_t n = 0; n < list->n; n++) {
        struct dbw_hsmkey *hsmkey = (struct dbw_hsmkey *)list->set[n];
        if (!strcmp(locator, hsmkey->locator)) return hsmkey;
    }
    return NULL;
}

/* Add object to array */
static int
append(void ***array, int *count, void *obj)
{
    int c = (*count) + 1;
    void **new = realloc((*array), c * sizeof(void *));
    if (!new) return 1;
    new[*count] = obj;
    (*array) = new;
    (*count) = c;
    return 0;
}

static int
list_add(struct dbw_list *list, struct dbrow *row)
{
    size_t c = list->n + 1;
    struct dbrow **new = realloc(list->set, c * sizeof(struct dbrow *));
    if (!new) return 1;
    new[list->n] = row;
    list->set = new;
    list->n = c;
    return 0;
}

int
dbw_add_keystate(struct dbw_db *db, struct dbw_key *key, struct dbw_keystate *keystate)
{
    int r = 0;
    /*link key to keystate*/
    keystate->key = key;
    /*link keystate to key*/
    r |= append((void ***)&key->keystate, &key->keystate_count, keystate);
    /*link keystate to db*/
    r |= list_add(db->keystates, (struct dbrow *)keystate);
    keystate->dirty = DBW_INSERT;
    return r;
}

int
dbw_add_zone(struct dbw_db *db, struct dbw_policy *policy, struct dbw_zone *zone)
{
    int r = 0;
    zone->policy = policy;
    r |= append((void ***)&policy->zone, &policy->zone_count, zone);
    r |= list_add(db->zones, (struct dbrow *)zone);
    zone->dirty = DBW_INSERT;
    return r;
}

int
dbw_add_hsmkey(struct dbw_db *db, struct dbw_policy *policy, struct dbw_hsmkey *hsmkey)
{
    int r = 0;
    hsmkey->policy = policy;
    r |= append((void ***)&policy->hsmkey, &policy->hsmkey_count, hsmkey);
    r |= list_add(db->hsmkeys, (struct dbrow *)hsmkey);
    hsmkey->dirty = DBW_INSERT;
    return r;
}

struct dbw_keydependency *
dbw_new_keydependency(struct dbw_db *db, struct dbw_key *fromkey, 
    struct dbw_key *tokey, int type, struct dbw_zone *zone)
{
    struct dbw_keydependency *dep = calloc(1, sizeof (struct dbw_keydependency));
    if (!dep) return NULL;
    dep->tokey = tokey;
    dep->tokey_id = tokey->id;
    dep->fromkey = fromkey;
    dep->fromkey_id = fromkey->id;
    dep->zone = zone;
    dep->zone_id = zone->id;
    dep->type = type;

    int r = 0;
    r |= list_add(db->keydependencies, (struct dbrow *)dep);
    r |= append((void ***)&zone->keydependency, &zone->keydependency_count, dep);
    r |= append((void ***)&fromkey->from_keydependency, &fromkey->from_keydependency_count, dep);
    r |= append((void ***)&tokey->to_keydependency, &tokey->to_keydependency_count, dep);
    /* TODO handle errors */
    dep->dirty = DBW_INSERT;
    return dep;
}

struct dbw_key*
dbw_new_key(struct dbw_db *db, struct dbw_zone *zone, struct dbw_hsmkey *hsmkey)
{
    struct dbw_key *key = calloc(1, sizeof (struct dbw_key));
    if (!key) return NULL;
    key->zone = zone;
    key->zone_id = zone->id;
    key->hsmkey = hsmkey;
    key->hsmkey_id = hsmkey->id;
    key->keystate_count = 0;
    key->keystate = NULL;

    int r = 0;
    r |= list_add(db->keys, (struct dbrow *)key);
    r |= append((void ***)&zone->key, &zone->key_count, key);
    r |= append((void ***)&hsmkey->key, &hsmkey->key_count, key);
    /* TODO handle errors */
    key->dirty = DBW_INSERT;
    return key;
}

struct dbw_keystate*
dbw_new_keystate(struct dbw_db *db, struct dbw_zone *zone, struct dbw_key *key)
{
    struct dbw_keystate *keystate = calloc(1, sizeof (struct dbw_keystate));
    if (!keystate) return NULL;
    keystate->key = key;
    keystate->key_id = key->id;

    int r = 0;
    r |= list_add(db->keystates, (struct dbrow *)keystate);
    r |= append((void ***)&key->keystate, &key->keystate_count, keystate);
    /* TODO handle errors */
    keystate->dirty = DBW_INSERT;
    return keystate;
}

struct dbw_hsmkey*
dbw_new_hsmkey(struct dbw_db *db, struct dbw_policy *policy)
{
    struct dbw_hsmkey *hsmkey = calloc(1, sizeof (struct dbw_hsmkey));
    if (!hsmkey) return NULL;
    hsmkey->policy = policy;
    hsmkey->policy_id = policy->id;
    hsmkey->key_count = 0;
    hsmkey->key = NULL;

    int r = 0;
    r |= list_add(db->hsmkeys, (struct dbrow *)hsmkey);
    r |= append((void ***)&policy->hsmkey, &policy->hsmkey_count, hsmkey);
    /* TODO handle errors */
    hsmkey->dirty = DBW_INSERT;
    return hsmkey;
}

struct dbw_policykey*
dbw_new_policykey(struct dbw_db *db, struct dbw_policy *policy)
{
    struct dbw_policykey *policykey = calloc(1, sizeof (struct dbw_policykey));
    if (!policykey) return NULL;
    policykey->policy = policy;
    policykey->policy_id = policy->id;

    int r = 0;
    r |= list_add(db->policykeys, (struct dbrow *)policykey);
    r |= append((void ***)&policy->policykey, &policy->policykey_count, policykey);
    /* TODO handle errors */
    policykey->dirty = DBW_INSERT;
    return policykey;
}

struct dbw_policy*
dbw_new_policy(struct dbw_db *db)
{
    struct dbw_policy *policy = calloc(1, sizeof (struct dbw_policy));
    if (!policy) return NULL;

    int r = 0;
    r |= list_add(db->policies, (struct dbrow *)policy);
    /* TODO handle errors */
    policy->dirty = DBW_INSERT;
    return policy;
}

int
dbw_zone_exists(db_connection_t *dbconn, char const *zonename)
{
    zone_db_t *zone = zone_db_new_get_by_name(dbconn, zonename);
    zone_db_free(zone);
    return zone != NULL;
}

void
dbw_mark_dirty(struct dbrow *row)
{
    /* If a record is marked UPDATE or DELETE don't overwrite. */
    if (row->dirty == DBW_CLEAN)
        row->dirty = DBW_UPDATE;
}

/* Summary for debugging purposes */
/*void*/
/*dbw_dump_db(struct dbw_db *db)*/
/*{*/
    /*for (size_t p = 0; p < db->policies->n; p++) {*/
        /*struct dbw_policy *policy = (struct dbw_policy *)db->policies->set[p];*/
        /*printf("policy %d, pkc: %d, hkc: %d, zc: %d\n", policy->id,*/
            /*policy->policykey_count, policy->hsmkey_count, policy->zone_count);*/
        /*for (size_t pk = 0; pk < policy->policykey_count; pk++) {*/
            /*struct dbw_policykey *policykey = policy->policykey[pk];*/
            /*printf("\tpolicykey: %d\n", policykey->id);*/
        /*}*/
        /*for (size_t z = 0; z < policy->zone_count; z++) {*/
            /*struct dbw_zone *zone = policy->zone[z];*/
            /*printf("\tzone: %d, kc: %d, kdc: %d\n", zone->id, zone->key_count,*/
                /*zone->keydependency_count);*/
            /*for (size_t k = 0; k < zone->key_count; k++) {*/
                /*struct dbw_key *key = zone->key[k];*/
                /*printf("\t\tkey: %d, ksc: %d, kdfc: %d, kdtc: %d\n", key->id,*/
                    /*key->keystate_count, key->from_keydependency_count,*/
                    /*key->to_keydependency_count);*/
            /*}*/
        /*}*/
    /*}*/
/*}*/
