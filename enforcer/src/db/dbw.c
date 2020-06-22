#include <string.h>
#include <pthread.h>
#include <stdlib.h>

#include "config.h"

#include "log.h"
#include "db/dbw.h"

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

void
dbw_free(struct dbw_db *db)
{
}

struct dbw_db *
dbw_fetch(db_connection_t *conn, ...)
{
    return NULL;
}

int
dbw_commit(struct dbw_db *db)
{
    if (pthread_rwlock_wrlock(&db_lock)) {
        ods_log_error("[dbw_commit] Unable to obtain database write lock.");
        return 1;
    }
    // commit
    (void)pthread_rwlock_unlock(&db_lock);
    return 0;
}

void
dbw_mark_dirty(void *obj)
{
}

db_connection_t*
db_connection_new(const char* database, const char* hostname, const char*username, const char*password)
{
    return 0;
}

int
db_connection_free(db_connection_t*conn)
{
    return 0;
}

int
database_version_get_version(db_connection_t* connection)
{
    return 1;
}

int dbw_object_fetch_(void* resultdata, int* resultcount, int fetchplan, const char* fetchname, ...)
{
    return 0;
}

void dbw_add(void*array,int*count,void*item)
{
    void** newarray;
    newarray = realloc(array, sizeof(void*)*(*count+1));
    newarray[*count] = item;
    ++(*count);
}
