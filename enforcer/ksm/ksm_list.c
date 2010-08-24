/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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
 *
 */

/*
 * ksm_list.c - List various aspects of the current configuration
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ksm/database.h"
#include "ksm/database_statement.h"
#include "ksm/datetime.h"
#include "ksm/db_fields.h"
#include "ksm/debug.h"
#include "ksm/ksmdef.h"
#include "ksm/ksm.h"
#include "ksm/ksm_internal.h"
#include "ksm/message.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"

/*+
 * KsmListBackups - Output a list of all backups perfomed
 *
 *
 * Arguments:
 *
 *      int repo_id
 *          ID of the repository (-1 for all)
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int KsmListBackups(int repo_id)
{
    char*       sql = NULL;     /* SQL query */
    char*       sql2 = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    char        stringval[KSM_INT_STR_SIZE];  /* For Integer to String conversion */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */
    DB_RESULT	result2;         /* Result of the query */
    DB_ROW      row2 = NULL;     /* Row data */

    char*       temp_date = NULL; /* place to store date returned */
    char*       temp_pre_date = NULL; /* place to store pre-backup date returned */
    char*       temp_repo = NULL; /* place to store repository returned */
    int         temp_backup_req = 0; /* place to store backuprequired returned */

    /* Select rows */
    StrAppend(&sql, "select distinct k.backup, s.name from keypairs k, securitymodules s ");
    StrAppend(&sql, "where s.id = k.securitymodule_id ");
    if (repo_id != -1) {
        StrAppend(&sql, "and s.id = ");
        snprintf(stringval, KSM_INT_STR_SIZE, "%d", repo_id);
        StrAppend(&sql, stringval);
    }
    StrAppend(&sql, " order by backup");

    DusEnd(&sql);

    status = DbExecuteSql(DbHandle(), sql, &result);

    if (status == 0) {
        status = DbFetchRow(result, &row);
        printf("Date:                    Repository:\n");
        while (status == 0) {
            /* Got a row, print it */
            DbString(row, 0, &temp_date);
            DbString(row, 1, &temp_repo);

            if (temp_date != NULL) { /* Ignore non-backup */
                printf("%-24s %s\n", temp_date, temp_repo);
            }
            
            status = DbFetchRow(result, &row);
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result);
    }

    DusFree(sql);
    DbFreeRow(row);
    DbStringFree(temp_date);

    /* List repos which need a backup */
    StrAppend(&sql2, "select s.name, s.requirebackup from keypairs k, securitymodules s ");
    StrAppend(&sql2, "where s.id = k.securitymodule_id ");
    if (repo_id != -1) {
        StrAppend(&sql2, "and s.id = ");
        snprintf(stringval, KSM_INT_STR_SIZE, "%d", repo_id);
        StrAppend(&sql2, stringval);
    }
    StrAppend(&sql2, " and k.backup is null");
    StrAppend(&sql2, " group by s.name order by s.name");

    DusEnd(&sql2);

    status = DbExecuteSql(DbHandle(), sql2, &result2);

    if (status == 0) {
        status = DbFetchRow(result2, &row2);
        while (status == 0) {
            /* Got a row, print it */
            DbString(row2, 0, &temp_repo);
            DbInt(row2, 1, &temp_backup_req);

            if (temp_backup_req == 0) {
                printf("Repository %s has unbacked up keys (that can be used)\n", temp_repo);
            } else {
                printf("Repository %s has unbacked up keys (that will not be used)\n", temp_repo);
            }
            
            status = DbFetchRow(result2, &row2);
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result2);
    }

    DusFree(sql2);
    DbFreeRow(row2);
    DbStringFree(temp_repo);

    /* List repos which need a backup commit */
    sql2 = NULL;
    StrAppend(&sql2, "select s.name from keypairs k, securitymodules s ");
    StrAppend(&sql2, "where s.id = k.securitymodule_id ");
    if (repo_id != -1) {
        StrAppend(&sql2, "and s.id = ");
        snprintf(stringval, KSM_INT_STR_SIZE, "%d", repo_id);
        StrAppend(&sql2, stringval);
    }
    StrAppend(&sql2, " and k.backup is null");
    StrAppend(&sql2, " and k.pre_backup is not null");
    StrAppend(&sql2, " group by s.name order by s.name");

    DusEnd(&sql2);

    status = DbExecuteSql(DbHandle(), sql2, &result2);

    if (status == 0) {
        status = DbFetchRow(result2, &row2);
        while (status == 0) {
            /* Got a row, print it */
            DbString(row2, 0, &temp_repo);

            printf("Repository %s has keys prepared for back up which have not been committed\n", temp_repo);
            
            status = DbFetchRow(result2, &row2);
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result2);
    }

    DusFree(sql2);
    DbFreeRow(row2);
    DbStringFree(temp_repo);

    return status;
}

/*+
 * KsmListRepos - Output a list of all repositories available
 *
 *
 * Arguments:
 *
 *      none
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int KsmListRepos()
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */

    char*       temp_name = NULL;   /* place to store name returned */
    char*       temp_cap = NULL;    /* place to store capacity returned */
    int         temp_back = 0;      /* place to store backup flag returned */

    /* Select rows */
    StrAppend(&sql, "select name, capacity, requirebackup from securitymodules ");
    StrAppend(&sql, "order by name");

    DusEnd(&sql);

    status = DbExecuteSql(DbHandle(), sql, &result);

    if (status == 0) {
        status = DbFetchRow(result, &row);
        printf("Name:                            Capacity:    RequireBackup:\n");
        while (status == 0) {
            /* Got a row, print it */
            DbString(row, 0, &temp_name);
            DbString(row, 1, &temp_cap);
            DbInt(row, 2, &temp_back);

            printf("%-32s %-12s %s\n", temp_name, (strlen(temp_cap) == 0) ? "unset" : temp_cap, (temp_back == 0) ? "No" : "Yes");
            
            status = DbFetchRow(result, &row);
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result);
    }

    DusFree(sql);
    DbFreeRow(row);
    DbStringFree(temp_name);
    DbStringFree(temp_cap);

    return status;
}

/*+
 * KsmListPolicies - Output a list of all policies available
 *
 *
 * Arguments:
 *
 *      none
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int KsmListPolicies()
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */

    char*       temp_name = NULL;   /* place to store name returned */
    char*       temp_desc = NULL;   /* place to store description returned */

    /* Select rows */
    StrAppend(&sql, "select name, description from policies ");
    StrAppend(&sql, "order by name");

    DusEnd(&sql);

    status = DbExecuteSql(DbHandle(), sql, &result);

    if (status == 0) {
        status = DbFetchRow(result, &row);
        printf("Name:                            Description:\n");
        while (status == 0) {
            /* Got a row, print it */
            DbString(row, 0, &temp_name);
            DbString(row, 1, &temp_desc);

            printf("%-32s %s\n", temp_name, (strlen(temp_desc) == 0) ? "unset" : temp_desc);
            
            status = DbFetchRow(result, &row);
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result);
    }

    DusFree(sql);
    DbFreeRow(row);
    DbStringFree(temp_name);
    DbStringFree(temp_desc);

    return status;
}

/*+
 * KsmListRollovers - Output a list of expected rollovers
 *
 *
 * Arguments:
 *
 *      int zone_id
 *          ID of the zone (-1 for all)
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int KsmListRollovers(int zone_id)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    char        stringval[KSM_INT_STR_SIZE];  /* For Integer to String conversion */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */

    char*       temp_zone = NULL;   /* place to store zone name returned */
    int         temp_type = 0;      /* place to store key type returned */
    char*       temp_date = NULL;   /* place to store date returned */

    /* Select rows */
    StrAppend(&sql, "select z.name, k.keytype, k.retire from zones z, KEYDATA_VIEW k where z.id = k.zone_id and k.state = 4 ");
    if (zone_id != -1) {
        StrAppend(&sql, "and zone_id = ");
        snprintf(stringval, KSM_INT_STR_SIZE, "%d", zone_id);
        StrAppend(&sql, stringval);
    }
    StrAppend(&sql, " order by zone_id");

    DusEnd(&sql);

    status = DbExecuteSql(DbHandle(), sql, &result);

    if (status == 0) {
        status = DbFetchRow(result, &row);
        printf("Zone:                           Keytype:      Rollover expected:\n");
        while (status == 0) {
            /* Got a row, print it */
            DbString(row, 0, &temp_zone);
            DbInt(row, 1, &temp_type);
            DbString(row, 2, &temp_date);

            printf("%-31s %-13s %s\n", temp_zone, (temp_type == KSM_TYPE_KSK) ? "KSK" : "ZSK", (temp_date == NULL) ? "(not scheduled)" : temp_date);
            
            status = DbFetchRow(result, &row);
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result);
    }

    DusFree(sql);
    DbFreeRow(row);
    DbStringFree(temp_zone);
    DbStringFree(temp_date);

    return status;
}

/*+
 * KsmCheckNextRollover - Find next expected rollover
 *
 *
 * Arguments:
 *
 *      int keytype
 *          KSK or ZSK
 *
 *      int zone_id
 *          ID of the zone
 *
 *      char** datetime
 *          (returned) date that a rollover is expected
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int KsmCheckNextRollover(int keytype, int zone_id, char** datetime)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */

    /* Select rows */
    sql = DqsSpecifyInit("KEYDATA_VIEW", "retire");
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, 0);
    DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, KSM_STATE_ACTIVE, 1);
    DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, 2);
    StrAppend(&sql, " order by retire asc");

    DqsEnd(&sql);

    status = DbExecuteSql(DbHandle(), sql, &result);

    if (status == 0) {
        status = DbFetchRow(result, &row);

        /* First row should be the closest rollover if there are multiple active keys */
        if (status == 0) {
            DbString(row, 0, datetime);
        }

        DbFreeResult(result);
        DbFreeRow(row);
    }

    DusFree(sql);

    return status;
}
