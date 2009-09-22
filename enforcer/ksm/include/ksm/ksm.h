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

#ifndef KSM_KSM_H
#define KSM_KSM_H

#ifdef __cplusplus
extern "C" {
#endif

/*+
 * ksm.h - KSM Definitions
 *
 * Description:
 *      Holds definitions and prototypes for the KSM library.
-*/

#include <time.h>
#include <ksm/database.h>
#include <ksm/database_statement.h>


/* General */

typedef int     KSM_ID;         /* Identifies a KSM entity */

#define KSM_NULL_ID ((KSM_ID) -1)   /* General invalid ID */

/* ksm_common */

int KsmInit(void);
int KsmRundown(void);

#define KSM_NAME_LENGTH     256         /* Includes trailing NULL */
#define KSM_POLICY_DESC_LENGTH     256  /* Includes trailing NULL */
#define KSM_POLICY_AUDIT_LENGTH    4096 /* Includes trailing NULL */
#define KSM_TIME_LENGTH     32          /* Includes trailing NULL */

#define KSM_SQL_SIZE        1024        /* Max size of SQL statement */
#define KSM_INT_STR_SIZE    32          /* Max size of int as string */
#define KSM_SALT_LENGTH     512         /* Includes trailing NULL */
#define KSM_ZONE_NAME_LENGTH     256    /* Includes trailing NULL */
#define KSM_ADAPTER_NAME_LENGTH  256    /* Includes trailing NULL */
/* ksm_key */

/* Key time flag states */

#define KEYDATA_M_ID            0x0001
#define KEYDATA_M_STATE         0x0002
#define KEYDATA_M_KEYTYPE       0x0004
#define KEYDATA_M_ALGORITHM     0x0008
#define KEYDATA_M_SIGLIFETIME   0x0010
#define KEYDATA_M_ACTIVE        0x0020
#define KEYDATA_M_DEAD          0x0040
#define KEYDATA_M_GENERATE      0x0080
#define KEYDATA_M_PUBLISH       0x0100
#define KEYDATA_M_READY         0x0200
#define KEYDATA_M_RETIRE        0x0400
#define KEYDATA_M_LOCATION      0x0800
#define KEYDATA_M_SIZE			0x1000
#define KEYDATA_M_SMID			0x2000

#define KEYDATA_M_TIMES         (KEYDATA_M_ACTIVE | KEYDATA_M_DEAD | \
    KEYDATA_M_GENERATE | KEYDATA_M_PUBLISH | KEYDATA_M_READY | KEYDATA_M_RETIRE)

/*
 * Structure for key information.  Note that on the date fields, the
 * "struct tm" fields are used to insert data into the database, and the
 * "char*" fields used to retrieve data.  In the latter case, a NULL field
 * will be represented by an empty string.
 */

typedef struct {
    DB_ID	keypair_id;
    int     state;
    int     keytype;
    int     algorithm;
    int     siglifetime;
    char    active[KSM_TIME_LENGTH];
    char    dead[KSM_TIME_LENGTH];
    char    generate[KSM_TIME_LENGTH];
    char    publish[KSM_TIME_LENGTH];
    char    ready[KSM_TIME_LENGTH];
    char    retire[KSM_TIME_LENGTH];
    char    location[KSM_NAME_LENGTH];
    int     securitymodule_id;
    int     size;
    int     policy_id;
    char    HSMKey_id[KSM_NAME_LENGTH]; /* TODO is this long enough ? */
    DB_ID	dnsseckey_id;
    int     zone_id;
    int     fixedDate;

    /*
     * The remaining fields are used for data manipulation and are not part of
     * the KEYDATA table.
     */

    int     flags;		/* States which fields are valid */
} KSM_KEYDATA;

int KsmKeyPairCreate(int policy_id, const char* HSMKeyID, int smID, int size, int alg, const char* generate, DB_ID* id);
int KsmDnssecKeyCreate(int zone_id, int keypair_id, int keytype, DB_ID* id);
int KsmDnssecKeyCreateOnPolicy(int policy_id, int keypair_id, int keytype);
int KsmKeyInitSql(DB_RESULT* result, const char* sql);
int KsmKeyInit(DB_RESULT* result, DQS_QUERY_CONDITION* condition);
int KsmKeyInitId(DB_RESULT* result, DB_ID id);
int KsmKey(DB_RESULT result, KSM_KEYDATA* data);
void KsmKeyEnd(DB_RESULT result);
int KsmKeyQuery(const char* sql, DB_RESULT* result);
int KsmKeyData(DB_ID id, KSM_KEYDATA* data);
int KsmKeyPredict(int policy_id, int keytype, int shared_keys, int interval, int *count);
int KsmKeyCountQueue(int keytype, int* count, int zone_id);
int KsmKeyCountStillGood(int policy_id, int sm, int bits, int algorithm, int interval, const char* datetime, int *count);
int KsmKeyGetUnallocated(int policy_id, int sm, int bits, int algorithm, int *keypair_id);   int KsmLinkKeys(const char* zone_name, int policy_id);

/* delete */

int KsmDeleteKeyRange(int minid, int maxid);
int KsmDeleteKeyRanges(int limit[], int size);

/* modify */

int KsmKeyModify(KSM_KEYDATA* data, int low, int high);

/* KsmParameter */

typedef struct {
    char        name[KSM_NAME_LENGTH];
    char        category[KSM_NAME_LENGTH];
    int         value;
    int         parameter_id;
} KSM_PARAMETER;

int KsmParameterInit(DB_RESULT* result, const char* name, const char* category, int policy_id);
int KsmParameterExist(DB_RESULT* result, const char* name, const char* category, int* parameter_id);
int KsmParameter(DB_RESULT result, KSM_PARAMETER* data);
void KsmParameterEnd(DB_RESULT result);
int KsmParameterValue(const char* name, const char* category, int* value, int policy_id, int* parameter_id);
int KsmParameterSet(const char* name, const char* category, int value, int policy_id);
int KsmParameterShow(const char* name, const char* category, int policy_id);

/* ksmPolicy */
typedef struct {
	int refresh;
	int jitter;
	int propdelay;
	int soamin;
	int soattl;
    int serial;
} KSM_SIGNER_POLICY;

typedef struct {
	int clockskew;
	int resign;
	int valdefault;
	int valdenial;
} KSM_SIGNATURE_POLICY;

typedef struct {
	int version;
	int resalt;
	int algorithm;
	int iteration;
	int optout;
	int ttl;
	int saltlength;
    char    salt[KSM_SALT_LENGTH];
    char    salt_stamp[KSM_TIME_LENGTH];
} KSM_DENIAL_POLICY;

typedef struct {
	int ttl;
	int retire_safety;
	int publish_safety;
	int share_keys;
} KSM_COMMON_KEY_POLICY;

typedef struct {
	int algorithm;
	int bits;
	int lifetime;
	int sm;
	char sm_name[KSM_NAME_LENGTH];
	unsigned long sm_capacity;
    int require_backup;
	int overlap;
	int ttl;
	int rfc5011;
	int type;
	int standby_keys;
    int manual_rollover;
} KSM_KEY_POLICY;

typedef struct {
    int         keycreate;
    int 		backup_interval;
    int keygeninterval;
} KSM_ENFORCER_POLICY;

typedef struct {
    int propdelay;
    int soa_ttl;
    int soa_min;
    int serial;
} KSM_ZONE_POLICY;

typedef struct {
    int propdelay;
    int ds_ttl;
    int soa_ttl;
    int soa_min;
} KSM_PARENT_POLICY;

typedef struct {
    int audit;
} KSM_AUDIT_POLICY;

typedef struct {
	int id;
	char* name;
	char* description;
	KSM_SIGNER_POLICY* signer;
	KSM_SIGNATURE_POLICY* signature;
	KSM_DENIAL_POLICY* denial;
	KSM_COMMON_KEY_POLICY* keys;
	KSM_KEY_POLICY* ksk;
	KSM_KEY_POLICY* zsk;
	KSM_ENFORCER_POLICY* enforcer;
	KSM_ZONE_POLICY* zone;
	KSM_PARENT_POLICY* parent;
	/*KSM_AUDIT_POLICY* audit;*/
	char* audit;
    int     shared_keys;
} KSM_POLICY;

typedef struct {
    char        name[KSM_NAME_LENGTH];
    char		category[KSM_NAME_LENGTH];
    int         value;
} KSM_POLICY_PARAMETER;

int KsmPolicyInit(DB_RESULT* handle, const char* name);
int KsmPolicyExists(const char* name);
int KsmPolicyParametersInit(DB_RESULT* handle, const char* name);
int KsmPolicyRead(KSM_POLICY* policy);
int KsmPolicy(DB_RESULT handle, KSM_POLICY* data);
int KsmPolicyParameter(DB_RESULT handle, KSM_POLICY_PARAMETER* data);
int KsmPolicyReadFromId(KSM_POLICY* policy);
int KsmPolicyNameFromId(KSM_POLICY* policy);
int KsmPolicyUpdateSalt(KSM_POLICY* policy);
int KsmPolicyPopulateSMFromIds(KSM_POLICY* policy);
int KsmPolicySetIdFromName(KSM_POLICY *policy);

KSM_POLICY *KsmPolicyAlloc();
void KsmPolicyFree(KSM_POLICY *policy);

/* ksmZone */
typedef struct {
    int id;
    char* name;
} KSM_ZONE;

int KsmZoneInit(DB_RESULT* handle, int policy_id);
int KsmZone(DB_RESULT handle, KSM_ZONE *data);
int KsmZoneCount(DB_RESULT handle, int* count);
int KsmZoneCountInit(DB_RESULT* handle, int id);
int KsmZoneIdFromName(const char* zone_name, int* zone_id);
int KsmZoneIdAndPolicyFromName(const char* zone_name, int* policy_id, int* zone_id);
int KsmDeleteZone(int zone_id);
int KsmZoneNameFromId(int zone_id, char** zone_name);

#define UNSIGNED 0
#define SIGNED 1

int KsmDNSSECKeysInSMCountInit(DB_RESULT* handle, int policy_id);
int KsmDNSSECKeysInSMCount(DB_RESULT handle, int* count);
int KsmDNSSECKeysStateCountInit(DB_RESULT* result, int policy_id, KSM_KEY_POLICY *key_policy, int state);

/* Purge */

void KsmPurge(void);

/*
 * Constants in the database tables.  These are used in the
 * ksm_keyword module.
 *
 * THESE MUST BE KEPT IN STEP WITH THE DATABASE CREATION SCRIPT
 */

/*
 * The following names and constants are in the SIG(0) Algorithm Numbers
 * page at IANA - http://www.iana.org/assignments/sig-alg-numbers.
 */

#define KSM_ALGORITHM_RSAMD5            1
#define KSM_ALGORITHM_RSAMD5_STRING     "rsamd5"
#define KSM_ALGORITHM_DH                2
#define KSM_ALGORITHM_DH_STRING         "dh"
#define KSM_ALGORITHM_DSASHA1           3
#define KSM_ALGORITHM_DSASHA1_STRING    "dsasha1"
#define KSM_ALGORITHM_RSASHA1           5
#define KSM_ALGORITHM_RSASHA1_STRING    "rsasha1"
#define KSM_ALGORITHM_RSASHA1_NSEC3_SHA1 7
#define KSM_ALGORITHM_RSASHA1_NSEC3_SHA1_STRING "rsasha1-nsec3-sha1"
#define KSM_ALGORITHM_INDIRECT          252
#define KSM_ALGORITHM_INDIRECT_STRING   "indirect"
#define KSM_ALGORITHM_PRIVDOM           253
#define KSM_ALGORITHM_PRIVDOM_STRING    "domain"
#define KSM_ALGORITHM_PRIVOID           254
#define KSM_ALGORITHM_PRIVOID_STRING    "oid"

#define KSM_FORMAT_FILE             1
#define KSM_FORMAT_FILE_STRING      "file"
#define KSM_FORMAT_HSM              2
#define KSM_FORMAT_HSM_STRING       "hsm"
#define KSM_FORMAT_URI              3
#define KSM_FORMAT_URI_STRING       "uri"

#define KSM_TYPE_KSK                257
#define KSM_TYPE_KSK_STRING         "ksk"
#define KSM_TYPE_ZSK                256
#define KSM_TYPE_ZSK_STRING         "zsk"

#define KSM_STATE_GENERATE          1
#define KSM_STATE_GENERATE_STRING   "generate"
#define KSM_STATE_PUBLISH           2
#define KSM_STATE_PUBLISH_STRING    "publish"
#define KSM_STATE_READY             3
#define KSM_STATE_READY_STRING      "ready"
#define KSM_STATE_ACTIVE            4
#define KSM_STATE_ACTIVE_STRING     "active"
#define KSM_STATE_RETIRE            5
#define KSM_STATE_RETIRE_STRING     "retire"
#define KSM_STATE_DEAD              6
#define KSM_STATE_DEAD_STRING       "dead"

#define KSM_SERIAL_UNIX_STRING      "unixtime"
#define KSM_SERIAL_UNIX             1
#define KSM_SERIAL_COUNTER_STRING   "counter"
#define KSM_SERIAL_COUNTER          2
#define KSM_SERIAL_DATE_STRING      "datecounter"
#define KSM_SERIAL_DATE             3
#define KSM_SERIAL_KEEP_STRING      "keep"
#define KSM_SERIAL_KEEP             4
#define KSM_SERIAL_KEEPCOUNTER_STRING "keepcounter"
#define KSM_SERIAL_KEEPCOUNTER      5

#define KSM_KEYS_NOT_SHARED         0
#define KSM_KEYS_SHARED             1

/* Reserved parameters and default values (in seconds) */
/* TODO redefine this properly:
 *      have _CAT defines separate 
 *      rename to match the new list
 *      add new items ? */
#define KSM_PAR_CLOCKSKEW               3600        /* 1 hour */
#define KSM_PAR_CLOCKSKEW_STRING        "clockskew"
#define KSM_PAR_CLOCKSKEW_CAT           "signature"
#define KSM_PAR_KSKLIFE                 63072000    /* 2 years */
#define KSM_PAR_KSKLIFE_STRING          "lifetime"
#define KSM_PAR_KSKLIFE_CAT             "ksk"
#define KSM_PAR_PROPDELAY               3600        /* 1 hour */
#define KSM_PAR_PROPDELAY_STRING        "propagationdelay"
#define KSM_PAR_PROPDELAY_CAT           "zone"
#define KSM_PAR_STANDBYKSKS             1
#define KSM_PAR_STANDBYKSKS_STRING      "standby"
#define KSM_PAR_STANDBYKSKS_CAT         "ksk"
#define KSM_PAR_STANDBYZSKS             1
#define KSM_PAR_STANDBYZSKS_STRING      "standby"
#define KSM_PAR_STANDBYZSKS_CAT         "ksk"
#define KSM_PAR_SIGNINT                 7200        /* 2 hours */
#define KSM_PAR_SIGNINT_STRING          "resign"
#define KSM_PAR_SIGNINT_CAT             "signature"
#define KSM_PAR_SOAMIN                  7200        /* 2 hours */
#define KSM_PAR_SOAMIN_STRING           "min"
#define KSM_PAR_SOAMIN_CAT              "zone"
#define KSM_PAR_SOATTL                  172800      /* 2 days */
#define KSM_PAR_SOATTL_STRING           "ttl"
#define KSM_PAR_SOATTL_CAT              "zone"
#define KSM_PAR_ZSKSIGLIFE              432000      /* 5 days */
#define KSM_PAR_ZSKSIGLIFE_STRING       "valdefault"
#define KSM_PAR_ZSKSIGLIFE_CAT          "signature"
#define KSM_PAR_ZSKLIFE                 2592000     /* 30 days */
#define KSM_PAR_ZSKLIFE_STRING          "lifetime"
#define KSM_PAR_ZSKLIFE_CAT             "zsk"
#define KSM_PAR_ZSKTTL                  172800      /* 2 days */
#define KSM_PAR_ZSKTTL_STRING           "ttl"
#define KSM_PAR_ZSKTTL_CAT              "keys"
#define KSM_PAR_KSKTTL                  172800      /* 2 days */
#define KSM_PAR_KSKTTL_STRING           "ttl"
#define KSM_PAR_KSKTTL_CAT              "keys"
#define KSM_PAR_KSKPROPDELAY            3600        /* 1 hour */
#define KSM_PAR_KSKPROPDELAY_STRING     "propagationdelay"
#define KSM_PAR_KSKPROPDELAY_CAT        "parent"
#define KSM_PAR_REGDELAY                0   /* TODO sort this out */
#define KSM_PAR_REGDELAY_STRING         "registrationdelay"  /* TODO sort this out */
#define KSM_PAR_REGDELAY_CAT            "parent"  /* TODO sort this out */
#define KSM_PAR_PUBSAFETY               172800      /* 2 days */
#define KSM_PAR_PUBSAFETY_STRING        "publishsafety"
#define KSM_PAR_PUBSAFETY_CAT           "keys"
#define KSM_PAR_RETSAFETY               172800      /* 2 days */
#define KSM_PAR_RETSAFETY_STRING        "retiresafety"
#define KSM_PAR_RETSAFETY_CAT           "keys"
#define KSM_PAR_KSK_MAN_ROLL            0      /* false (i.e. automatic roll) */
#define KSM_PAR_KSK_MAN_ROLL_STRING     "manual_rollover"
#define KSM_PAR_KSK_MAN_ROLL_CAT        "ksk"
#define KSM_PAR_ZSK_MAN_ROLL            0      /* false (i.e. automatic roll) */
#define KSM_PAR_ZSK_MAN_ROLL_STRING     "manual_rollover"
#define KSM_PAR_ZSK_MAN_ROLL_CAT        "zsk"

typedef struct {            /* Holds collection of parameters */
    int     clockskew;      /* Clock skew */
    int     ksklife;        /* Lifetime of a KSK */
    int     standbyksks;    /* Number of Standby Key Signing keys */
    int     standbyzsks;    /* Number of Standby Zone signing keys */
    int     propdelay;      /* Propagation delay */
    int     signint;        /* Signing interval - how long signing the zone takes */
    int     soamin;         /* "Minimum" value from SOA record */
    int     soattl;         /* TTL of the SOA record */
    int     zsksiglife;     /* Length of signatures signed by this ZSK */
    int     zsklife;        /* How long key is used for */
    int     zskttl;         /* TTL of ZSK DNSKEY record */
    int     kskttl;         /* TTL of KSK DNSKEY record */
    int     kskpropdelay;   /* KSK Propagation delay */
    int     regdelay;       /* KSK Registration delay */
    int     pub_safety;     /* Publish safety margin */
    int     ret_safety;     /* Retire safety margin */
    int     kskmanroll;     /* Do we only roll the KSK manually? */
    int     zskmanroll;     /* Do we only roll the ZSK manually? */
} KSM_PARCOLL;

int KsmCollectionInit(KSM_PARCOLL* data);
int KsmParameterClockskew(KSM_PARCOLL* collection);
int KsmParameterKskLifetime(KSM_PARCOLL* collection);
int KsmParameterStandbyKSKeys(KSM_PARCOLL* collection);
int KsmParameterStandbyZSKeys(KSM_PARCOLL* collection);
int KsmParameterPropagationDelay(KSM_PARCOLL* collection);
int KsmParameterSigningInterval(KSM_PARCOLL* collection);
int KsmParameterSoaMin(KSM_PARCOLL* collection);
int KsmParameterSoaTtl(KSM_PARCOLL* collection);
int KsmParameterZskLifetime(KSM_PARCOLL* collection);
int KsmParameterZskTtl(KSM_PARCOLL* collection);
int KsmParameterKskTtl(KSM_PARCOLL* collection);
int KsmParameterKskPropagationDelay(KSM_PARCOLL* collection);
int KsmParameterRegistrationDelay(KSM_PARCOLL* collection);
int KsmParameterPubSafety(KSM_PARCOLL* collection);
int KsmParameterRetSafety(KSM_PARCOLL* collection);
int KsmParameterInitialPublicationInterval(KSM_PARCOLL* collection);
int KsmParameterCollection(KSM_PARCOLL* data, int policy_id);

/* ksm_keyword */

int KsmKeywordAlgorithmNameToValue(const char* name);
int KsmKeywordFormatNameToValue(const char* name);
int KsmKeywordParameterNameToValue(const char* name);
int KsmKeywordStateNameToValue(const char* name);
int KsmKeywordTypeNameToValue(const char* name);
const char* KsmKeywordAlgorithmValueToName(int value);
const char* KsmKeywordFormatValueToName(int value);
const char* KsmKeywordStateValueToName(int value);
const char* KsmKeywordTypeValueToName(int value);
const char* KsmKeywordSerialValueToName(int value);
int KsmKeywordParameterExists(const char* name);

/* ksm_update */

int KsmUpdate(int policy_id, int zone_id);
void KsmUpdateKey(KSM_KEYDATA* data, KSM_PARCOLL* collection);
void KsmUpdateGenerateKeyTime(KSM_KEYDATA* data);
void KsmUpdatePublishKeyTime(KSM_KEYDATA* data, KSM_PARCOLL* collection);
void KsmUpdateReadyKeyTime(KSM_KEYDATA* data);
void KsmUpdateActiveKeyTime(KSM_KEYDATA* data, KSM_PARCOLL* collection);
void KsmUpdateRetireKeyTime(KSM_KEYDATA* data, KSM_PARCOLL* collection);
void KsmUpdateDeadKeyTime(KSM_KEYDATA* data);
int KsmUpdateKeyTime(const KSM_KEYDATA* data, const char* source,
    const char* destination, int interval);

/* ksm_request */

typedef int (*KSM_REQUEST_CALLBACK)(void* context, KSM_KEYDATA* key);

int KsmRequestKeys(int keytype, int rollover, const char* datetime,
	KSM_REQUEST_CALLBACK callback, void* context, int policy_id, int zone_id,
    int run_interval);
int KsmRequestKeysByType(int keytype, int rollover, const char* datetime,
	KSM_REQUEST_CALLBACK callback, void* context, int policy_id, int zone_id,
    int run_interval);
int KsmRequestSetActiveExpectedRetire(int keytype, const char* datetime, int zone_id);
int KsmRequestChangeStateActiveRetire(int keytype, const char* datetime, int zone_id, int policy_id);
int KsmRequestChangeStateRetireDead(int keytype, const char* datetime, int zone_id, int policy_id);
int KsmRequestChangeStatePublishReady(int keytype, const char* datetime, int zone_id, int policy_id);
int KsmRequestChangeState(int keytype, const char* datetime, int src_state,
	int dst_state, int zone_id, int policy_id);
int KsmRequestChangeStateGeneratePublish(int keytype, const char* datetime,
	int count, int zone_id);
int KsmRequestChangeStateReadyActive(int keytype, const char* datetime,
	int count, int zone_id);
int KsmRequestChangeStateN(int keytype, const char* datetime,
    int count, int src_state, int dst_state, int zone_id);
int KsmRequestChangeStateGeneratePublishConditional( int keytype,
	const char* datetime, KSM_PARCOLL* collection, int zone_id,
    int run_interval);
int KsmRequestPendingRetireCount(int keytype, const char* datetime,
	KSM_PARCOLL* parameters, int* count, int zone_id, int interval);
int KsmRequestAvailableCount(int keytype, const char* datetime,
	KSM_PARCOLL* parameters, int* count, int zone_id);
int KsmRequestGenerateCount(int keytype, int* count, int zone_id);
int KsmRequestCheckActiveKey(int keytype, const char* datetime, int* count, int zone_id);
int KsmRequestCountReadyKey(int keytype, const char* datetime, int* count, int zone_id);
int KsmRequestCheckFirstPass(int keytype, int* first_pass_flag, int zone_id);

int KsmRequestIssueKeys(int keytype, KSM_REQUEST_CALLBACK callback,
	void* context, int zone_id);

int KsmRequestPrintKey(void* context, KSM_KEYDATA* data);

int KsmRequestDNSSECKeys(const char* datetime, KSM_POLICY* policy);
int KsmRequestDNSSECKeysChangeStateRetireDead(KSM_KEY_POLICY *policy, const char* datetime, int verify);
int KsmRequestDNSSECKeysChangeState(KSM_KEY_POLICY *policy, const char* datetime, int src_state, int dst_state, int verify);
int KsmRequestDNSSECKeysChangeStatePublishReady(KSM_KEY_POLICY *policy, const char* datetime, int verify);
int KsmRequestDNSSECKeysChangeStateGeneratePublishConditional(KSM_POLICY *policy, KSM_KEY_POLICY *key_policy, const char* datetime, int verify);
int KsmRequestDNSSECKeysSetActiveExpectedRetire(int keytype, const char* datetime, int verify);
int KsmRequestDNSSECKeysPendingRetireCount(KSM_KEY_POLICY, const char* datetime, int* count);

int KsmPolicyClockskew(KSM_SIGNATURE_POLICY *policy);
int KsmPolicyKeyLifetime(KSM_KEY_POLICY *policy);
int KsmPolicyStandbyKeys(KSM_KEY_POLICY *policy);
int KsmPolicyPropagationDelay(KSM_SIGNER_POLICY *policy);
int KsmPolicySigningInterval(KSM_PARCOLL* collection);
int KsmPolicySoaMin(KSM_SIGNER_POLICY *policy);
int KsmPolicySoaTtl(KSM_SIGNER_POLICY *policy);
int KsmPolicyZskTtl(KSM_PARCOLL* collection);
int KsmPolicyInitialPublicationInterval(KSM_POLICY *policy);

/* KsmImport */
int KsmImportRepository(const char* repo_name, const char* repo_capacity, int require_backup);
int KsmImportPolicy(const char* policy_name, const char* policy_description);
int KsmImportZone(const char* zone_name, int policy_id);
int KsmImportAudit(int policy_id, const char* audit_contents);
int KsmImportKeyPair(int policy_id, const char* HSMKeyID, int smID, int size, int alg, int state, const char* time, const char* opt_time, DB_ID* id);
int KsmSmIdFromName(const char* name, int *id);
int KsmSerialIdFromName(const char* name, int *id);
int KsmPolicyIdFromName(const char* name, int *id);
int KsmMarkBackup(int repo_id, const char* datetime);
int KsmCheckHSMkeyID(int repo_id, const char* cka_id, int *exists);

/* KsmList */
int KsmListBackups(int repo_id);
int KsmListRepos();
int KsmListPolicies();
int KsmListRollovers(int zone_id);
int KsmListKeys(int zone_id, int long_list);
int KsmCheckNextRollover(int keytype, int zone_id, char** datetime);

#ifdef __cplusplus
};
#endif

#endif /* KSM_KSM_H */
