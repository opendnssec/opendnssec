const char* const sqlstmts_sqlite3_qschema_[] = {
  "SELECT count(name) FROM sqlite_master WHERE type='table' AND name='databaseVersion'",

  NULL };

const char* const sqlstmts_sqlite3_schema_[] = {
  "CREATE TABLE databaseVersion (\n"
  "  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n"
  "  rev INTEGER NOT NULL DEFAULT 1,\n"
  "  version UNSIGNED INTEGER NOT NULL\n"
  ")",

  "CREATE TABLE policy (\n"
  "    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n"
  "    rev INTEGER NOT NULL DEFAULT 1,\n"
  "    name TEXT NOT NULL,\n"
  "    description TEXT NOT NULL,\n"
  "    signaturesResign UNSIGNED INT NOT NULL,\n"
  "    signaturesRefresh UNSIGNED INT NOT NULL,\n"
  "    signaturesJitter UNSIGNED INT NOT NULL,\n"
  "    signaturesInceptionOffset UNSIGNED INT NOT NULL,\n"
  "    signaturesValidityDefault UNSIGNED INT NOT NULL,\n"
  "    signaturesValidityDenial UNSIGNED INT NOT NULL,\n"
  "    signaturesValidityKeyset UNSIGNED INT,\n"
  "    signaturesMaxZoneTtl UNSIGNED INT NOT NULL,\n"
  "    denialType INT NOT NULL,\n"
  "    denialOptout UNSIGNED INT NOT NULL,\n"
  "    denialTtl UNSIGNED INT NOT NULL,\n"
  "    denialResalt UNSIGNED INT NOT NULL,\n"
  "    denialAlgorithm UNSIGNED INT NOT NULL,\n"
  "    denialIterations UNSIGNED INT NOT NULL,\n"
  "    denialSaltLength UNSIGNED INT NOT NULL,\n"
  "    denialSalt TEXT NOT NULL,\n"
  "    denialSaltLastChange UNSIGNED INT NOT NULL,\n"
  "    keysTtl UNSIGNED INT NOT NULL,\n"
  "    keysRetireSafety UNSIGNED INT NOT NULL,\n"
  "    keysPublishSafety UNSIGNED INT NOT NULL,\n"
  "    keysShared UNSIGNED INT NOT NULL,\n"
  "    keysPurgeAfter UNSIGNED INT NOT NULL,\n"
  "    zonePropagationDelay UNSIGNED INT NOT NULL,\n"
  "    zoneSoaTtl UNSIGNED INT NOT NULL,\n"
  "    zoneSoaMinimum UNSIGNED INT NOT NULL,\n"
  "    zoneSoaSerial INT NOT NULL,\n"
  "    parentRegistrationDelay UNSIGNED INT NOT NULL,\n"
  "    parentPropagationDelay UNSIGNED INT NOT NULL,\n"
  "    parentDsTtl UNSIGNED INT NOT NULL,\n"
  "    parentSoaTtl UNSIGNED INT NOT NULL,\n"
  "    parentSoaMinimum UNSIGNED INT NOT NULL,\n"
  "    passthrough UNSIGNED INT NOT NULL\n"
  ")",

  "CREATE UNIQUE INDEX policyName ON policy ( name )",

  "CREATE TABLE policyKey (\n"
  "    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n"
  "    rev INTEGER NOT NULL DEFAULT 1,\n"
  "    policyId INTEGER NOT NULL,\n"
  "    role INT NOT NULL,\n"
  "    algorithm UNSIGNED INT NOT NULL,\n"
  "    bits UNSIGNED INT NOT NULL,\n"
  "    lifetime UNSIGNED INT NOT NULL,\n"
  "    repository TEXT NOT NULL,\n"
  "    standby UNSIGNED INT NOT NULL,\n"
  "    manualRollover UNSIGNED INT NOT NULL,\n"
  "    rfc5011 UNSIGNED INT NOT NULL,\n"
  "    minimize UNSIGNED INT NOT NULL\n"
  ")",

  "CREATE INDEX policyKeyPolicyId ON policyKey ( policyId )",

  "CREATE TABLE hsmKey (\n"
  "    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n"
  "    rev INTEGER NOT NULL DEFAULT 1,\n"
  "    policyId INTEGER NOT NULL,\n"
  "    locator TEXT NOT NULL,\n"
  "    state INT NOT NULL,\n"
  "    bits UNSIGNED INT NOT NULL,\n"
  "    algorithm UNSIGNED INT NOT NULL,\n"
  "    role INT NOT NULL,\n"
  "    inception UNSIGNED INT NOT NULL,\n"
  "    isRevoked UNSIGNED INT NOT NULL,\n"
  "    keyType INT NOT NULL,\n"
  "    repository TEXT NOT NULL,\n"
  "    backup INT NOT NULL\n"
  ")",

  "CREATE INDEX hsmKeyPolicyId ON hsmKey ( policyId )",

  "CREATE UNIQUE INDEX hsmKeyLocator ON hsmKey ( locator )",

  "CREATE TABLE zone (\n"
  "    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n"
  "    rev INTEGER NOT NULL DEFAULT 1,\n"
  "    policyId INTEGER NOT NULL,\n"
  "    name TEXT NOT NULL,\n"
  "    signconfNeedsWriting UNSIGNED INT NOT NULL,\n"
  "    signconfPath TEXT NOT NULL,\n"
  "    nextChange INT NOT NULL,\n"
  "    ttlEndDs UNSIGNED INT NOT NULL,\n"
  "    ttlEndDk UNSIGNED INT NOT NULL,\n"
  "    ttlEndRs UNSIGNED INT NOT NULL,\n"
  "    rollKskNow UNSIGNED INT NOT NULL,\n"
  "    rollZskNow UNSIGNED INT NOT NULL,\n"
  "    rollCskNow UNSIGNED INT NOT NULL,\n"
  "    inputAdapterType TEXT NOT NULL,\n"
  "    inputAdapterUri TEXT NOT NULL,\n"
  "    outputAdapterType TEXT NOT NULL,\n"
  "    outputAdapterUri TEXT NOT NULL,\n"
  "    nextKskRoll UNSIGNED INT NOT NULL,\n"
  "    nextZskRoll UNSIGNED INT NOT NULL,\n"
  "    nextCskRoll UNSIGNED INT NOT NULL\n"
  ")",

  "CREATE INDEX zonePolicyId ON zone ( policyId )",

  "CREATE UNIQUE INDEX zoneName ON zone ( name )",

  "CREATE TABLE keyData (\n"
  "    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n"
  "    rev INTEGER NOT NULL DEFAULT 1,\n"
  "    zoneId INTEGER NOT NULL,\n"
  "    hsmKeyId INTEGER NOT NULL,\n"
  "    algorithm UNSIGNED INT NOT NULL,\n"
  "    inception UNSIGNED INT NOT NULL,\n"
  "    role INT NOT NULL,\n"
  "    introducing UNSIGNED INT NOT NULL,\n"
  "    shouldRevoke UNSIGNED INT NOT NULL,\n"
  "    standby UNSIGNED INT NOT NULL,\n"
  "    activeZsk UNSIGNED INT NOT NULL,\n"
  "    publish UNSIGNED INT NOT NULL,\n"
  "    activeKsk UNSIGNED INT NOT NULL,\n"
  "    dsAtParent INT NOT NULL,\n"
  "    keytag UNSIGNED INT NOT NULL,\n"
  "    minimize UNSIGNED INT NOT NULL\n"
  ")",

  "CREATE INDEX keyDataZoneId ON keyData ( zoneId )",

  "CREATE INDEX keyDataHsmKeyId ON keyData ( hsmKeyId )",

  "CREATE TABLE keyState (\n"
  "    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n"
  "    rev INTEGER NOT NULL DEFAULT 1,\n"
  "    keyDataId INTEGER NOT NULL,\n"
  "    type INT NOT NULL,\n"
  "    state INT NOT NULL,\n"
  "    lastChange UNSIGNED INT NOT NULL,\n"
  "    minimize UNSIGNED INT NOT NULL,\n"
  "    ttl UNSIGNED INT NOT NULL\n"
  ")",

  "CREATE INDEX keyStateKeyDataId ON keyState ( keyDataId )",

  "CREATE TABLE keyDependency (\n"
  "    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n"
  "    rev INTEGER NOT NULL DEFAULT 1,\n"
  "    zoneId INTEGER NOT NULL,\n"
  "    fromKeyDataId INTEGER NOT NULL,\n"
  "    toKeyDataId INTEGER NOT NULL,\n"
  "    type INT NOT NULL\n"
  ")",

  "CREATE INDEX keyDependencyZoneId ON keyDependency ( zoneId )",

  "CREATE INDEX keyDependencyFromKeyDataId ON keyDependency ( fromKeyDataId )",

  "CREATE INDEX keyDependencyToKeyDataId ON keyDependency ( toKeyDataId )",

  NULL };

const char* const sqlstmts_sqlite3_schema1_[] = {
  "DROP INDEX keyDependencyZoneId",

  "ALTER TABLE keyDependency DROP COLUMN zoneId",

  "UPDATE databaseVersion set version = 2",

  NULL };

const char* const sqlstmts_sqlite3_qschema1_[] = {
  "SELECT count(version) FROM databaseVersion WHERE version >= 2",

  NULL };

const char* const sqlstmts_sqlite3_default_[] = {
  "SELECT id, rev, locator, repository, state, bits, algorithm, role, inception, isRevoked, keyType, backup, policyId FROM hsmKey",

  "INSERT OR REPLACE INTO hsmKey ( id, rev, policyId, locator, state, bits, algorithm, role, inception, isRevoked, keyType, repository, backup )\n"
  "VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",

  "DELETE FROM hsmKey WHERE id = ? AND rev = ?",

  "SELECT id, rev, name, description, passthrough,\n"
  "       signaturesResign, signaturesRefresh, signaturesJitter, signaturesInceptionOffset,\n"
  "       signaturesValidityDefault, signaturesValidityDenial, signaturesValidityKeyset, signaturesMaxZoneTtl,\n"
  "       denialType, denialOptout, denialTtl, denialResalt, denialAlgorithm, denialIterations,\n"
  "       denialSaltLength, denialSalt, denialSaltLastChange,\n"
  "       keysTtl, keysRetireSafety, keysPublishSafety, keysShared, keysPurgeAfter,\n"
  "       zonePropagationDelay, zoneSoaTtl, zoneSoaMinimum, zoneSoaSerial,\n"
  "       parentRegistrationDelay, parentPropagationDelay, parentDsTtl, parentSoaTtl, parentSoaMinimum\n"
  "FROM policy",

  "INSERT OR REPLACE INTO policy ( id, rev, name, description, passthrough,\n"
  "       signaturesResign, signaturesRefresh, signaturesJitter, signaturesInceptionOffset,\n"
  "       signaturesValidityDefault, signaturesValidityDenial, signaturesValidityKeyset, signaturesMaxZoneTtl,\n"
  "       denialType, denialOptout, denialTtl, denialResalt, denialAlgorithm, denialIterations,\n"
  "       denialSaltLength, denialSalt, denialSaltLastChange,\n"
  "       keysTtl, keysRetireSafety, keysPublishSafety, keysShared, keysPurgeAfter,\n"
  "       zonePropagationDelay, zoneSoaTtl, zoneSoaMinimum, zoneSoaSerial,\n"
  "       parentRegistrationDelay, parentPropagationDelay, parentDsTtl, parentSoaTtl, parentSoaMinimum )\n"
  "VALUES ( ?, ?, ?, ?, ?,\n"
  "         ?, ?, ?, ?, ?, ?, ?, ?,\n"
  "         ?, ?, ?, ?, ?, ?, ?, ?, ?,\n"
  "         ?, ?, ?, ?, ?, ?, ?, ?, ?,\n"
  "         ?, ?, ?, ?, ? )",

  "DELETE FROM policy WHERE id = ? AND rev = ?",

  "SELECT id, rev, policyId, policyId, repository, role, algorithm, bits, lifetime, standby, manualRollover, rfc5011, minimize\n"
  "FROM policyKey",

  "INSERT OR REPLACE INTO policyKey ( id, rev, policyId, role, algorithm, bits, lifetime, repository, standby, manualRollover, rfc5011, minimize )\n"
  "VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )",

  "DELETE FROM policykey WHERE id = ? AND rev = ?",

  "SELECT id, rev, policyId, policyId, name, nextChange, signconfPath,\n"
  "       inputAdapterUri, inputAdapterType, outputAdapterUri, outputAdapterType,\n"
  "       nextKskRoll, nextZskRoll, nextCskRoll, signconfNeedsWriting,\n"
  "       ttlEndDs, ttlEndDk, ttlEndRs, rollKskNow, rollZskNow, rollCskNow\n"
  "FROM zone",

  "INSERT OR REPLACE INTO zone ( id, rev, policyId, name, nextChange, signconfPath,\n"
  "       inputAdapterUri, inputAdapterType, outputAdapterUri, outputAdapterType,\n"
  "       nextKskRoll, nextZskRoll, nextCskRoll, signconfNeedsWriting,\n"
  "       ttlEndDs, ttlEndDk, ttlEndRs, rollKskNow, rollZskNow, rollCskNow )\n"
  "VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n",

  "DELETE FROM zone WHERE id = ? AND rev = ?",

  "SELECT id, rev, zoneId, zoneId, hsmKeyId,\n"
  "       algorithm, inception, role, introducing, shouldRevoke, standby,\n"
  "       activeZsk, publish, activeKsk, dsAtParent, keytag, minimize\n"
  "FROM keyData",

  "INSERT OR REPLACE INTO keyData ( id, rev, zoneId, hsmKeyId,\n"
  "       algorithm, inception, role, introducing, shouldRevoke, standby,\n"
  "       activeZsk, publish, activeKsk, dsAtParent, keytag, minimize )\n"
  "VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )",

  "DELETE FROM keyData WHERE id = ? AND rev = ?",

  "SELECT id, rev, keyDataId, type, state, lastChange, minimize, ttl\n"
  "FROM keyState",

  "INSERT OR REPLACE INTO keyState ( id, rev, keyDataId, type, state, lastChange, minimize, ttl )\n"
  "VALUES ( ?, ?, ?, ?, ?, ?, ?, ? )",

  "DELETE FROM keyState WHERE id = ? AND rev = ?",

  "SELECT id, rev, fromKeyDataId, toKeyDataId, type\n"
  "FROM keyDependency",

  "INSERT OR REPLACE INTO keyDependency ( id, rev, fromKeyDataId, toKeyDataId, type )\n"
  "VALUES ( ?, ?, ?, ?, ? )",

  "DELETE FROM keyDependency WHERE id = ? AND rev = ?",

  NULL };

const char* const sqlstmts_sqlite3_probe_[] = {
  "SELECT 1",

  NULL };

const char* const* sqlstmts_sqlite3_array[] = {
  sqlstmts_sqlite3_qschema_,
  sqlstmts_sqlite3_qschema1_,
  sqlstmts_sqlite3_default_,
  sqlstmts_sqlite3_probe_,
  sqlstmts_sqlite3_schema_,
  sqlstmts_sqlite3_schema1_,
  NULL 
};

const char* const** sqlstmts_sqlite3_qschema = &sqlstmts_sqlite3_array[0];
const char* const** sqlstmts_sqlite3_qschema1 = &sqlstmts_sqlite3_array[1];
const char* const** sqlstmts_sqlite3_default = &sqlstmts_sqlite3_array[2];
const char* const** sqlstmts_sqlite3_probe = &sqlstmts_sqlite3_array[3];
const char* const** sqlstmts_sqlite3_schema = &sqlstmts_sqlite3_array[4];
const char* const** sqlstmts_sqlite3_schema1 = &sqlstmts_sqlite3_array[5];
