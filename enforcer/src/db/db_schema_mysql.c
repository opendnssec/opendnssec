/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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

const char* db_schema_mysql_create[] = {
    "CREATE TABLE zone ( id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT NOT NULL,  rev INT UNSIGNED NOT NULL DEFAULT 1,  policyId BIGINT UNSIGNED NOT NULL,  name TEXT NOT NULL,  signconfNeedsWriting INT UNSIGNED NOT NULL,  signconfPath TEXT NOT NULL,  nextChange INT NOT NULL,  ttlEndDs INT UNSIGNED NOT NULL,  ttlEndDk INT UNSIGNED NOT NULL,  ttlEndRs INT UNSIGNED NOT NULL,  rollKskNow INT UNSIGNED NOT NULL,  rollZskNow INT UNSIGNED NOT NULL,  rollCskNow INT UNSIGNED NOT NULL,  inputAdapterType TEXT NO",
    "T NULL,  inputAdapterUri TEXT NOT NULL,  outputAdapterType TEXT NOT NULL,  outputAdapterUri TEXT NOT NULL,  nextKskRoll INT UNSIGNED NOT NULL,  nextZskRoll INT UNSIGNED NOT NULL,  nextCskRoll INT UNSIGNED NOT NULL)",
    0,
    "CREATE INDEX zonePolicyId ON zone ( policyId )",
    0,
    "CREATE UNIQUE INDEX zoneName ON zone ( name(255) )",
    0,
    "CREATE TABLE keyData ( id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT NOT NULL,  rev INT UNSIGNED NOT NULL DEFAULT 1,  zoneId BIGINT UNSIGNED NOT NULL,  hsmKeyId BIGINT UNSIGNED NOT NULL,  algorithm INT UNSIGNED NOT NULL,  inception INT UNSIGNED NOT NULL,  role INT NOT NULL,  introducing INT UNSIGNED NOT NULL,  shouldRevoke INT UNSIGNED NOT NULL,  standby INT UNSIGNED NOT NULL,  activeZsk INT UNSIGNED NOT NULL,  publish INT UNSIGNED NOT NULL,  activeKsk INT UNSIGNED NOT NULL,  dsAtParent INT NOT ",
    "NULL,  keytag INT UNSIGNED NOT NULL,  minimize INT UNSIGNED NOT NULL)",
    0,
    "CREATE INDEX keyDataZoneId ON keyData ( zoneId )",
    0,
    "CREATE INDEX keyDataHsmKeyId ON keyData ( hsmKeyId )",
    0,
    "CREATE TABLE keyState ( id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT NOT NULL,  rev INT UNSIGNED NOT NULL DEFAULT 1,  keyDataId BIGINT UNSIGNED NOT NULL,  type INT NOT NULL,  state INT NOT NULL,  lastChange INT UNSIGNED NOT NULL,  minimize INT UNSIGNED NOT NULL,  ttl INT UNSIGNED NOT NULL)",
    0,
    "CREATE INDEX keyStateKeyDataId ON keyState ( keyDataId )",
    0,
    "CREATE TABLE keyDependency ( id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT NOT NULL,  rev INT UNSIGNED NOT NULL DEFAULT 1,  zoneId BIGINT UNSIGNED NOT NULL,  fromKeyDataId BIGINT UNSIGNED NOT NULL,  toKeyDataId BIGINT UNSIGNED NOT NULL,  type INT NOT NULL)",
    0,
    "CREATE INDEX keyDependencyZoneId ON keyDependency ( zoneId )",
    0,
    "CREATE INDEX keyDependencyFromKeyDataId ON keyDependency ( fromKeyDataId )",
    0,
    "CREATE INDEX keyDependencyToKeyDataId ON keyDependency ( toKeyDataId )",
    0,
    "CREATE TABLE hsmKey ( id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT NOT NULL,  rev INT UNSIGNED NOT NULL DEFAULT 1,  policyId BIGINT UNSIGNED NOT NULL,  locator TEXT NOT NULL,  state INT NOT NULL,  bits INT UNSIGNED NOT NULL,  algorithm INT UNSIGNED NOT NULL,  role INT NOT NULL,  inception INT UNSIGNED NOT NULL,  isRevoked INT UNSIGNED NOT NULL,  keyType INT NOT NULL,  repository TEXT NOT NULL,  backup INT NOT NULL)",
    0,
    "CREATE INDEX hsmKeyPolicyId ON hsmKey ( policyId )",
    0,
    "CREATE UNIQUE INDEX hsmKeyLocator ON hsmKey ( locator(255) )",
    0,
    "CREATE TABLE policy ( id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT NOT NULL,  rev INT UNSIGNED NOT NULL DEFAULT 1,  name TEXT NOT NULL,  description TEXT NOT NULL,  signaturesResign INT UNSIGNED NOT NULL,  signaturesRefresh INT UNSIGNED NOT NULL,  signaturesJitter INT UNSIGNED NOT NULL,  signaturesInceptionOffset INT UNSIGNED NOT NULL,  signaturesValidityDefault INT UNSIGNED NOT NULL,  signaturesValidityDenial INT UNSIGNED NOT NULL,  signaturesValidityKeyset INT UNSIGNED,  signaturesMaxZoneTtl INT UNSIGNED NOT NULL,  denialType INT N",
    "OT NULL,  denialOptout INT UNSIGNED NOT NULL,  denialTtl INT UNSIGNED NOT NULL,  denialResalt INT UNSIGNED NOT NULL,  denialAlgorithm INT UNSIGNED NOT NULL,  denialIterations INT UNSIGNED NOT NULL,  denialSaltLength INT UNSIGNED NOT NULL,  denialSalt TEXT NOT NULL,  denialSaltLastChange INT UNSIGNED NOT NULL,  keysTtl INT UNSIGNED NOT NULL,  keysRetireSafety INT UNSIGNED NOT NULL,  keysPublishSafety INT UNSIGNED NOT NULL,  keysShared INT UNSIGNED NOT NULL,  keysPurgeAfter INT UNSIGNED NOT NULL, ",
    " zonePropagationDelay INT UNSIGNED NOT NULL,  zoneSoaTtl INT UNSIGNED NOT NULL,  zoneSoaMinimum INT UNSIGNED NOT NULL,  zoneSoaSerial INT NOT NULL,  parentRegistrationDelay INT UNSIGNED NOT NULL,  parentPropagationDelay INT UNSIGNED NOT NULL,  parentDsTtl INT UNSIGNED NOT NULL,  parentSoaTtl INT UNSIGNED NOT NULL,  parentSoaMinimum INT UNSIGNED NOT NULL,  passthrough INT UNSIGNED NOT NULL)",
    0,
    "CREATE UNIQUE INDEX policyName ON policy ( name(255) )",
    0,
    "CREATE TABLE policyKey ( id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT NOT NULL,  rev INT UNSIGNED NOT NULL DEFAULT 1,  policyId BIGINT UNSIGNED NOT NULL,  role INT NOT NULL,  algorithm INT UNSIGNED NOT NULL,  bits INT UNSIGNED NOT NULL,  lifetime INT UNSIGNED NOT NULL,  repository TEXT NOT NULL,  standby INT UNSIGNED NOT NULL,  manualRollover INT UNSIGNED NOT NULL,  rfc5011 INT UNSIGNED NOT NULL,  minimize INT UNSIGNED NOT NULL)",
    0,
    "CREATE INDEX policyKeyPolicyId ON policyKey ( policyId )",
    0,
    "CREATE TABLE databaseVersion ( id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT NOT NULL,  rev INT UNSIGNED NOT NULL DEFAULT 1,  version INT UNSIGNED NOT NULL)",
    0,
    0
};

const char* db_schema_mysql_drop[] = {
    "DROP TABLE IF EXISTS zone",
    0,
    "DROP TABLE IF EXISTS keyData",
    0,
    "DROP TABLE IF EXISTS keyState",
    0,
    "DROP TABLE IF EXISTS keyDependency",
    0,
    "DROP TABLE IF EXISTS hsmKey",
    0,
    "DROP TABLE IF EXISTS policy",
    0,
    "DROP TABLE IF EXISTS policyKey",
    0,
    "DROP TABLE IF EXISTS databaseVersion",
    0,
    0
};
