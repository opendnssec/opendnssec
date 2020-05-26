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

const char* db_schema_sqlite_create[] = {
    "CREATE TABLE zone ( id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,  rev INTEGER NOT NULL DEFAULT 1,  policyId INTEGER NOT NULL,  name TEXT NOT NULL,  signconfNeedsWriting UNSIGNED INT NOT NULL,  signconfPath TEXT NOT NULL,  nextChange INT NOT NULL,  ttlEndDs UNSIGNED INT NOT NULL,  ttlEndDk UNSIGNED INT NOT NULL,  ttlEndRs UNSIGNED INT NOT NULL,  rollKskNow UNSIGNED INT NOT NULL,  rollZskNow UNSIGNED INT NOT NULL,  rollCskNow UNSIGNED INT NOT NULL,  inputAdapterType TEXT NOT NULL,  inputAdapterU",
    "ri TEXT NOT NULL,  outputAdapterType TEXT NOT NULL,  outputAdapterUri TEXT NOT NULL,  nextKskRoll UNSIGNED INT NOT NULL,  nextZskRoll UNSIGNED INT NOT NULL,  nextCskRoll UNSIGNED INT NOT NULL, reason TEXT DEFAULT \"\")",
    0,
    "CREATE INDEX zonePolicyId ON zone ( policyId )",
    0,
    "CREATE UNIQUE INDEX zoneName ON zone ( name )",
    0,
    "CREATE TABLE keyData ( id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,  rev INTEGER NOT NULL DEFAULT 1,  zoneId INTEGER NOT NULL,  hsmKeyId INTEGER NOT NULL,  algorithm UNSIGNED INT NOT NULL,  inception UNSIGNED INT NOT NULL,  role INT NOT NULL,  introducing UNSIGNED INT NOT NULL,  shouldRevoke UNSIGNED INT NOT NULL,  standby UNSIGNED INT NOT NULL,  activeZsk UNSIGNED INT NOT NULL,  publish UNSIGNED INT NOT NULL,  activeKsk UNSIGNED INT NOT NULL,  dsAtParent INT NOT NULL,  keytag UNSIGNED INT NOT",
    " NULL,  minimize UNSIGNED INT NOT NULL, reason TEXT DEFAULT \"\")",
    0,
    "CREATE INDEX keyDataZoneId ON keyData ( zoneId )",
    0,
    "CREATE INDEX keyDataHsmKeyId ON keyData ( hsmKeyId )",
    0,
    "CREATE TABLE keyState ( id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,  rev INTEGER NOT NULL DEFAULT 1,  keyDataId INTEGER NOT NULL,  type INT NOT NULL,  state INT NOT NULL,  lastChange UNSIGNED INT NOT NULL,  minimize UNSIGNED INT NOT NULL,  ttl UNSIGNED INT NOT NULL, reason TEXT DEFAULT \"\")",
    0,
    "CREATE INDEX keyStateKeyDataId ON keyState ( keyDataId )",
    0,
    "CREATE TABLE keyDependency ( id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,  rev INTEGER NOT NULL DEFAULT 1,  zoneId INTEGER NOT NULL,  fromKeyDataId INTEGER NOT NULL,  toKeyDataId INTEGER NOT NULL,  type INT NOT NULL)",
    0,
    "CREATE INDEX keyDependencyZoneId ON keyDependency ( zoneId )",
    0,
    "CREATE INDEX keyDependencyFromKeyDataId ON keyDependency ( fromKeyDataId )",
    0,
    "CREATE INDEX keyDependencyToKeyDataId ON keyDependency ( toKeyDataId )",
    0,
    "CREATE TABLE hsmKey ( id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,  rev INTEGER NOT NULL DEFAULT 1,  policyId INTEGER NOT NULL,  locator TEXT NOT NULL,  state INT NOT NULL,  bits UNSIGNED INT NOT NULL,  algorithm UNSIGNED INT NOT NULL,  role INT NOT NULL,  inception UNSIGNED INT NOT NULL,  isRevoked UNSIGNED INT NOT NULL,  keyType INT NOT NULL,  repository TEXT NOT NULL,  backup INT NOT NULL,  reason TEXT DEFAULT \"\")",
    0,
    "CREATE INDEX hsmKeyPolicyId ON hsmKey ( policyId )",
    0,
    "CREATE UNIQUE INDEX hsmKeyLocator ON hsmKey ( locator )",
    0,
    "CREATE TABLE policy ( id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,  rev INTEGER NOT NULL DEFAULT 1,  name TEXT NOT NULL,  description TEXT NOT NULL,  signaturesResign UNSIGNED INT NOT NULL,  signaturesRefresh UNSIGNED INT NOT NULL,  signaturesJitter UNSIGNED INT NOT NULL,  signaturesInceptionOffset UNSIGNED INT NOT NULL,  signaturesValidityDefault UNSIGNED INT NOT NULL,  signaturesValidityDenial UNSIGNED INT NOT NULL,  signaturesValidityKeyset UNSIGNED INT,  signaturesMaxZoneTtl UNSIGNED INT NOT NULL,  denialType INT NOT NULL,  deni",
    "alOptout UNSIGNED INT NOT NULL,  denialTtl UNSIGNED INT NOT NULL,  denialResalt UNSIGNED INT NOT NULL,  denialAlgorithm UNSIGNED INT NOT NULL,  denialIterations UNSIGNED INT NOT NULL,  denialSaltLength UNSIGNED INT NOT NULL,  denialSalt TEXT NOT NULL,  denialSaltLastChange UNSIGNED INT NOT NULL,  keysTtl UNSIGNED INT NOT NULL,  keysRetireSafety UNSIGNED INT NOT NULL,  keysPublishSafety UNSIGNED INT NOT NULL,  keysShared UNSIGNED INT NOT NULL,  keysPurgeAfter UNSIGNED INT NOT NULL,  zonePropagati",
    "onDelay UNSIGNED INT NOT NULL,  zoneSoaTtl UNSIGNED INT NOT NULL,  zoneSoaMinimum UNSIGNED INT NOT NULL,  zoneSoaSerial INT NOT NULL,  parentRegistrationDelay UNSIGNED INT NOT NULL,  parentPropagationDelay UNSIGNED INT NOT NULL,  parentDsTtl UNSIGNED INT NOT NULL,  parentSoaTtl UNSIGNED INT NOT NULL,  parentSoaMinimum UNSIGNED INT NOT NULL,  passthrough UNSIGNED INT NOT NULL)",
    0,
    "CREATE UNIQUE INDEX policyName ON policy ( name )",
    0,
    "CREATE TABLE policyKey ( id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,  rev INTEGER NOT NULL DEFAULT 1,  policyId INTEGER NOT NULL,  role INT NOT NULL,  algorithm UNSIGNED INT NOT NULL,  bits UNSIGNED INT NOT NULL,  lifetime UNSIGNED INT NOT NULL,  repository TEXT NOT NULL,  standby UNSIGNED INT NOT NULL,  manualRollover UNSIGNED INT NOT NULL,  rfc5011 UNSIGNED INT NOT NULL,  minimize UNSIGNED INT NOT NULL)",
    0,
    "CREATE INDEX policyKeyPolicyId ON policyKey ( policyId )",
    0,
    "CREATE TABLE databaseVersion ( id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,  rev INTEGER NOT NULL DEFAULT 1,  version UNSIGNED INT NOT NULL)",
    0,
    0
};

const char* db_schema_sqlite_drop[] = {
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
