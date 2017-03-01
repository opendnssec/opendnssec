/* This file was derrived from sqlite version. Some weird constructs are to
 * work around sqlite's limitations.
 */

INSERT INTO databaseVersion VALUES (NULL, 1, 1);

-- ~ ************
-- ~ ** policy table
-- ~ **
-- ~ **
-- ~ **
-- ~ **
-- ~ ************

INSERT INTO policy
SELECT id, 1, name, description,
0, 0, 0,
0, 0, 0, 0,
86400, 0, 0,
0, 0, 0,
0, 0, 0,
0, 0, 0,
0, 0, 0,
0, 0, 0,
0, 0, 0,
0, 0, 0,
0
FROM REMOTE.policies;

UPDATE policy
SET signaturesResign = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 1
		AND REMOTE.parameters.name = 'resign');

UPDATE policy
SET signaturesRefresh = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 1
		AND REMOTE.parameters.name = 'refresh') ;

UPDATE policy
SET signaturesJitter = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 1
		AND REMOTE.parameters.name = 'jitter');

UPDATE policy
SET signaturesInceptionOffset = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 1
		AND REMOTE.parameters.name = 'clockskew');

UPDATE policy
SET signaturesValidityDefault = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 1
		AND REMOTE.parameters.name = 'valdefault');

UPDATE policy
SET signaturesValidityDenial = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 1
		AND REMOTE.parameters.name = 'valdenial');

-- MaxZoneTTL default 86400

-- We need the following mapping 1.4 -> 2.0 for denialType
-- 0 -> 1
-- 3 -> 0

UPDATE policy, REMOTE.parameters_policies, REMOTE.parameters
SET policy.denialType = (~REMOTE.parameters_policies.value)&1
WHERE REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	AND REMOTE.parameters_policies.policy_id = policy.id
	AND REMOTE.parameters.category_id = 2
	AND REMOTE.parameters.name = 'version';

UPDATE policy, REMOTE.parameters, REMOTE.parameters_policies
SET policy.denialOptout = REMOTE.parameters_policies.value
WHERE REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	AND REMOTE.parameters_policies.policy_id = policy.id
	AND REMOTE.parameters.category_id = 2
	AND REMOTE.parameters.name = 'optout';

UPDATE policy, REMOTE.parameters, REMOTE.parameters_policies
SET policy.denialTtl = REMOTE.parameters_policies.value
WHERE REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	AND REMOTE.parameters_policies.policy_id = policy.id
	AND REMOTE.parameters.category_id = 2
	AND REMOTE.parameters.name = 'ttl';

UPDATE policy, REMOTE.parameters, REMOTE.parameters_policies
SET policy.denialResalt = REMOTE.parameters_policies.value
WHERE REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	AND REMOTE.parameters_policies.policy_id = policy.id
	AND REMOTE.parameters.category_id = 2
	AND REMOTE.parameters.name = 'resalt';

UPDATE policy, REMOTE.parameters, REMOTE.parameters_policies
SET policy.denialAlgorithm = REMOTE.parameters_policies.value
WHERE REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	AND REMOTE.parameters_policies.policy_id = policy.id
	AND REMOTE.parameters.category_id = 2
	AND REMOTE.parameters.name = 'algorithm';

UPDATE policy, REMOTE.parameters, REMOTE.parameters_policies
SET policy.denialIterations = REMOTE.parameters_policies.value
WHERE REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	AND REMOTE.parameters_policies.policy_id = policy.id
	AND REMOTE.parameters.category_id = 2
	AND REMOTE.parameters.name = 'iterations';

UPDATE policy, REMOTE.parameters, REMOTE.parameters_policies
SET policy.denialSaltLength = REMOTE.parameters_policies.value
WHERE REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	AND REMOTE.parameters_policies.policy_id = policy.id
	AND REMOTE.parameters.category_id = 2
	AND REMOTE.parameters.name = 'saltlength';

UPDATE policy, REMOTE.policies
SET denialSalt = REMOTE.policies.salt
WHERE REMOTE.policies.id = policy.id
	AND REMOTE.policies.salt IS NOT NULL;

UPDATE policy, REMOTE.policies
SET denialSaltLastChange = UNIX_TIMESTAMP(REMOTE.policies.salt_stamp)
WHERE REMOTE.policies.id = policy.id
	AND REMOTE.policies.salt_stamp IS NOT NULL;

UPDATE policy
SET keysTtl = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 5
		AND REMOTE.parameters.name = 'ttl');

UPDATE policy
SET keysRetireSafety = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 5
		AND REMOTE.parameters.name = 'retiresafety');

UPDATE policy
SET keysPublishSafety = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 5
		AND REMOTE.parameters.name = 'publishsafety');

UPDATE policy
SET keysShared = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 5
		AND REMOTE.parameters.name = 'zones_share_keys');

UPDATE policy
SET keysPurgeAfter = COALESCE((
        SELECT value
        FROM  REMOTE.parameters_policies
        INNER JOIN REMOTE.parameters
        ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
        WHERE REMOTE.parameters_policies.policy_id = policy.id
                AND REMOTE.parameters.category_id = 5
                AND REMOTE.parameters.name = 'purge'), 0);

UPDATE policy
SET zonePropagationDelay = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 7
		AND REMOTE.parameters.name = 'propagationdelay');

UPDATE policy
SET zoneSoaTtl = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 7
		AND REMOTE.parameters.name = 'ttl');

UPDATE policy
SET zoneSoaMinimum = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 7
		AND REMOTE.parameters.name = 'min');

-- Temporary mapping table between 1.4 and 2.0 SOA serial strategy
CREATE TABLE mapping (
	soa14 INTEGER,
	soa20 INTEGER
);
INSERT INTO mapping SELECT  1, 2;
INSERT INTO mapping SELECT  2, 0;
INSERT INTO mapping SELECT  3, 1;
INSERT INTO mapping SELECT  4, 3;

UPDATE policy
SET zoneSoaSerial = (
	SELECT mapping.soa20
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
        INNER JOIN mapping
        ON REMOTE.parameters_policies.value = mapping.soa14
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 7
		AND REMOTE.parameters.name = 'serial');

DROP TABLE mapping;

-- parentRegistrationDelay = 0 on 1.4

UPDATE policy
SET parentPropagationDelay = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 8
		AND REMOTE.parameters.name = 'propagationdelay');

UPDATE policy
SET parentDsTtl = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 8
		AND REMOTE.parameters.name = 'ttlds');

UPDATE policy
SET parentSoaTtl = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 8
		AND REMOTE.parameters.name = 'ttl');

UPDATE policy
SET parentSoaMinimum = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policy.id
		AND REMOTE.parameters.category_id = 8
		AND REMOTE.parameters.name = 'min');

-- passthrough = 0

-- ~ ************
-- ~ ** policyKey table
-- ~ **
-- ~ ** For each policy in 1.4 add two keys: KSK and ZSK
-- ~ **
-- ~ **
-- ~ ************

-- Insert each KSK
INSERT INTO policyKey
SELECT null, 1, id,
		1, 0, 0,
		0, 0, 0,
		0, 0, 4
FROM REMOTE.policies;

-- Insert each ZSK
INSERT INTO policyKey
SELECT null, 1, id,
		2, 0, 0,
		0, 0, 0,
		0, 0, 1
FROM REMOTE.policies;

UPDATE policyKey
SET algorithm = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 3
		AND REMOTE.parameters.name = 'algorithm')
WHERE policyKey.role = 1;

UPDATE policyKey
SET algorithm = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 4
		AND REMOTE.parameters.name = 'algorithm')
WHERE policyKey.role = 2;

UPDATE policyKey
SET bits = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 3
		AND REMOTE.parameters.name = 'bits')
WHERE policyKey.role = 1;

UPDATE policyKey
SET bits = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 4
		AND REMOTE.parameters.name = 'bits')
WHERE policyKey.role = 2;

UPDATE policyKey
SET lifetime = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 3
		AND REMOTE.parameters.name = 'lifetime')
WHERE policyKey.role = 1;

UPDATE policyKey
SET lifetime = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 4
		AND REMOTE.parameters.name = 'lifetime')
WHERE policyKey.role = 2;

UPDATE policyKey
SET repository = (
	SELECT REMOTE.securitymodules.name
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	INNER JOIN REMOTE.securitymodules
	ON REMOTE.parameters_policies.value = REMOTE.securitymodules.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 3
		AND REMOTE.parameters.name = 'repository')
WHERE policyKey.role = 1;

UPDATE policyKey
SET repository = (
	SELECT REMOTE.securitymodules.name
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	INNER JOIN REMOTE.securitymodules
	ON REMOTE.parameters_policies.value = REMOTE.securitymodules.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 4
		AND REMOTE.parameters.name = 'repository')
WHERE policyKey.role = 2;

UPDATE policyKey
SET standby = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 3
		AND REMOTE.parameters.name = 'standby')
WHERE policyKey.role = 1;

UPDATE policyKey
SET standby = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 4
		AND REMOTE.parameters.name = 'standby')
WHERE policyKey.role = 2;

UPDATE policyKey
SET manualRollover = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 3
		AND REMOTE.parameters.name = 'manual_rollover')
WHERE policyKey.role = 1;

UPDATE policyKey
SET manualRollover = (
	SELECT value
	FROM  REMOTE.parameters_policies
	INNER JOIN REMOTE.parameters
	ON REMOTE.parameters_policies.parameter_id = REMOTE.parameters.id
	WHERE REMOTE.parameters_policies.policy_id = policyKey.policyId
		AND REMOTE.parameters.category_id = 4
		AND REMOTE.parameters.name = 'manual_rollover')
WHERE policyKey.role = 2;

-- rfc5011 = 0. 2.0 has no support
-- minimize already set

-- ~ ************
-- ~ ** hsmKey table
-- ~ **
-- ~ ** get from keypairs and dnsseckeys
-- ~ **
-- ~ **
-- ~ ************

INSERT INTO hsmKey
SELECT DISTINCT REMOTE.keypairs.id, 1, REMOTE.keypairs.policy_id,
REMOTE.keypairs.HSMkey_id, 2, REMOTE.keypairs.size,
REMOTE.keypairs.algorithm,  (~(REMOTE.dnsseckeys.keytype)&1)+1,
CASE WHEN REMOTE.keypairs.generate IS NOT NULL THEN
	UNIX_TIMESTAMP(REMOTE.keypairs.generate)
	ELSE UNIX_TIMESTAMP() END,
0,
1, -- only RSA supported
 REMOTE.securitymodules.name,
0 -- assume no backup
FROM REMOTE.keypairs
JOIN REMOTE.dnsseckeys
	ON REMOTE.keypairs.id = REMOTE.dnsseckeys.keypair_id
JOIN REMOTE.securitymodules
	ON REMOTE.securitymodules.id = REMOTE.keypairs.securitymodule_id;

-- For some policies put the keys in a shared state
UPDATE hsmKey, policy
SET hsmKey.state = 3
WHERE policy.id = hsmKey.policyId AND policy.keysShared != 0;

-- ~ ************
-- ~ ** zone table
-- ~ **
-- ~ **
-- ~ **
-- ~ **
-- ~ ************

INSERT INTO zone
SELECT zones.id, 1, zones.policy_id,
	zones.name, 1, zones.signconf, 0, 
	0,0,0,
	0,0,0,
	zones.in_type, zones.input,
	zones.out_type, zones.output,
	0,0,0
	FROM REMOTE.zones;

-- ~ ************
-- ~ ** ketData table
-- ~ **
-- ~ **
-- ~ **
-- ~ **
-- ~ ************

-- Temporary mapping table between 1.4 states and 2.0 ds_at_parent states
-- We are ignoring the fact this may set a DS state for a ZSK; We don't care
CREATE TABLE mapping (
	state INTEGER,
	ds_state INTEGER
);
INSERT INTO mapping SELECT  1, 0;
INSERT INTO mapping SELECT  2, 0;
INSERT INTO mapping SELECT  3, 1;
INSERT INTO mapping SELECT  4, 3;
INSERT INTO mapping SELECT  5, 5;
INSERT INTO mapping SELECT  6, 5;
INSERT INTO mapping SELECT  7, 5;
INSERT INTO mapping SELECT  8, 5;
INSERT INTO mapping SELECT  9, 5;
INSERT INTO mapping SELECT 10, 5;

INSERT INTO keyData
SELECT
	NULL, 1, REMOTE.dnsseckeys.zone_id,
	REMOTE.dnsseckeys.keypair_id, REMOTE.keypairs.algorithm,
	CASE WHEN REMOTE.dnsseckeys.publish IS NOT NULL THEN
		UNIX_TIMESTAMP(REMOTE.dnsseckeys.publish)
		ELSE UNIX_TIMESTAMP() END,
	(~REMOTE.dnsseckeys.keytype&1)+1,
	REMOTE.dnsseckeys.state <= 4, -- introducing
	0, -- should revoke, not used
	0, -- standby
	REMOTE.dnsseckeys.state  = 4 AND REMOTE.dnsseckeys.keytype = 256, -- activeZSK:
	REMOTE.dnsseckeys.state >= 2 AND REMOTE.dnsseckeys.state <= 5, -- publish
	REMOTE.dnsseckeys.state  = 4 AND REMOTE.dnsseckeys.keytype = 257, -- activeKSK:
	mapping.ds_state, -- dsatparent
	1<<16, -- keytag (crap, will 2.0 regenerate this?)
	(REMOTE.dnsseckeys.keytype&1)*3+1 -- minimize
FROM REMOTE.dnsseckeys
JOIN REMOTE.keypairs
	ON REMOTE.dnsseckeys.keypair_id = REMOTE.keypairs.id
JOIN mapping
	ON REMOTE.dnsseckeys.state = mapping.state
WHERE EXISTS(select REMOTE.zones.id FROM REMOTE.zones WHERE REMOTE.zones.id = REMOTE.dnsseckeys.zone_id);

UPDATE keyData
SET dsatparent = 0
WHERE role = 2;

DROP TABLE mapping;

-- If an active time is set for a ready KSK dsAtParent is submitted
-- instead of submit
UPDATE keyData, REMOTE.dnsseckeys
SET keyData.dsatparent = 2
WHERE keyData.dsAtParent = 1
	AND REMOTE.dnsseckeys.keypair_id = keyData.hsmkeyid
	AND REMOTE.dnsseckeys.active IS NOT NULL;

-- ~ ************
-- ~ ** Keystate table
-- ~ **
-- ~ **
-- ~ **
-- ~ **
-- ~ ************

CREATE TABLE mapping (
	state INTEGER,
	ds INTEGER,
	dk INTEGER,
	ks INTEGER,
	rs INTEGER
);
INSERT INTO mapping SELECT  1, 0, 0, 0, 0;
INSERT INTO mapping SELECT  2, 0, 1, 1, 1;
INSERT INTO mapping SELECT  3, 0, 2, 2, 1;
INSERT INTO mapping SELECT  4, 2, 2, 2, 1;
INSERT INTO mapping SELECT  5, 3, 2, 2, 3;
INSERT INTO mapping SELECT  6, 0, 3, 3, 0;
INSERT INTO mapping SELECT  7, 3, 0, 0, 0;
INSERT INTO mapping SELECT  8, 3, 0, 0, 0;
INSERT INTO mapping SELECT  9, 3, 0, 0, 0;
INSERT INTO mapping SELECT 10, 3, 0, 0, 0;

-- DS RECORDS
INSERT INTO keyState
SELECT NULL, 1, keyData.id, 0, mapping.ds, UNIX_TIMESTAMP(), (keyData.minimize>>2)&1, policy.parentDsTtl
FROM keyData
JOIN zone
	ON zone.id = keyData.zoneId
JOIN policy
	ON policy.id = zone.policyId
JOIN REMOTE.dnsseckeys
	ON REMOTE.dnsseckeys.keypair_id = keyData.hsmkeyid
JOIN mapping
	ON mapping.state = REMOTE.dnsseckeys.state;

UPDATE keyState, keyData, REMOTE.dnsseckeys
SET keyState.state = 1
WHERE keyState.state = 0
	AND keyState.type = 0
	AND keyData.id = keyState.keydataId
	AND REMOTE.dnsseckeys.keypair_id = keyData.hsmkeyid
	AND REMOTE.dnsseckeys.active IS NOT NULL;

-- DNSKEY RECORDS
INSERT INTO keyState
SELECT NULL, 1, keyData.id, 2, mapping.dk, UNIX_TIMESTAMP(), (keyData.minimize>>1)&1, policy.keysTtl
FROM keyData
JOIN zone
	ON zone.id = keyData.zoneId
JOIN policy
	ON policy.id = zone.policyId
JOIN REMOTE.dnsseckeys
	ON REMOTE.dnsseckeys.keypair_id = keyData.hsmkeyid
JOIN mapping
	ON mapping.state = REMOTE.dnsseckeys.state;

-- RRSIG DNSKEY RECORDS
INSERT INTO keyState
SELECT NULL, 1, keyData.id, 3, mapping.ks, UNIX_TIMESTAMP(), (keyData.minimize>>1)&1, policy.keysTtl
FROM keyData
JOIN zone
	ON zone.id = keyData.zoneId
JOIN policy
	ON policy.id = zone.policyId
JOIN REMOTE.dnsseckeys
	ON REMOTE.dnsseckeys.keypair_id = keyData.hsmkeyid
JOIN mapping
	ON mapping.state = REMOTE.dnsseckeys.state;

-- RRSIG RECORDS
INSERT INTO keyState
SELECT NULL, 1, keyData.id, 1, mapping.rs, UNIX_TIMESTAMP(), (keyData.minimize>>0)&1, policy.signaturesMaxZoneTtl
FROM keyData
JOIN zone
	ON zone.id = keyData.zoneId
JOIN policy
	ON policy.id = zone.policyId
JOIN REMOTE.dnsseckeys
	ON REMOTE.dnsseckeys.keypair_id = keyData.hsmkeyid
JOIN mapping
	ON mapping.state = REMOTE.dnsseckeys.state;

CREATE TABLE tmp (
	id INTEGER
);

INSERT INTO tmp
SELECT rs.id
FROM keyState AS rs
JOIN keyData
        ON keyData.id = rs.keydataId
JOIN REMOTE.dnsseckeys
        ON REMOTE.dnsseckeys.keypair_id = keyData.hsmkeyid
JOIN zone
        ON keyData.zoneId = zone.id
JOIN policy
        ON policy.id = zone.policyId
WHERE (UNIX_TIMESTAMP(REMOTE.dnsseckeys.active) + policy.signaturesValidityDefault) < UNIX_TIMESTAMP();

-- Set to OMN if Tactive + Dttl < Tnow
UPDATE keyState
SET keyState.state = 2
WHERE keyState.state = 1
AND keyState.type = 1 AND EXISTS(SELECT id FROM tmp where id = keyState.id);

DROP TABLE tmp;

CREATE TABLE tmp (
	id INTEGER
);

INSERT tmp
SELECT rs.id FROM keyState AS rs
JOIN keyState AS dk ON dk.keyDataId = rs.keyDataId
WHERE rs.type = 1 AND dk.type = 2 AND rs.state = 1 AND dk.state = 2
AND NOT EXISTS(
	SELECT* FROM keyState AS rs2
	JOIN keyState AS dk2 ON dk2.keyDataId = rs2.keyDataId
	WHERE rs2.type = 1 AND dk2.type = 2 AND rs2.state = 3 AND dk2.state = 2
);

-- Force the RRSIG state in omnipresent if rumoured and there is no old ZSK
-- unretentive
UPDATE keyState
SET state = 2
WHERE EXISTS(SELECT id FROM tmp WHERE id = keyState.id);
DROP TABLE tmp;
DROP TABLE mapping;

-- We need to create records in the keydependency table in case we are in a
-- rollover. Only done for ZSK. For every introducing ZSK with RRSIG rumoured
-- that has an outroducing ZSK with RRSIG unretentive, we add a record.
INSERT INTO keyDependency
SELECT NULL, 0, keyData.zoneID, SUB.IDout, keyData.id, 1
FROM keyData
JOIN keyState AS KS1
	ON KS1.keyDataId = keyData.id
JOIN keyState AS KS2
	ON KS2.keyDataId = keyData.id
JOIN (
	SELECT keyData.id AS IDout, keyData.zoneID
	FROM keyData
	JOIN keyState AS KS1
		ON KS1.keyDataId = keyData.id
	JOIN keyState AS KS2
		ON KS2.keyDataId = keyData.id
	WHERE KS1.type = 2
		AND KS1.state = 2
		AND KS2.type = 1
		AND KS2.state = 3
		AND keyData.introducing = 0
		AND keyData.role = 2
) AS SUB
	ON SUB.zoneId = keyData.zoneId
WHERE
	KS1.type = 2
	AND KS1.state = 2
	AND KS2.type = 1
	AND KS2.state = 1;

UPDATE keyState
SET state = 4
WHERE (keyState.type = 0 OR keyState.type = 3) AND keyDataId IN (
	       SELECT keyData.id
	       FROM keyData
	       WHERE keyData.role = 2);

UPDATE keyState
SET state = 4
WHERE keyState.type = 1 AND keyDataId IN (
	       SELECT keyData.id
	       FROM keyData
	       WHERE keyData.role = 1);
