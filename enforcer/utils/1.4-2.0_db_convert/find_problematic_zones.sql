SELECT zones.name
FROM dnsseckeys
JOIN zones on zones.id = dnsseckeys.zone_id
WHERE dnsseckeys.keytype = 257
AND dnsseckeys.active IS NULL
AND dnsseckeys.zone_id NOT IN
	(SELECT dnsseckeys.zone_id
	FROM dnsseckeys
	WHERE dnsseckeys.keytype = 257
	AND dnsseckeys.state = 4)
;
