#!/usr/bin/env bash
#
# Regression test case for SUPPORT-229: Broken zone when ODS replaces the DNSKEY but does not re-sign RRsets using the new DNSKEY.
# Specifically, after the ZSK <Lifetime> period but before the <Refresh> period, with the customers kasp.xml settings ODS replaces
# the only ZSK DNSKEY (used to create the RRSIGs in the zone) with a new one but does NOT replace the RRSIGs, so the RRSIG records
# are unusable because the DNSKEY they must be verified against no longer exists in the zone.
#
# TO DO: Is the missing DNSKEY lacking the <Publish/> stanza in the signconf? YES it is - augment the test to check this?
# TO DO: Match RRSIGs against DNSKEYs using something better than relying on zone comments?
# TO DO: Base the leap time on the actual kasp.xml ZSK <Lifetime> value, not a hard-coded leap time.
# TO DO: Understand why it breaks after 31 days but not after 30 days.
# TO DO: Refactor into more helper functions?
# TO DO: Reduce to the simplest reproduction scenario, e.g. without enforcer(d) but only with signer(d) using constructed signconf.
#
SIGNED_ZONES="$INSTALL_ROOT/var/opendnssec/signed"
SIGNCONF_FILE="${INSTALL_ROOT}/var/opendnssec/signconf/example.com.xml"
TESTDIR=$(dirname $0)
THIRTY_ONE_DAYS_IN_SECONDS=$((31*24*60*60))
LIGHT_GREEN='\033[0;92m'
NO_COLOUR='\033[0m'

# helper functions
l() {
    echo -en "${LIGHT_GREEN}$(date -u +'%b %d %H:%M:%S') UTC: LINE $1: ${NO_COLOUR}"
}

# entrypoint
[ -n "$HAVE_MYSQL" ] && ods_setup_conf conf.xml conf-mysql.xml

# ensure we start from a clean setup
l $LINENO && ods_reset_env &&

# start both enforcer and signer
l $LINENO && ods_start_ods-control &&

#########################################################################
# wait for creation and signing of a single simple signed zone
# assumes that the input zone file is present in test subdir unsigned/example.com
# and is mentioned in file zonelist.xml in the test dir
l $LINENO && syslog_waitfor 5 'ods-signerd: .*\[STATS\] example.com' &&
l $LINENO && test -f "${SIGNED_ZONES}/example.com" &&
#########################################################################

#########################################################################
# check that DNSKEY "id" and RRSIG KEYTAG values (11324 and 52667 here) match, otherwise the zone is broken
# example.com.     3600   IN      DNSKEY  256 3 7 <BASE64> ;{id = 11324 (zsk), size = 1024b}
# example.com.    86400   IN      RRSIG   A 7 2 [0-9]+ 20190403012345 20190312213351 52667 example.com. <BASE64>
l $LINENO && log_this cat-example.com-before cat "${SIGNED_ZONES}/example.com" &&
l $LINENO && log_this key-status-before ods-enforcer key list --all --verbose &&
l $LINENO && echo -n "Capturing RRSIG A count.." && RRSIG_A_COUNT=$(grep -E -- "^example.com.\s+[0-9]+\s+IN\s+RRSIG\s+A" "${SIGNED_ZONES}/example.com" | wc -l) && echo " ${RRSIG_A_COUNT}" &&
l $LINENO && echo "Checking RRSIG A count ${RRSIG_A_COUNT} == 1.." && [ "${RRSIG_A_COUNT}" -eq "1" ] &&
l $LINENO && echo -n "Capturing ZSK count.." && ZSK_COUNT=$(grep -E -- "^example.com.\s+[0-9]+\s+IN\s+DNSKEY\s+256" "${SIGNED_ZONES}/example.com" | wc -l) && echo " ${ZSK_COUNT}" &&
l $LINENO && echo "Checking ZSK count ${ZSK_COUNT} == 1.." && [ "${ZSK_COUNT}" -eq "1" ] &&
l $LINENO && echo -n "Capturing ZSK KEYTAG (id).." && DNSKEYID=$(grep -E -- "^example.com.\s+[0-9]+\s+IN\s+DNSKEY\s+256" "${SIGNED_ZONES}/example.com" | grep -Eo 'id = [0-9]+ \(zsk\)' | grep -Eo '[0-9]+') && echo " ${DNSKEYID}" &&
l $LINENO && echo -n "Capturing RRSIG A KEYTAG.." && KEYTAG=$(grep -E -- "^example.com.\s+[0-9]+\s+IN\s+RRSIG\s+A" "${SIGNED_ZONES}/example.com" | awk '{print $11}') && echo " ${KEYTAG}" &&
l $LINENO && echo -n "Capturing DNSKEY ${KEYTAG} status.." && ZSKSTATUS=$(ods-enforcer key list --all --verbose | awk '{print $2,$3,$10}' | grep ${KEYTAG}) && echo " ${ZSKSTATUS}" &&
l $LINENO && echo "Checking ZSK ${KEYTAG} is ready.." && [ "${ZSKSTATUS}" == "ZSK ready ${KEYTAG}" ] &&
l $LINENO && echo "Testing KEYTAG equality (DNSKEYID: $DNSKEYID == KEYTAG: $KEYTAG ?).." && [ "${DNSKEYID}" == "${KEYTAG}" ] &&
#########################################################################

#########################################################################
# leap to the time of the next key generation.
# kasp.xml says the ZSK should be regenerated every 30 days.
l $LINENO && log_this ods-enforcer-leap ods_enforcer_leap_over ${THIRTY_ONE_DAYS_IN_SECONDS} &&
#########################################################################

#########################################################################
# as above check for mismatched DNSKEY "id" and RRSIG.
# if the bug is present this will fail.
l $LINENO && log_this cat-example.com.xml-after cat "${SIGNCONF_FILE}" &&
l $LINENO && log_this cat-example.com-after cat "${SIGNED_ZONES}/example.com" &&
l $LINENO && log_this key-status-after ods-enforcer key list --all --verbose &&
l $LINENO && echo -n "Capturing RRSIG A count.." && RRSIG_A_COUNT=$(grep -E -- "^example.com.\s+[0-9]+\s+IN\s+RRSIG\s+A" "${SIGNED_ZONES}/example.com" | wc -l) && echo " ${RRSIG_A_COUNT}" &&
l $LINENO && echo "Checking RRSIG A count ${RRSIG_A_COUNT} == 1.." && [ "${RRSIG_A_COUNT}" -eq "1" ] &&
l $LINENO && echo -n "Capturing ZSK count.." && ZSK_COUNT=$(grep -E -- "^example.com.\s+[0-9]+\s+IN\s+DNSKEY\s+256" "${SIGNED_ZONES}/example.com" | wc -l) && echo " ${ZSK_COUNT}" &&
l $LINENO && echo "Checking ZSK count ${ZSK_COUNT} == 1.." && [ "${ZSK_COUNT}" -eq "1" ] &&
l $LINENO && echo -n "Capturing ZSK KEYTAG (id).." && DNSKEYID=$(grep -E -- "^example.com.\s+[0-9]+\s+IN\s+DNSKEY\s+256" "${SIGNED_ZONES}/example.com" | grep -Eo 'id = [0-9]+ \(zsk\)' | grep -Eo '[0-9]+') && echo " ${DNSKEYID}" &&
l $LINENO && echo -n "Capturing RRSIG A KEYTAG.." && KEYTAG=$(grep -E -- "^example.com.\s+[0-9]+\s+IN\s+RRSIG\s+A" "${SIGNED_ZONES}/example.com" | awk '{print $11}') && echo " ${KEYTAG}" &&
l $LINENO && echo -n "Capturing DNSKEY ${DNSKEYID} status.." && ZSKDNSKEYSTATUS=$(ods-enforcer key list --all --verbose | awk '{print $2,$3,$10}' | grep ${DNSKEYID}) && echo " ${ZSKDNSKEYSTATUS}" &&
l $LINENO && echo -n "Capturing DNSKEY ${KEYTAG} status.." && ZSKKEYTAGSTATUS=$(ods-enforcer key list --all --verbose | awk '{print $2,$3,$10}' | grep ${KEYTAG}) && echo " ${ZSKKEYTAGSTATUS}" &&
l $LINENO && echo "Checking ZSK ${DNSKEYID} is active.." && [ "${ZSKDNSKEYSTATUS}" == "ZSK active ${DNSKEYID}" ] &&
l $LINENO && echo "Checking ZSK ${KEYTAG} is retire.." && [ "${ZSKKEYTAGSTATUS}" == "ZSK retire ${KEYTAG}" ] &&
l $LINENO && echo "Testing KEYTAG equality (DNSKEYID: $DNSKEYID == KEYTAG: $KEYTAG ?).." && [ "${DNSKEYID}" == "${KEYTAG}" ] &&
#########################################################################

# Shutdown
l $LINENO && ods_stop_ods-control &&

# NOTE: You can change this to "return 1" to prevent testdir/_xxx log files being cleaned up
return 0

# One of the statements above failed, abort.
l $LINENO && echo '*********** ERROR **********'
l $LINENO && ods_kill
return 1
