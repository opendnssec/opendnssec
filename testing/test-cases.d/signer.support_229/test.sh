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

# entrypoint
[ -n "$HAVE_MYSQL" ] && ods_setup_conf conf.xml conf-mysql.xml

# ensure we start from a clean setup
ods_reset_env &&

# start both enforcer and signer
ods_start_ods-control &&

capture_dnskey_ids() {
    ZONE_NAME="$1"
    FLAGS_VALUE_TO_MATCH="$2"
    COMMENT_TXT_TO_MATCH="$3"
    ZONE_FILE_PATH="${SIGNED_ZONES}/${ZONE_NAME}"
    grep -E -- "^${ZONE_NAME}\.[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+DNSKEY[[:space:]]+${FLAGS_VALUE_TO_MATCH}" ${ZONE_FILE_PATH} \
        | grep -Eo 'id = [0-9]+ \('${COMMENT_TXT_TO_MATCH}'\)' \
        | grep -Eo '[0-9]+' \
        | sort \
        | uniq
}

pretty_print_multiline_value_as_space_separated_single_line_value() {
    for VALUE in $*; do
        echo $VALUE | tr '[:space:]' ' '
    done
}

find_orphaned_signatures() {
    ZONE_NAME="$1"
    ZONE_FILE_PATH="${SIGNED_ZONES}/${ZONE_NAME}"

    echo -n "Capturing KSK ids from zone file DNSKEY RR comments.. "
    KSK_IDS=$(capture_dnskey_ids "${ZONE_NAME}" 257 ksk)
    pretty_print_multiline_value_as_space_separated_single_line_value ${KSK_IDS}
    echo

    echo -n "Capturing ZSK ids from zone file DNSKEY RR comments.. "
    ZSK_IDS=$(capture_dnskey_ids "${ZONE_NAME}" 256 zsk)
    pretty_print_multiline_value_as_space_separated_single_line_value ${ZSK_IDS}
    echo

    echo -n "Capturing DNSKEY RRSIG keytags from zone file.. "
    DNSKEY_RRSIG_KEYTAGS=$(grep -E -- "^${ZONE_NAME}\.[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+RRSIG[[:space:]]DNSKEY" ${ZONE_FILE_PATH} | awk '{print $11}' | sort | uniq)
    pretty_print_multiline_value_as_space_separated_single_line_value ${DNSKEY_RRSIG_KEYTAGS}
    echo

    echo -n "Capturing non-DNSKEY RRSIG keytags from zone file.. "
    NON_DNSKEY_RRSIG_KEYTAGS=$(grep -E -- "^${ZONE_NAME}\.[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+RRSIG[[:space:]]" ${ZONE_FILE_PATH} | \
        grep -Ev -- "^${ZONE_NAME}\.[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+RRSIG[[:space:]]DNSKEY" | awk '{print $11}' | sort | uniq)
    pretty_print_multiline_value_as_space_separated_single_line_value ${NON_DNSKEY_RRSIG_KEYTAGS}
    echo

    for DNSKEY_RRSIG_KEYTAG in $DNSKEY_RRSIG_KEYTAGS; do
        echo -n "Checking that a KSK exists with id equal to DNSKEY RRSIG keytag ${DNSKEY_RRSIG_KEYTAG}.. "
        echo ${KSK_IDS} | grep -Fwq ${DNSKEY_RRSIG_KEYTAG} && {
            echo "KSK id ${DNSKEY_RRSIG_KEYTAG} found in DNSKEY RR comments"
        } || {
            echo "ERROR: No KSK with id ${DNSKEY_RRSIG_KEYTAG} found in DNSKEY RR comments"
            return 1
        }
    done

    for NON_DNSKEY_RRSIG_KEYTAG in $NON_DNSKEY_RRSIG_KEYTAGS; do
        echo -n "Checking that a ZSK exists with id equal to non-DNSKEY RRSIG keytag ${NON_DNSKEY_RRSIG_KEYTAG}.. "
        echo ${ZSK_IDS} | grep -Fwq ${NON_DNSKEY_RRSIG_KEYTAG} && {
            echo "ZSK id ${NON_DNSKEY_RRSIG_KEYTAG} found in DNSKEY RR comments"
        } || {
            echo "ERROR: No ZSK with id ${NON_DNSKEY_RRSIG_KEYTAG} found in DNSKEY RR comments"
            return 1
        }
    done

    echo "No oprhaned signatures found."

    return 0
}

#########################################################################
# wait for creation and signing of a single simple signed zone
# assumes that the input zone file is present in test subdir unsigned/example.com
# and is mentioned in file zonelist.xml in the test dir
syslog_waitfor 5 'ods-signerd: .*\[STATS\] example.com' &&
test -f "${SIGNED_ZONES}/example.com" &&
#########################################################################

#########################################################################
# check that DNSKEY "id" and RRSIG KEYTAG values (11324 and 52667 here) match, otherwise the zone is broken
# example.com.     3600   IN      DNSKEY  256 3 7 <BASE64> ;{id = 11324 (zsk), size = 1024b}
# example.com.    86400   IN      RRSIG   A 7 2 [0-9]+ 20190403012345 20190312213351 52667 example.com. <BASE64>
log_this cat-example.com-before cat "${SIGNED_ZONES}/example.com" &&
log_this key-status-before ods-enforcer key list --all --verbose &&
find_orphaned_signatures "example.com" &&
#########################################################################

#########################################################################
# leap to the time of the next key generation.
# kasp.xml says the ZSK should be regenerated every 30 days.
log_this ods-enforcer-leap ods_enforcer_leap_over ${THIRTY_ONE_DAYS_IN_SECONDS} &&
#########################################################################

#########################################################################
# as above check for mismatched DNSKEY "id" and RRSIG.
# if the bug is present this will fail.
log_this cat-example.com.xml-after cat "${SIGNCONF_FILE}" &&
log_this cat-example.com-after cat "${SIGNED_ZONES}/example.com" &&
log_this key-status-after ods-enforcer key list --all --verbose &&
find_orphaned_signatures "example.com" &&
#########################################################################

# Shutdown
ods_stop_ods-control &&

# NOTE: You can change this to "return 1" to prevent testdir/_xxx log files being cleaned up
return 0

# One of the statements above failed, abort.
echo '*********** ERROR **********'
ods_kill
return 1
