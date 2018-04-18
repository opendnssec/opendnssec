#!/usr/bin/env bash

#TEST: Test look-ahead command

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&
ods_reset_env &&

echo -n "LINE: ${LINENO} " && ods_start_enforcer &&

# First scenario
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-look-ahead-list1 ods-enforcer look-ahead -z ods -s 15 &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "0[[:space:]]*KSK[[:space:]]*hidden[[:space:]]*rumoured[[:space:]]*rumoured[[:space:]]*NA.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "0[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*rumoured[[:space:]]*NA[[:space:]]*rumoured.*1[[:space:]]*1" &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "2[[:space:]]*KSK[[:space:]]*rumoured[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*waiting for ds-submit[[:space:]]*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "2[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*omnipresent.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "2 - Submitting DS to parent zone." &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "3[[:space:]]*KSK[[:space:]]*rumoured[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*waiting for ds-seen[[:space:]]*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "3 - Marking DS as seen." &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "5[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*NA.*1[[:space:]]*1" &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "6[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*NA.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "6[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*omnipresent.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "6[[:space:]]*KSK[[:space:]]*hidden[[:space:]]*rumoured[[:space:]]*rumoured[[:space:]]*NA.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "6[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*rumoured[[:space:]]*NA[[:space:]]*hidden.*1[[:space:]]*0" &&

echo "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "7 - Removing DS from parent zone." &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "7 - Submitting DS to parent zone." &&

echo "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "8 - Marking DS as gone." &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "8 - Marking DS as seen." &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "13[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*NA.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "13[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*omnipresent.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "13[[:space:]]*KSK[[:space:]]*hidden[[:space:]]*hidden[[:space:]]*hidden[[:space:]]*NA.*0[[:space:]]*0" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list1 stdout "13[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*hidden[[:space:]]*NA[[:space:]]*hidden.*0[[:space:]]*0" &&

echo "LINE: ${LINENO} " && log_grep_count ods-enforcer-look-ahead-list1 stdout "15[[:space:]]*ZSK" 1 &&
echo "LINE: ${LINENO} " && log_grep_count ods-enforcer-look-ahead-list1 stdout "15[[:space:]]*KSK" 1 &&

# Second Scenario: algorithm change
echo -n "LINE: ${LINENO} " && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-submit --all && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen --all && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap && sleep 3 &&
# Now both ksk and zsk are active
echo -n "LINE: ${LINENO} " && cp kasp-alg-switch.xml "$INSTALL_ROOT/etc/opendnssec/kasp.xml" && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer policy import && sleep 3 &&
# Number of steps is 10 by default
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-look-ahead-list2 ods-enforcer look-ahead -z ods &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "0[[:space:]]*KSK[[:space:]]*hidden[[:space:]]*rumoured[[:space:]]*rumoured[[:space:]]*NA.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "0[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*rumoured[[:space:]]*NA[[:space:]]*rumoured.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "0[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*NA.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "0[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*omnipresent.*1[[:space:]]*1" &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "2[[:space:]]*KSK[[:space:]]*rumoured[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*waiting for ds-submit[[:space:]]*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "2[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*omnipresent.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "2[[:space:]]*KSK[[:space:]]*unretentive[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*waiting for ds-retract[[:space:]]*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "2[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*omnipresent.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "2 - Removing DS from parent zone." &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "2 - Submitting DS to parent zone." &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "3 - Marking DS as gone." &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "3 - Marking DS as seen." &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "7[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*NA.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "7[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*omnipresent.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "7[[:space:]]*KSK[[:space:]]*hidden[[:space:]]*hidden[[:space:]]*hidden[[:space:]]*NA.*0[[:space:]]*0" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "7[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*hidden[[:space:]]*NA[[:space:]]*hidden.*0[[:space:]]*0" &&

echo "LINE: ${LINENO} " && log_grep_count ods-enforcer-look-ahead-list2 stdout "9[[:space:]]*ZSK" 1 &&
echo "LINE: ${LINENO} " && log_grep_count ods-enforcer-look-ahead-list2 stdout "9[[:space:]]*KSK" 1 &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "10[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*NA.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "10[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*omnipresent[[:space:]]*NA[[:space:]]*omnipresent.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "10[[:space:]]*KSK[[:space:]]*hidden[[:space:]]*rumoured[[:space:]]*rumoured[[:space:]]*NA.*1[[:space:]]*1" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-look-ahead-list2 stdout "10[[:space:]]*ZSK[[:space:]]*NA[[:space:]]*rumoured[[:space:]]*NA[[:space:]]*hidden.*1[[:space:]]*0" &&

echo -n "LINE: ${LINENO} " && ods_stop_enforcer &&
return 0

echo
echo "************ERROR******************"
echo
ods-enforcer key list -dp
ods-enforcer key list -v
ods_kill
return 1
