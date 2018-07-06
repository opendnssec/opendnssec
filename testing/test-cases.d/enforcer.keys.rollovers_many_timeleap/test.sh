#!/usr/bin/env bash
#
#TEST: Test to track key rollovers in 'real' time from the enforcer side only. 
#TEST: Configured with short key lifetimes and 1 min enforcer interval.
#TEST: Checks the output of ods-enforcer key list and the signconf.xml contents
#TEST: Takes about 10 mins and follows several KSK and ZKK rollovers.

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env -i &&

echo -n "LINE: ${LINENO} " && ##################  SETUP TIME 0 ###########################
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output date &&
echo -n "LINE: ${LINENO} " && ods_start_enforcer &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods1 &&


echo -n "LINE: ${LINENO} " && #### TIME 1: Keys are Published/Ready
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 1 -----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect publish/ready" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&

echo -n "LINE: ${LINENO} " && KSK1_CKA=`log_grep -o ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*publish" | awk '{print $8}'` &&
echo -n "LINE: ${LINENO} " && ZSK1_CKA=`log_grep -o ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*ready" | awk '{print $8}'` &&

echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*publish.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*ready.*$ZSK1_CKA" &&
echo -n "LINE: ${LINENO} " && [ ! -z $KSK1_CKA ] &&
echo -n "LINE: ${LINENO} " && [ ! -z $ZSK1_CKA ] &&

echo -n "LINE: ${LINENO} " && rm -f _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 2 -----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&

echo -n "LINE: ${LINENO} " && #### TIME 2: Keys are Ready/Active -> do ds-submit/ds-seen
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 3 -----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect ready(ds-submit)/active" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*ready.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK1_CKA" &&
echo -n "LINE: ${LINENO} " && rm -f _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Do ds-submit" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key ds-submit --zone ods1 --cka_id $KSK1_CKA &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect ready(ds-seen)/active" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*ready.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK1_CKA" &&
echo -n "LINE: ${LINENO} " && rm -f _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Do ds-seen" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key ds-seen --zone ods1 --cka_id $KSK1_CKA &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && #### Keys are both active right after ds-seen command
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect active/active " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Still expect rumoured DS  " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK1_CKA" &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --debug &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*rumoured[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*.*$KSK1_CKA" &&

echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Wait for DS TTL to pass  " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 4 -----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect omnipresent DS " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --debug &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && #### TIME 3: ZSK rollover
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Next event is ZSK auto rollover " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 5 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect active/active/publish" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*publish" &&

echo -n "LINE: ${LINENO} " && ZSK2_CKA=`log_grep -o ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*publish" | awk '{print $8}'` &&

echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


echo -n "LINE: ${LINENO} " && #### TIME 4: New ZSK appears
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 6 -----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect active/retire/ready " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*ready.*$ZSK2_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && #### TIME 5: New ZSK should be ready
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 7 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect active/retire /active" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK1_CKA" &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect unretentive DNSKEY, hidden RRSIG" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK.*unretentive.*hidden.*$ZSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK2_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && #### TIME 6: Rollover done
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 8 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect active/retire/active " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK1_CKA" &&


echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect hidden DNSKEY and hidden RRSIG" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK.*hidden.*hidden.*$ZSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK2_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


echo -n "LINE: ${LINENO} " && #### TIME 7: Active Keys
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 9 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect active/active" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && ! log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK2_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


echo -n "LINE: ${LINENO} " && #### TIME 8: Next ZSK rollover starts
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 10 ----------------" &&
echo -n "LINE: ${LINENO} " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect active/active/publish " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK2_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*publish" &&

echo -n "LINE: ${LINENO} " && ZSK3_CKA=`log_grep -o ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*publish" | awk '{print $8}'` &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


echo -n "LINE: ${LINENO} " && #### TIME 9: Next ZSK rollover continues
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 11 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect active/retire/ready " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK2_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*ready.*$ZSK3_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


echo -n "LINE: ${LINENO} " && #### TIME 10: Next ZSK rollover starts
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 12 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect active/retire/active " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK2_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK3_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && #### Lets try to roll the KSK manually now
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Do manual key rollover for KSK" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key rollover  --zone ods1 --keytype KSK &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------- TIME LEAP 13 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Expect a new KSK to be published" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- The rollover list for manual roll.....!!!" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*publish" &&

echo -n "LINE: ${LINENO} " && KSK2_CKA=`log_grep -o ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*publish" | awk '{print $8}'` &&

echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && #### TIME 11: Expect KSK to be ready 
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 14 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Expect a new KSK to be ready ..." &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*retire.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*ready.*$KSK2_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Do ds-submit" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key ds-submit --zone ods1 --cka_id $KSK2_CKA &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Do ds-seen" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key ds-seen --zone ods1 --cka_id $KSK2_CKA &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 15 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && #### Keys are both active right after ds-seen command
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output echo "----- Expect active/active " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*retire.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK2_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


echo -n "LINE: ${LINENO} " && #### TIME 11.5: Expect DS becomes omnipresent
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Wait for DS TTL to pass  " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 16 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------------------------------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Expect DS becomes omnipresent since DS TTL has passed" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --debug &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*.*$KSK2_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Do ds-retract" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key ds-retract --zone ods1 --cka_id $KSK1_CKA &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Do ds-gone" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key ds-gone --zone ods1 --cka_id $KSK1_CKA &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 17 ----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------------------------------------" &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Expect hidden DS for old KSK " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --debug &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*unretentive[[:space:]]*unretentive[[:space:]]*unretentive.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent.*$KSK2_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


echo -n "LINE: ${LINENO} " && #### TIME 12
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 18 -----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------------------------------------" &&


echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Expect hidden DNSKEY and RRSIGDNSKEY" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --debug &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*hidden[[:space:]]*unretentive[[:space:]]*unretentive.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent.*$KSK2_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && #### TIME 12.5
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 19 -----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------------------------------------" &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Expect old ZSK has NOT been removed from the list " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && #### TIME 13
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 20 -----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------------------------------------" &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Expect old ZSK has been removed from the list " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && ! log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

echo -n "LINE: ${LINENO} " && #### TIME 14
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 21 -----------------" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual 'ods-enforcer time leap --attach' &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "--------------------------------------------" &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual echo "----- Expect old KSK has been removed from the list " &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-output_manual ods-enforcer rollover list &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-temp ods-enforcer key list  --debug &&
echo -n "LINE: ${LINENO} " && ! log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK.*$KSK1_CKA" &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent.*$KSK2_CKA" &&
echo -n "LINE: ${LINENO} " && rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


ods_stop_enforcer &&
echo "**** OK" &&
# Change this line to return 1 even on succeess if you want to leave the output files around for inspection
return 0

echo "################## ERROR: CURRENT STATE ###########################"
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue

echo
echo  "**** FAILED"
ods_kill
return 1
