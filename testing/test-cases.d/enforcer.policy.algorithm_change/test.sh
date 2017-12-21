#!/usr/bin/env bash
#
#TEST: intro ksk and zsk. change alg. introduce new pair.
#runtime: about 12 seconds 

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env -i &&
ods_start_enforcer &&

echo "################## ZONE ADD 1 ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add --zone ods1 &&

echo "################## LEAP TO OMNIPRESENT ZSK DNSKEY ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&

echo -n "LINE: ${LINENO} " && KSK1=`ods-enforcer key list -d -p | grep ods1 | grep KSK |cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && ZSK1=`ods-enforcer key list -d -p | grep ods1 | grep ZSK |cut -d ";" -f 9` &&

echo -n "LINE: ${LINENO} " && ods-enforcer key ds-submit -z ods1 -k $KSK1 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods1 -k $KSK1 &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&

echo "################## CHANGE ALGORITHM AND RESTART ###########################" &&
ods_stop_enforcer &&
echo -n "LINE: ${LINENO} " && cp kasp-alg-switch.xml  "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
ods_start_enforcer &&
echo -n "LINE: ${LINENO} " && ods-enforcer policy import &&

echo "################## INTRODUCE ZSK ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&

## between these 2 enforces the new keys should be generated.
## find new ZSK
echo -n "LINE: ${LINENO} " && ZSK2=`ods-enforcer key list -d -p | grep ods1 | grep -v $ZSK1 | grep ZSK |cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && KSK2=`ods-enforcer key list -d -p | grep ods1 | grep -v $KSK1 | grep KSK |cut -d ";" -f 9` &&

echo "################## MUST BE 1 NEW KSK AND ZSK ###########################" &&
echo -n "LINE: ${LINENO} " && test `echo "$KSK2" | wc -w` -eq 1 &&
echo -n "LINE: ${LINENO} " && test -n "$KSK2" &&
echo -n "LINE: ${LINENO} " && test `echo "$ZSK2" | wc -w` -eq 1 &&
echo -n "LINE: ${LINENO} " && test -n "$ZSK2" &&


echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep "$ZSK2" | grep "NA;rumoured;NA;rumoured;" &&

echo "################## INTRODUCE KSK ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && KSK2=`ods-enforcer key list -d -p | grep ods1 | grep -v $KSK1 | grep KSK |cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && test -n "$KSK2" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $ZSK1 | grep "NA;omnipresent;NA;omnipresent;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $KSK1 | grep "unretentive;omnipresent;omnipresent;NA;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $ZSK2 | grep "NA;omnipresent;NA;omnipresent;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $KSK2 | grep "rumoured;omnipresent;omnipresent;NA;" &&

echo -n "LINE: ${LINENO} " && ods-enforcer key ds-retract -z ods1 -k $KSK1 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-submit -z ods1 -k $KSK2 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-gone -z ods1 -k $KSK1 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods1 -k $KSK2 &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&

echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $ZSK1 | grep "NA;unretentive;NA;unretentive;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $KSK1 | grep "hidden;unretentive;unretentive;NA;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $ZSK2 | grep "NA;omnipresent;NA;omnipresent;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $KSK2 | grep "omnipresent;omnipresent;omnipresent;NA;" &&

echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $ZSK1 | grep "NA;hidden;NA;unretentive;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $KSK1 | grep "hidden;hidden;hidden;NA;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $ZSK2 | grep "NA;omnipresent;NA;omnipresent;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $KSK2 | grep "omnipresent;omnipresent;omnipresent;NA;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $ZSK1 | grep "NA;hidden;NA;hidden;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $KSK1 | grep "hidden;hidden;hidden;NA;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $ZSK2 | grep "NA;omnipresent;NA;omnipresent;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep $KSK2 | grep "omnipresent;omnipresent;omnipresent;NA;" &&

echo "################## TEST TEARDOWN ###########################" &&
echo -n "LINE: ${LINENO} " && ods_stop_enforcer &&
exit 0

echo "################## ERROR: CURRENT STATE ###########################"
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue

echo
echo "************error******************"
echo
ods_kill
return 1
