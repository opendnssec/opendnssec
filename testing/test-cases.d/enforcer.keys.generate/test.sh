#!/usr/bin/env bash
#
#TEST: Test to check to check that the enforcer automatically generates keys correctly
#TEST: This test does mulitple runs of the enforcer with zones
#TEST: on different policies and checks it generates the right number
#TEST: of the right kind of key. Tries to test algorithm and length mixtures
#TEST: shared keys and standby

## Conf: AutomaticKeyGenerationPeriod = 50H
## Policy 1: 50H/10H share:N expected keys: 1/5 
## Policy 2: 45H/15H share:N expected keys: 2/4
## Policy 3: 45H/15H share:N expected keys: 2/4
## Policy 4: 45H/25H share:N expected keys: 2/2
## Policy 5: 45H/25H share:Y expected keys: 2/2
## Policy 6: 45H/25H share:Y expected keys: 2/2

function check_hsmkey_count() {
    EXPECT=$1 &&
    FOUND=`ods-hsmutil list|grep "keys found"|cut -f 1 -d " "` &&
    echo "expecting" $EXPECT "keys. Found" $FOUND "keys" &&
    test $EXPECT -eq $FOUND
}

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env -i -n &&

##################  Basic behaviour  ###########################

# Generate keys with algorithm 7, length 2048
ods-hsmutil list &&
check_hsmkey_count 0 &&

log_this ods-zone-add-1 ods-enforcer zone add --zone p1ods1 --policy Policy1 &&
check_hsmkey_count 6 && #1/5

log_this ods-zone-add-2 ods-enforcer zone add --zone p2ods2 --policy Policy2 &&
log_this ods-zone-add-5 ods-enforcer zone add --zone p2ods5 --policy Policy2 &&
check_hsmkey_count 12 && #1/5 + 2/4

log_this ods-zone-add-1 ods-enforcer zone add --zone p3ods1 --policy Policy3 &&
log_this ods-zone-add-4 ods-enforcer zone add --zone p3ods4 --policy Policy3 &&
check_hsmkey_count 18 && #1/5 + 2/4 + 2/4

log_this ods-zone-add-1 ods-enforcer zone add --zone p4ods1 --policy Policy4 &&
check_hsmkey_count 22 && #1/5 + 2/4 + 2/4 + 2/2

log_this ods-zone-add-1 ods-enforcer zone add --zone p5ods1 --policy Policy5 &&
log_this ods-zone-add-2 ods-enforcer zone add --zone p5ods2 --policy Policy5 &&
check_hsmkey_count 26 && #1/5 + 2/4 + 2/4 + 2/2 + 2/2

## All zones are scheduled at the same time. a timeleap should visit them all
## Now all zones are assigned a key we expect
##   NR KSK/ZSK
## policy 1: 1/5 + 1/1   =  8 keys
## policy 2: 2/4 + 2/2   = 10 keys
## policy 3: 2/4 + 2/2   = 10 keys
## policy 4: 2/2 + 1/1   =  6 keys
## policy 5: 2/2 + 1/1   =  6 keys (shared)
##                      +-----
##                          40 keys
ods-enforcer time leap --attach &&
check_hsmkey_count 40 &&

ods_stop_enforcer &&

echo && 
echo "************OK******************" &&
echo &&

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

