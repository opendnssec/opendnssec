#!/usr/bin/env bash
#
#TEST: Test to check support in the kasp.xml and signconf.xml format 
#TEST: for new NSEC3PARAM. Also check the zone signing works OK.

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

rm -rf base &&
mkdir  base &&
rm -rf gold &&
mkdir  gold &&

##################  First run with 3 different TTLs ###########################
# Start enforcer (Zones already exist and we let it generate keys itself)
ods_start_enforcer &&

sleep 1 && ods_enforcer_idle && sleep 1 &&

for zone in with-ttl no-ttl with-0-ttl; do
	# Used only to create a gold while setting up the test
	# cp $INSTALL_ROOT/var/opendnssec/signconf/$zone.xml goldA/  &&       
	cp $INSTALL_ROOT/var/opendnssec/signconf/$zone.xml base/ 
done &&

# compare all the signconf files for this run
cp goldA/* gold/ &&
log_this ods-compare-signconfs1  ods_compare_gold_vs_base_signconf &&
rm gold/* &&
rm base/* &&

# Now export and check the TTL values are there
# Note the exported kasp has all times in seconds to can't be compared to the input kasp.xml
echo "Exporting policy" &&
ods-enforcer policy export --all > kasp.xml.temp~ &&
sed -e 's#>.*</Salt># />#g' kasp.xml.temp~ > kasp.xml.temp2~ &&
log_this ods-compare-kasp1 ods_comparexml  kasp.xml.temp2~ kasp.xml.gold_exported &&
echo "Exported policy OK" &&

# Lets fire up the signer and check what ends up in the zones
ods_start_signer && 
syslog_waitfor 60 'ods-signerd: .*\[STATS\] no-ttl' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] with-ttl' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] with-0-ttl' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/no-ttl" &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/with-ttl" &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/with-0-ttl" &&
`$GREP -q -- "no-ttl.[[:space:]]0[[:space:]]IN[[:space:]]NSEC3PARAM" "$INSTALL_ROOT/var/opendnssec/signed/no-ttl"` &&
`$GREP -q -- "with-0-ttl.[[:space:]]0[[:space:]]IN[[:space:]]NSEC3PARAM" "$INSTALL_ROOT/var/opendnssec/signed/with-0-ttl"` &&
`$GREP -q -- "with-ttl.[[:space:]]3600[[:space:]]IN[[:space:]]NSEC3PARAM" "$INSTALL_ROOT/var/opendnssec/signed/with-ttl"` &&


##################  Second run with all the TTL values changed ###########################
# Now import the same policies but with the TTL changed in all of them
# no-ttl      -> add <TTL>PT3600S</TTL>
# with-ttl    -> remove <TTL>PT3600S</TTL> (expect a default of 0)
# with-0-ttl  -> change <TTL>PT0S</TTL> to <TTL>PT3600S</TTL>  
echo "Importing changed policies" &&
cp kasp.reversed.xml "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-import-reversed ods-enforcer policy import && sleep 3 &&

for zone in with-ttl no-ttl with-0-ttl; do
	# Used only to create a gold while setting up the test
	# cp $INSTALL_ROOT/var/opendnssec/signconf/$zone.xml goldB/ 
	cp $INSTALL_ROOT/var/opendnssec/signconf/$zone.xml base/
done &&

# compare all the signconf files for this run
cp goldB/* gold/ &&
log_this ods-compare-signconfs2  ods_compare_gold_vs_base_signconf &&
#rm gold/* &&
#rm base/* &&

# Lets export the policies again and double check
echo "Exporting policy2" &&
ods-enforcer policy export --all > kasp.xml.temp3~ && 
sed -e 's#>.*</Salt># />#g' kasp.xml.temp3~ > kasp.xml.temp4~ &&
log_this ods-compare-kasp2 ods_comparexml  kasp.xml.temp4~ kasp.xml.gold_exported2 &&
echo "Exported changed policy2 OK" &&

syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] no-ttl' &&
syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] with-ttl' &&
syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] with-0-ttl' &&
`$GREP -q -- "no-ttl.[[:space:]]3600[[:space:]]IN[[:space:]]NSEC3PARAM" "$INSTALL_ROOT/var/opendnssec/signed/no-ttl"` &&
`$GREP -q -- "with-0-ttl.[[:space:]]3600[[:space:]]IN[[:space:]]NSEC3PARAM" "$INSTALL_ROOT/var/opendnssec/signed/with-0-ttl"` &&
`$GREP -q -- "with-ttl.[[:space:]]0[[:space:]]IN[[:space:]]NSEC3PARAM" "$INSTALL_ROOT/var/opendnssec/signed/with-ttl"` &&

ods_stop_signer && 
ods_stop_enforcer &&

rm -rf base &&
rm -rf gold &&
rm kasp.xml.temp* &&
rm *~ &&


echo &&
echo "************ OK ******************" &&
echo &&
return 0

echo "################## ERROR: CURRENT STATE ###########################"
echo "DEBUG: " && ods-enforcer key list -d
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue
echo
echo "************ERROR******************"
echo
ods_kill
return 1

