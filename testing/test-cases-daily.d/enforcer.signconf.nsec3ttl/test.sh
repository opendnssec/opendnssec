#!/usr/bin/env bash
#
#TEST: Test to check signconf format for config with NSEC3PARAM TTL set or not

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

rm -rf base &&
mkdir  base &&

# Used only to create a gold while setting up the test
#rm -rf gold && mkdir gold &&

##################  SETUP ###########################
# Start enforcer (Zones already exist and we let it generate keys itself)
ods_start_enforcer_timeshift &&

for zone in with-ttl non-ttl; do
	# Used only to create a gold while setting up the test
	#cp $INSTALL_ROOT/var/opendnssec/signconf/$zone.xml gold/signconf_"$zone".xml        
	cp $INSTALL_ROOT/var/opendnssec/signconf/$zone.xml base/signconf_"$zone".xml
done &&

# compare all the signconf files
log_this ods-compare-signconfs  ods_compare_gold_vs_base_signconf &&
rm -rf base &&

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

