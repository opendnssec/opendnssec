#!/usr/bin/env bash

#TEST: Test that a enforcer update call warns on algorithm change

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_enforcer && 

# Switch the kasp.xml file for one with a non algorithm update
cp -- "kasp_no_algo_change.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&

# Run an update; we do not expect to be asked for confirmation
log_this ods-enforcer-update1 ods-enforcer update kasp &&
#log_grep ods-enforcer-update1 stdout 'Notifying enforcer of new database...' &&

# Export the policy and check some of its values
log_this ods-enforcer-export2 ods-enforcer policy list &&
log_this ods-enforcer-export1 ods-enforcer policy export -p default &&
log_grep ods-enforcer-export1 stdout '<Policy name="default">' &&
log_grep ods-enforcer-export1 stdout '<KSK>' &&
log_grep ods-enforcer-export1 stdout '<Algorithm length="2048">7</Algorithm>' &&
#log_grep ods-enforcer-export1 stdout '<Lifetime>PT345600S</Lifetime>' &&
log_grep ods-enforcer-export1 stdout '<Repository>SoftHSM</Repository>' &&
#log_grep ods-enforcer-export1 stdout '<Standby>0</Standby>' &&
log_grep ods-enforcer-export1 stdout '</KSK>' &&	
	

# Switch the kasp.xml file for one with an algorithm update
cp -- "kasp_algo_change.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&

# Run an update; but say "no" when asked for confirmation
echo "n" | log_this ods-enforcer-update2 ods-enforcer update kasp &&
#log_grep ods-enforcer-update2 stdout 'Algorithm change attempted... details:' &&
#log_grep ods-enforcer-update2 stdout 'Policy: default, KSK algorithm changed from 7 to 8.' &&
#log_grep ods-enforcer-update2 stdout '\*WARNING\* This will change the algorithms used as noted above. Algorithm rollover is _not_ supported by OpenDNSSEC and zones may break. Are you sure' &&
#log_grep ods-enforcer-update2 stdout 'Okay, quitting...' &&

# Export the policy and check some of its values (shouldn't have changed)
log_this ods-enforcer-export2 ods-enforcer policy export -p default &&
log_grep ods-enforcer-export2 stdout '<Policy name="default">' &&
log_grep ods-enforcer-export2 stdout '<KSK>' &&
log_grep ods-enforcer-export2 stdout '<Algorithm length="2048">8</Algorithm>' &&
#log_grep ods-enforcer-export2 stdout '<Lifetime>PT345600S</Lifetime>' &&
log_grep ods-enforcer-export2 stdout '<Repository>SoftHSM</Repository>' &&
#log_grep ods-enforcer-export2 stdout '<Standby>0</Standby>' &&
log_grep ods-enforcer-export2 stdout '</KSK>' &&
	

# Finally; Run an update; but say "yes" when asked for confirmation
echo "y" | log_this ods-enforcer-update3 ods-enforcer update kasp &&
#log_grep ods-enforcer-update3 stdout 'Algorithm change attempted... details:' &&
#log_grep ods-enforcer-update3 stdout 'Policy: default, KSK algorithm changed from 7 to 8.' &&
#log_grep ods-enforcer-update3 stdout '\*WARNING\* This will change the algorithms used as noted above. Algorithm rollover is _not_ supported by OpenDNSSEC and zones may break. Are you sure' &&
#log_grep ods-enforcer-update3 stdout 'Notifying enforcer of new database...' &&

# Export the policy and check some of its values (should have changed)
log_this ods-enforcer-export3 ods-enforcer policy export -p default &&
log_grep ods-enforcer-export3 stdout '<Policy name="default">' &&
log_grep ods-enforcer-export3 stdout '<KSK>' &&
log_grep ods-enforcer-export3 stdout '<Algorithm length="2048">8</Algorithm>' &&
#log_grep ods-enforcer-export3 stdout '<Lifetime>PT345600S</Lifetime>' &&
log_grep ods-enforcer-export3 stdout '<Repository>SoftHSM</Repository>' &&
#log_grep ods-enforcer-export3 stdout '<Standby>0</Standby>' &&
log_grep ods-enforcer-export3 stdout '</KSK>' &&

# Make sure none of this shennanigans has altered the other policy
log_this ods-enforcer-export4 ods-enforcer policy export -p default2 &&
log_grep ods-enforcer-export4 stdout '<Policy name="default2">' &&
log_grep ods-enforcer-export4 stdout '<KSK>' &&
log_grep ods-enforcer-export4 stdout '<Algorithm length="2048">7</Algorithm>' &&
#log_grep ods-enforcer-export4 stdout '<Lifetime>PT345600S</Lifetime>' &&
log_grep ods-enforcer-export4 stdout '<Repository>SoftHSM</Repository>' &&
#log_grep ods-enforcer-export4 stdout '<Standby>0</Standby>' &&
log_grep ods-enforcer-export4 stdout '</KSK>' &&

return 0

ods_kill
return 1
