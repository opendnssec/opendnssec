#!/usr/bin/env bash

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else 
        ods_setup_conf conf.xml conf.xml
fi &&

ods_reset_env &&

cp $INSTALL_ROOT/etc/opendnssec/zonelist.xml $INSTALL_ROOT/etc/opendnssec/zonelist.xml.update &&

chmod 755 $INSTALL_ROOT/etc/opendnssec &&

ods_ods-control_enforcer_start &&

log_this ods-enforcer-zone_none   ods-enforcer zone list &&
log_grep ods-enforcer-zone_none   stdout "No zones in database." &&

log_this ods-enforcer-zone_ods0   ods-enforcer zone add --zone ods0 --xml &&
log_grep ods-enforcer-zone_ods0   stdout "Zone ods0 added successfully" &&

touch $INSTALL_ROOT/etc/opendnssec/zonelist.xml.update &&
chmod 0 $INSTALL_ROOT/etc/opendnssec/zonelist.xml.update &&
chmod 555 $INSTALL_ROOT/etc/opendnssec &&

! log_this ods-enforcer-zone_ods1 ods-enforcer zone add --zone ods1 --xml &&
log_grep ods-enforcer-zone_ods1   stderr "Zonelist .*zonelist.xml update failed" &&
log_grep ods-enforcer-zone_ods1   stdout "Zone ods1 added successfully" &&

log_this ods-enforcer-zone_ods2   ods-enforcer zone add --zone ods2 &&
! log_grep ods-enforcer-zone_zone_ods2 stderr "Zonelist .*zonelist.xml update failed" &&
log_grep ods-enforcer-zone_ods2   stdout "Zone ods2 added successfully" &&

chmod 775 $INSTALL_ROOT/etc/opendnssec &&

log_this ods-enforcer-zone_ods3   ods-enforcer zone add --zone ods3 --xml &&
! log_grep ods-enforcer-zone_zone_ods3 stderr "Zonelist .*zonelist.xml update failed" &&
log_grep ods-enforcer-zone_ods3   stdout "Zone ods3 added successfully" &&

# compare the zonelist
ods_comparexml --format-installpath zonelist-gold.xml $INSTALL_ROOT/etc/opendnssec/zonelist.xml &&

ods_ods-control_enforcer_stop &&

echo && 
echo "************OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1
