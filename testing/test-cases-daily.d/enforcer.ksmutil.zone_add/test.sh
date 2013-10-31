#!/usr/bin/env bash
#
#TEST: Test the command of ods-ksmutil zone add work correctly
#Notice: The use case must be used to test OPENDNSSEC-430 and OPENDNSSEC-431 in JIRA,I think,we should check if the input file and the output file are mached in the zonelist.xml use our eyes 

#DISABLED: ON FREEBSD - due to pthread seg fault on freebsd64

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else 
        ods_setup_conf conf.xml conf.xml
fi &&

#case "$DISTRIBUTION" in
#	freebsd )
#		return 0
#		;;
#esac

ods_reset_env &&


##################  TEST  ###########################
#0. Test all default
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods0 &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods0" &&

#1. Test existing policy
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods1 --policy Policy1&&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods1" &&

#2. Test noneexistent policy 
! log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods2 --policy NonexistentPolicy &&
log_grep ods-ksmutil-zone_add   stdout "Error, can't find policy : NonexistentPolicy" &&

#3. Test more parameters
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods3 --in-type File --out-type File &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods3" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods4 --in-type File --out-type File --input $INSTALL_ROOT/var/opendnssec/unsigned/ods4 --output $INSTALL_ROOT/var/opendnssec/signed/ods4 &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods4" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods5 --in-type File --out-type DNS &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods5" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods6 --in-type File --out-type DNS --input $INSTALL_ROOT/var/opendnssec/unsigned/ods6 --output $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods6" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods7 --in-type DNS --out-type DNS &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods7" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods8 --in-type DNS --out-type DNS --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods8" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods9 --in-type DNS --out-type File &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods9" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods10 --in-type DNS --out-type File --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/var/opendnssec/signed/ods10 &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods10" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone list &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods0; on policy default" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods1; on policy Policy1" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods3; on policy default" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods4; on policy default" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods5; on policy default" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods6; on policy default" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods7; on policy default" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods8; on policy default" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods9; on policy default" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods10; on policy default" &&

#4. Test bad parameter
! log_this ods-ksmutil-zone_add   ods-ksmutil zone &&
log_grep ods-ksmutil-zone_add   stderr "usage: ods-ksmutil \[-c <config> | --config <config>\] zone" &&

#5. Test none exist input file
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods11 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods11 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods11.xml &&
log_grep ods-ksmutil-zone_add   stdout "WARNING: The input file $INSTALL_ROOT/var/opendnssec/unsigned/ods11 for zone ods11 does not currently exist. The zone will been added to the database anyway" &&

mv $INSTALL_ROOT/etc/opendnssec/addns.xml $INSTALL_ROOT/etc/opendnssec/addns.xml.backup &&
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods12 --input $INSTALL_ROOT/etc/opendnssec/addns.xml --in-type DNS --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods12.xml &&
log_grep ods-ksmutil-zone_add   stdout "WARNING: The input file $INSTALL_ROOT/etc/opendnssec/addns.xml for zone ods12 does not currently exist. The zone will been added to the database anyway" &&

#6. Test none exist output file in the case of --out-type DNS
mv $INSTALL_ROOT/etc/opendnssec/addns.xml.backup $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods13 --input $INSTALL_ROOT/etc/opendnssec/addns.xml --in-type DNS --out-type DNS --output $INSTALL_ROOT/etc/opendnssec/addns1.xml --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods13.xml &&
log_grep ods-ksmutil-zone_add   stdout "WARNING: The output file $INSTALL_ROOT/etc/opendnssec/addns1.xml for zone ods13 does not currently exist." &&

echo && 
echo "************OK******************" &&
echo 
return 1

echo
echo "************ERROR******************"
echo
ods_kill
return 1



