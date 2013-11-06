#!/usr/bin/env bash
#
#TEST: Test the command of ods-ksmutil zone add work correctly
#Notice: The use case must be used to test OPENDNSSEC-430 and OPENDNSSEC-431 in JIRA,I think,we should check if the input file and the output file are mached in the zonelist.xml use our eyes 


if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else 
        ods_setup_conf conf.xml conf.xml
fi &&

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

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods3  --input $INSTALL_ROOT/var/opendnssec/unsigned/ods4 --output $INSTALL_ROOT/var/opendnssec/signed/ods4 &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone: ods3" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone list &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods0; on policy default" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods1; on policy Policy1" &&
log_grep ods-ksmutil-zone_add   stdout "Found Zone: ods3; on policy default" &&


#4. Test bad parameter
! log_this ods-ksmutil-zone_add   ods-ksmutil zone &&
log_grep ods-ksmutil-zone_add   stderr "usage: ods-ksmutil \[-c <config> | --config <config>\] zone" &&

#5. Test none exist input file
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods11 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods11 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods11.xml &&
log_grep ods-ksmutil-zone_add   stdout "WARNING: The input file $INSTALL_ROOT/var/opendnssec/unsigned/ods11 for zone ods11 does not currently exist. The zone will been added to the database anyway" &&


echo && 
echo "************OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1



