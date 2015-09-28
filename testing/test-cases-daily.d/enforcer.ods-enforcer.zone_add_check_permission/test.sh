#!/usr/bin/env bash
#
#TEST: Test the ods-ksmutil zone add. when xml_flag == 1 check the permission of the zonelist.xml.backup or the path. 

myPath="$INSTALL_ROOT/etc/opendnssec" 
myFile="$INSTALL_ROOT/etc/opendnssec/zonelist.xml.backup" 
bak_File="$INSTALL_ROOT/etc/opendnssec/zonelist.xml.backup_bak" 

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else 
        ods_setup_conf conf.xml conf.xml
fi &&

ods_reset_env &&

if [ -f $myFile ]; then
	chmod 664 "$myFile" 
else	
	cp "$INSTALL_ROOT/etc/opendnssec/zonelist.xml" "$INSTALL_ROOT/etc/opendnssec/zonelist.xml.backup"
fi &&

chmod 755 $myPath &&

echo "************Test begin******************" &&
log_this ods-ksmutil-zone_none   ods-ksmutil zone list &&
log_grep ods-ksmutil-zone_none   stdout "No zones in DB or zonelist." &&

log_this ods-ksmutil-zone_none_ods0   ods-ksmutil zone add --zone ods0 &&
log_grep ods-ksmutil-zone_none_ods0   stdout "Imported zone: ods0" &&

######### When the zonelist.xml.backup exist, check the permission of the file ##############
if [ -f $myFile ]; then 
	chmod 0 $myFile
fi &&

! log_this ods-ksmutil-zone_none_ods1   ods-ksmutil zone add --zone ods1 &&
log_grep ods-ksmutil-zone_none_ods1   stdout "ERROR: The backup file $myFile can not be written." &&

chmod 664 $myFile &&
log_this ods-ksmutil-zone_none_ods1   ods-ksmutil zone add --zone ods1 &&
log_grep ods-ksmutil-zone_none_ods1   stdout "Imported zone: ods1" &&

########### When the zonelist.xml.backup does not exist, check the permission of the path #########
mv $myFile $bak_File &&
chmod 555 $myPath &&
! log_this ods-ksmutil-zone_none_ods2   ods-ksmutil zone add --zone ods2 &&
log_grep ods-ksmutil-zone_none_ods2   stdout "ERROR: The backup file $myFile can not be written." &&


chmod 755 $myPath &&
log_this ods-ksmutil-zone_none_ods2   ods-ksmutil zone add --zone ods2 &&
log_grep ods-ksmutil-zone_none_ods2   stdout "Imported zone: ods2" &&

mv $bak_File $myFile &&

########### The check should only be run when xml_flag == 1 ####################################
chmod 0 $myFile &&
log_this ods-ksmutil-zone_none_ods3   ods-ksmutil zone add --zone ods3 --no-xml &&
log_grep ods-ksmutil-zone_none_ods3   stdout "Imported zone: ods3 into database only" &&
chmod 664 $myFile &&

echo && 
echo "************OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1
