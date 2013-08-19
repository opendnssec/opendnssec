#!/usr/bin/env bash
#
#TEST: Test to check the operation of the 'ods-ksmutil key generate' command
#TEST: with enforcer runs when key generation is set to manual
#TEST: It then switches to automatic key generation and checks the enforcer
#TEST: then does the right thing.

#DISABLED: ON FREEBSD - due to pthread seg fault on freebsd64

ENFORCER_WAIT=30

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

add_zones() {
	for (( ZONE_COUNT=$1; ZONE_COUNT<=$2; ZONE_COUNT++ ))
	do
		sed s/ods./ods_$ZONE_COUNT./g unsigned/ods > unsigned/ods_$ZONE_COUNT &&
		log_this ods-zone-add_$3 ods-ksmutil zone add --zone ods_$ZONE_COUNT --policy Policy$3
	done 	
}

case "$DISTRIBUTION" in
	freebsd )
		return 0
		;;
esac

ods_reset_env &&

##########################################################################################
##################  Shared keys and same alg & length behaviour ###########################
##########################################################################################

# Add a few zones
add_zones 1 10 5 && 

# Generate keys on a policy which shares keys with the same algorithm 7 and length 2048
echo "y" | log_this ods-ksmutil-generate_1   ods-ksmutil key generate --interval PT100M --policy  Policy5 &&
log_grep ods-ksmutil-generate_1   stdout "Info: 10 zone(s) found on policy \"Policy5\"" &&
log_grep ods-ksmutil-generate_1   stdout "3 new KSK(s) (2048 bits) need to be created."  &&
log_grep ods-ksmutil-generate_1   stdout "5 new ZSK(s) (2048 bits) need to be created." &&
log_grep ods-ksmutil-generate_1   stdout "all done! " &&
log_this ods-ksmutil-keylist_hms_1   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_hms_1   stdout "8 keys found." && 

export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

! syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy5\""  &&
# check is hasn't generated any keys
log_this enforcer-keylist_hsm_1   ods-hsmutil list &&
log_grep enforcer-keylist_hsm_1   stdout "8 keys found." &&
# check is has allocated keys to zones
log_this enforcer-keylist_1   ods-ksmutil key list --verbose &&
log_grep enforcer-keylist_1   stdout "ods_10.*ZSK           active" && 
log_grep enforcer-keylist_1   stdout "ods_10.*KSK           publish" &&

################## Jump forward 20M
export ENFORCER_TIMESHIFT='01-01-2010 12:20' &&
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

! syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy5\""  &&
# check is hasn't generated any keys
log_this enforcer-keylist_hsm_2   ods-hsmutil list &&
log_grep enforcer-keylist_hsm_2  stdout "8 keys found." &&
# but it has transitioned keys
log_this enforcer-keylist_2  ods-ksmutil key list --verbose &&
log_grep enforcer-keylist_2   stdout "ods_10  .*ZSK           active" &&
log_grep enforcer-keylist_2   stdout "ods_10  .*ZSK           publish" &&  
log_grep enforcer-keylist_2   stdout "ods_10  .*KSK           ready" &&

# Check we don't generate keys when we don't need them
echo "y" | log_this ods-ksmutil-generate_2   ods-ksmutil key generate --interval PT80M --policy  Policy5 &&
log_grep ods-ksmutil-generate_2   stdout "Info: 10 zone(s) found on policy \"Policy5\"" &&
log_grep ods-ksmutil-generate_2   stdout "No new KSKs need to be created."  &&
log_grep ods-ksmutil-generate_2   stdout "No new ZSKs need to be created." &&
log_grep ods-ksmutil-generate_2   stdout "all done! " &&
log_this ods-ksmutil-keylist_2   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_2   stdout "8 keys found." &&

# Now check we do generate them when we will need them
echo "y" | log_this ods-ksmutil-generate_3   ods-ksmutil key generate --interval PT180M --policy  Policy5 &&
log_grep ods-ksmutil-generate_3   stdout "Info: 10 zone(s) found on policy \"Policy5\"" &&
log_grep ods-ksmutil-generate_3   stdout "No new KSKs need to be created."  &&
log_grep ods-ksmutil-generate_3   stdout "6 new ZSK(s) (2048 bits) need to be created." &&
log_grep ods-ksmutil-generate_3   stdout "all done! " &&
log_this ods-ksmutil-keylist_3   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_3   stdout "14 keys found." &&

# check the enforcer doesn't generate any keys
export ENFORCER_TIMESHIFT='01-01-2010 12:20' &&
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

! syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy5\""  &&
# check is hasn't generated any keys
log_this enforcer-keylist_hsm_3   ods-hsmutil list &&
log_grep enforcer-keylist_hsm_3   stdout "14 keys found." &&

################### Now lets switch the automatic key generation and check the enforcer does the right thing
if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql_2.xml
else
	    ods_setup_conf conf.xml conf_2.xml
fi &&

log_this ods-ksmutil-update ods-ksmutil update conf &&

log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy5\""  &&
syslog_grep_count 1  'ods-enforcerd: .*No new KSKs need to be created.'  &&
syslog_grep_count 1  'ods-enforcerd: .*8 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_hsm_3   ods-hsmutil list &&
log_grep enforcer-keylist_hsm_3   stdout "22 keys found." &&


##############################################################################################################
##################  Same again but with Shared keys and diff alg & length behaviour ###########################
#############################################################################################################

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else
	    ods_setup_conf conf.xml conf.xml
fi &&
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&

# Add a few zones
add_zones 1 10 6 && 

# Generate keys on a policy which shares keys with the diff algorithm  and length 
echo "y" | log_this ods-ksmutil1-generate_1   ods-ksmutil key generate --interval PT100M --policy  Policy6 &&
log_grep ods-ksmutil1-generate_1   stdout "Info: 10 zone(s) found on policy \"Policy6\"" &&
log_grep ods-ksmutil1-generate_1   stdout "3 new KSK(s) (1024 bits) need to be created."  &&
log_grep ods-ksmutil1-generate_1   stdout "5 new ZSK(s) (2048 bits) need to be created." &&
log_grep ods-ksmutil1-generate_1   stdout "all done! " &&
log_this ods-ksmutil1-keylist_hms_1   ods-hsmutil list &&
log_grep ods-ksmutil1-keylist_hms_1   stdout "8 keys found." && 

export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
log_this_timeout ods-control-enforcer1-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

! syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy6\""  &&
# check is hasn't generated any keys
log_this enforcer1-keylist_hsm_1   ods-hsmutil list &&
log_grep enforcer1-keylist_hsm_1   stdout "8 keys found." &&
# check is has allocated keys to zones
log_this enforcer1-keylist_1   ods-ksmutil key list --verbose &&
log_grep enforcer1-keylist_1   stdout "ods_10.*ZSK           active" && 
log_grep enforcer1-keylist_1   stdout "ods_10.*KSK           publish" &&

################## Jump forward 20M
export ENFORCER_TIMESHIFT='01-01-2010 12:20' &&
log_this_timeout ods-control-enforcer1-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

! syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy6\""  &&
# check is hasn't generated any keys
log_this enforcer1-keylist_hsm_2   ods-hsmutil list &&
log_grep enforcer1-keylist_hsm_2  stdout "8 keys found." &&
# but it has transitioned keys
log_this enforcer1-keylist_2  ods-ksmutil key list --verbose &&
log_grep enforcer1-keylist_2   stdout "ods_10  .*ZSK           active" &&
log_grep enforcer1-keylist_2   stdout "ods_10  .*ZSK           publish" &&  
log_grep enforcer1-keylist_2   stdout "ods_10  .*KSK           ready" &&

# Check we don't generate keys when we don't need them
echo "y" | log_this ods-ksmutil1-generate_2   ods-ksmutil key generate --interval PT80M --policy  Policy6 &&
log_grep ods-ksmutil1-generate_2   stdout "Info: 10 zone(s) found on policy \"Policy6\"" &&
log_grep ods-ksmutil1-generate_2   stdout "No new KSKs need to be created."  &&
log_grep ods-ksmutil1-generate_2   stdout "No new ZSKs need to be created." &&
log_grep ods-ksmutil1-generate_2   stdout "all done! " &&
log_this ods-ksmutil1-keylist_2   ods-hsmutil list &&
log_grep ods-ksmutil1-keylist_2   stdout "8 keys found." &&

# Now check we do generate them when we will need them
echo "y" | log_this ods-ksmutil1-generate_3   ods-ksmutil key generate --interval PT180M --policy  Policy6 &&
log_grep ods-ksmutil1-generate_3   stdout "Info: 10 zone(s) found on policy \"Policy6\"" &&
log_grep ods-ksmutil1-generate_3   stdout "2 new KSK(s) (1024 bits) need to be created." &&
log_grep ods-ksmutil1-generate_3   stdout "4 new ZSK(s) (2048 bits) need to be created." &&
log_grep ods-ksmutil1-generate_3   stdout "all done! " &&
log_this ods-ksmutil1-keylist_3   ods-hsmutil list &&
log_grep ods-ksmutil1-keylist_3   stdout "14 keys found." &&

# check the enforcer doesn't generate any keys
export ENFORCER_TIMESHIFT='01-01-2010 12:20' &&
log_this_timeout ods-control-enforcer1-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

! syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy6\""  &&
# check is hasn't generated any keys
log_this enforcer1-keylist_hsm_3   ods-hsmutil list &&
log_grep enforcer1-keylist_hsm_3   stdout "14 keys found." &&


################### Now lets switch the automatic key generation and check the enforcer does the right thing
if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql_2.xml
else
	    ods_setup_conf conf.xml conf_2.xml
fi &&

log_this ods-ksmutil1-update ods-ksmutil update conf &&

log_this_timeout ods-control-enforcer1-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy6\""  &&
syslog_grep_count 1  'ods-enforcerd: .*3 new KSK(s) (1024 bits) need to be created.' &&
syslog_grep_count 1  'ods-enforcerd: .*5 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer1-keylist_hsm_3   ods-hsmutil list &&
log_grep enforcer1-keylist_hsm_3   stdout "22 keys found." &&

###################################################################################################################
##################  Same again but _without_ Shared keys and diff alg & length behaviour ###########################
###################################################################################################################

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else
	    ods_setup_conf conf.xml conf.xml
fi &&
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&

# Add a few zones
add_zones 1 10 1 && 

# Generate keys on a policy which shares keys with the diff algorithm  and length 
echo "y" | log_this ods-ksmutil2-generate_1   ods-ksmutil key generate --interval PT100M --policy  Policy1 &&
log_grep ods-ksmutil2-generate_1   stdout "Info: 10 zone(s) found on policy \"Policy1\"" &&
log_grep ods-ksmutil2-generate_1   stdout "30 new KSK(s) (1024 bits) need to be created."  &&
log_grep ods-ksmutil2-generate_1   stdout "50 new ZSK(s) (2048 bits) need to be created." &&
log_grep ods-ksmutil2-generate_1   stdout "all done! " &&
log_this ods-ksmutil2-keylist_hms_1   ods-hsmutil list &&
log_grep ods-ksmutil2-keylist_hms_1   stdout "80 keys found." && 

export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
log_this_timeout ods-control-enforcer2-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

! syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy1\""  &&
# check is hasn't generated any keys
log_this enforcer2-keylist_hsm_1   ods-hsmutil list &&
log_grep enforcer2-keylist_hsm_1   stdout "80 keys found." &&
# check is has allocated keys to zones
log_this enforcer2-keylist_1   ods-ksmutil key list --verbose &&
log_grep enforcer2-keylist_1   stdout "ods_10.*ZSK           active" && 
log_grep enforcer2-keylist_1   stdout "ods_10.*KSK           publish" &&

################## Jump forward 20M
export ENFORCER_TIMESHIFT='01-01-2010 12:20' &&
log_this_timeout ods-control-enforcer2-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

! syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy1\""  &&
# check is hasn't generated any keys
log_this enforcer2-keylist_hsm_2   ods-hsmutil list &&
log_grep enforcer2-keylist_hsm_2  stdout "80 keys found." &&
# but it has transitioned keys
log_this enforcer2-keylist_2  ods-ksmutil key list --verbose &&
log_grep enforcer2-keylist_2   stdout "ods_10  .*ZSK           active" &&
log_grep enforcer2-keylist_2   stdout "ods_10  .*ZSK           publish" &&  
log_grep enforcer2-keylist_2   stdout "ods_10  .*KSK           ready" &&

# Check we don't generate keys when we don't need them
echo "y" | log_this ods-ksmutil2-generate_2   ods-ksmutil key generate --interval PT80M --policy  Policy1 &&
log_grep ods-ksmutil2-generate_2   stdout "Info: 10 zone(s) found on policy \"Policy1\"" &&
log_grep ods-ksmutil2-generate_2   stdout "No new KSKs need to be created."  &&
log_grep ods-ksmutil2-generate_2   stdout "No new ZSKs need to be created." &&
log_grep ods-ksmutil2-generate_2   stdout "all done! " &&
log_this ods-ksmutil2-keylist_2   ods-hsmutil list &&
log_grep ods-ksmutil2-keylist_2   stdout "80 keys found." &&

# Now check we do generate them when we will need them
echo "y" | log_this ods-ksmutil2-generate_3   ods-ksmutil key generate --interval PT180M --policy  Policy1 &&
log_grep ods-ksmutil2-generate_3   stdout "Info: 10 zone(s) found on policy \"Policy1\"" &&
log_grep ods-ksmutil2-generate_3   stdout "20 new KSK(s) (1024 bits) need to be created." &&
log_grep ods-ksmutil2-generate_3   stdout "40 new ZSK(s) (2048 bits) need to be created." &&
log_grep ods-ksmutil2-generate_3   stdout "all done! " &&
log_this ods-ksmutil2-keylist_3   ods-hsmutil list &&
log_grep ods-ksmutil2-keylist_3   stdout "140 keys found." &&

# check the enforcer doesn't generate any keys
export ENFORCER_TIMESHIFT='01-01-2010 12:20' &&
log_this_timeout ods-control-enforcer2-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

! syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy1\""  &&
# check is hasn't generated any keys
log_this enforcer2-keylist_hsm_3   ods-hsmutil list &&
log_grep enforcer2-keylist_hsm_3   stdout "140 keys found." &&

################### Now lets switch the automatic key generation and check the enforcer does the right thing
if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql_2.xml
else
	    ods_setup_conf conf.xml conf_2.xml
fi &&

log_this ods-ksmutil2-update ods-ksmutil update conf &&

log_this_timeout ods-control-enforcer2-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

syslog_grep_count 1  "ods-enforcerd: .*10 zone(s) found on policy \"Policy1\""  &&
syslog_grep_count 1  'ods-enforcerd: .*30 new KSK(s) (1024 bits) need to be created.' &&
syslog_grep_count 1  'ods-enforcerd: .*50 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer2-keylist_hsm_3   ods-hsmutil list &&
log_grep enforcer2-keylist_hsm_3   stdout "220 keys found." &&

echo &&
echo "************OK******************" &&
echo

return 0 

echo
echo "************ERROR******************"
echo
ods_kill
return 1

