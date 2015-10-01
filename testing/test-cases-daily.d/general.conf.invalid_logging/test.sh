#!/usr/bin/env bash

#TEST: Set logging to a invalid channel and expect failure.

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

! ods_reset_env &&
! log_this confcheck-kaspcheck ods-kaspcheck &&
! log_this confcheck-enforcerd ods-enforcerd --no-daemon &&
! log_this confcheck-signerd ods-signerd --no-daemon &&
log_grep confcheck-kaspcheck stdout 'ERROR: .*conf.xml fails to validate' &&
log_grep confcheck-kaspcheck stderr 'element Logging: Relax-NG validity error.*: Element Common failed to validate content' &&
# log_grep confcheck-enforcerd stderr 'syslog facility local99 not supported, logging to log_daemon' &&
log_grep confcheck-signerd stderr 'Relax-NG validity error.*' &&
log_grep confcheck-signerd stderr 'element Logging: Relax-NG validity error.*: Element Common failed to validate content' &&

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-correct-mysql.xml
else
	ods_setup_conf conf.xml conf-correct.xml
fi &&

ods_reset_env &&
ods_ods-control_start &&

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
else
	ods_setup_conf conf.xml conf.xml
fi &&

# It is unclear whether a reload actually leads to reloading the config file
# if it does, the signer does not output any sign the configuration is now
# wrong, nor does the return status of the CLI has an error exit status
# So the following test succeeds for no reason
ods-signer reload &&

# The enforcer indicates a problem, there are a number of small errors:
# - The command line utility when run non-interactive does give a
#   descriptive output message, however a carriage return is missing.
# - The interactive version gives a generic message that the server
#   did not accept, but no descriptive message.
# - The error message output to syslog, is in fact different from the
#   message when running the enforcerd in non-daemon modus.
! ods-enforcer update conf &&
sleep 60 &&
syslog_waitfor 10 'ERROR: .*conf.xml fails to validate' &&

ods_ods-control_stop &&
return 0

ods_kill
return 1
