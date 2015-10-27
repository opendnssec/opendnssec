#!/usr/bin/env bash

#TEST: Use a Repository Capacity of 0 and expect failure

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

( ods_reset_env || true ) &&
! log_this confcheck ods-kaspcheck &&
log_grep confcheck stdout 'ERROR: .*conf.xml fails to validate' &&
log_grep confcheck stderr 'conf.xml:.* element Capacity: Relax-NG validity error.*: Element Repository failed to validate content' &&

# OPENDNSSEC-689: the following should fail and the enforer should not start (the false later on), but it does because
# the enforcer first daemonizes, then reads config file.  For now we leave this bug.
! ( ods_start_enforcer && false ) &&
# It does not produce any problem with the config file, that is BAD!
# the messages indicate that the error should by in syslog, but due
# to OPENDNSSEC-689 it does not.  Hence the following is not working:
#syslog_waitfor 10 "ods-enforcerd: .*Type positiveInteger doesn't allow value '0'" &&
# but the following indicates enough for the moment
# It doesn't really matter that much which error is exactly produced, as long
# as it there and it would be good if it is descriptive.
# But it must al least indicate some problem (not start, give error, or some
# thing, but not continue without indicating anything).
log_grep ods_ods-control_enforcer_start stderr 'conf.xml.*element Capacity: Relax-NG validity error.*: Element Repository failed to validate content'
log_grep ods_ods-control_enforcer_start stderr '.*crit.*[engine] cfgfile .*conf.xml has errors'
log_grep ods_ods-control_enforcer_start stderr 'enforcerd stopped with exitcode 2'
log_grep ods_ods-control_enforcer_start stderr 'Error: Daemon reported a failure starting. Please consult the logfiles.'

# the enforcer should not be running
! pgrep -u `id -u` 'ods-enforcerd' >/dev/null 2>/dev/null &&

! ods_start_signer &&
# signer does not log anything to syslog if reading conf.xml
! pgrep -u `id -u` 'ods-signerd' >/dev/null 2>/dev/null &&

return 0

ods_kill
return 1
