s
#!/usr/bin/env bash

#TEST: Change port of database and check if enforcer fails to connect

if [ -z "$HAVE_MYSQL" ]; then
	return 0
fi &&

! ods_reset_env &&

ods_setup_conf conf.xml conf-correct.xml &&

ods_reset_env &&

ods_setup_conf conf.xml conf.xml &&

! ods_start_enforcer &&
# This is not guaranteed to work:
# syslog_waitfor 80 "ods-enforcerd: Could not connect to database or database not set up properly." &&
# if your MySQL is MariaDB, the failure appears elsewhere (which is allowed)
# and the following message is outputted
# Error: unable to connect to database!
# But a simple egrep won't do as this is outputed to stderr, not syslog
! pgrep -u `id -u` 'ods-enforcerd' >/dev/null 2>/dev/null &&
return 0

ods_kill
return 1
