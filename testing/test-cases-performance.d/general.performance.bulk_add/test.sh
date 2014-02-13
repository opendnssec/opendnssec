#!/usr/bin/env bash
#
#TEST: Runs the general.performance.* tests.
#TEST: Designed to work in CentOS on titan - portability is questionable

prep_zones() {
  # do nothing for now - if this is anabled it should be altered to create the zone files under root install dir
  #for (( i=1 ; i <= 50000 ; i+=1 )); do sed s/\$ORIGIN.*txt/\$ORIGIN\ txt${i}/ unsigned/zone.txt > unsigned/zone.txt$i; done
  true
}

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&
prep_zones && 
source performance_test_utils.sh &&

# start enforcer daemon as this is needed in 2.0
ods_start_enforcer &&

source ./performance_test.sh &&

ods_stop_enforcer &&

echo && 
echo "************OK******************" &&
echo &&
cat performance_results.log &&

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

