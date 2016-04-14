#!/bin/bash

now=`../../../sbin/ods-enforcer queue 2>&1 | sed -e 's/^It is now.*(\([0-9][0-9]*\)[^)]*).*$/\1/p' -e 'd'`
cat > ../../../var/opendnssec/sequences/$now-dssubmit

exit 0
