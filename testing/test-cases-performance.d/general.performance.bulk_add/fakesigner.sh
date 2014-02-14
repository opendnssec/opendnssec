#!/bin/bash

while [ 1 ] ; do
  rm ../../../../root/local-test/var/run/opendnssec/engine.sock
  cat /dev/null | /usr/bin/nc -nlU ../../../../root/local-test/var/run/opendnssec/engine.sock 
done

