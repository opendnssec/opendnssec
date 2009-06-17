#!/bin/sh
#
# This is an example test script, notably testing against the SoftHSM.
# It uses the quickndirty version of the test for quicker cycling.
#
cd `dirname $0`/../../src
make
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
export SOFTHSM_CONF=/tmp/config.file
echo > "$SOFTHSM_CONF" '0:/tmp/test.db'
softhsm --init-token --slot 0 --label 'Testtoken' --pin 1234 --so-pin 4321
echo
echo ===========
echo Config file
echo ===========
cat $SOFTHSM_CONF
echo
echo ============
echo Running test
echo ============
./quickndirty-hsmbully
# gdb --tui ./quickndirty-hsmbully
