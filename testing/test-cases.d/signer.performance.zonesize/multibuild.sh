#!/bin/sh

rm _build

configuration="-	"
configuration

for p in `ps auxww | grep ods- | grep -v grep | awk '{print$2}'` 
do
    kill -9 $p
done

for size in 10000 50000 100000 250000 500000 1000000 5000000 10000000
do
    if [ \! -f zonefiles/z$size ] ; then
        ./generate-zonefile - $size 1.0 0.2 > zonefiles/z$size
    fi
    ../../test-this.sh $size 2>&1 | tee -a _build
    sleep 60
    for p in `ps auxww | grep ods- | grep -v grep | awk '{print$2}'` 
    do
      kill -9 $p
    done

done

echo "STATISTICS	configuration	zonesize	memusage (kb)	time (s)"
grep ^STATISTICS _build
exit 0
