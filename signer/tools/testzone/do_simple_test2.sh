#!/bin/sh
(
  cat tjeb.nl &&\
  ../create_dnskey_pkcs11 -o tjeb.nl -m /home/jelte/opt/softHSM/lib/libsofthsm.so -p 11223344 45_5
) |\
../sorter |\
../stripper -o tjeb.nl |\
../nseccer |\
../signer_pkcs11 -o tjeb.nl -p 11223344 -m /home/jelte/opt/softHSM/lib/libsofthsm.so 45_5 >\
tjeb.nl.signed


