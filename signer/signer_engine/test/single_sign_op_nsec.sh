export SOFTHSM_CONF=./softhsm.conf
TMP_COMMANDS=`mktemp signtestXXXXX`
TMP_ZONE=`mktemp signzoneXXXXX`
# set the commands in a tmp file

echo "" > $TMP_COMMANDS
echo ":origin tjeb.nl" >> $TMP_COMMANDS
echo ":soa_ttl 3600" >> $TMP_COMMANDS
echo ":soa_minimum 3600" >> $TMP_COMMANDS
echo ":expiration 20090701000000" >> $TMP_COMMANDS
echo ":inception 20090605072316" >> $TMP_COMMANDS
echo ":jitter 60" >> $TMP_COMMANDS
echo ":refresh 20090606072616" >> $TMP_COMMANDS
echo ":add_ksk fc9ead5ec20345ca87e61836ff327ce1 5 257" >> $TMP_COMMANDS
echo ":add_zsk e715319b2fe146bfb4fa8e9b2c780d21 5 256" >> $TMP_COMMANDS
# prepare the zone
echo "Preparing zone"
cat unsigned_zones/tjeb.nl > $TMP_ZONE
echo "Adding keys"
../../tools/create_dnskey -r test -c opendnssec.xml -o tjeb.nl -a 5 -f 257 -t 3600 fc9ead5ec20345ca87e61836ff327ce1 >> $TMP_ZONE
../../tools/create_dnskey -r test -c opendnssec.xml -o tjeb.nl -a 5 -f 256 -t 3600 e715319b2fe146bfb4fa8e9b2c780d21 >> $TMP_ZONE
# sort, nsec, and sign it
echo "Signing zone"
../../tools/zone_reader -f $TMP_ZONE -o tjeb.nl |\
../../tools/nseccer >> $TMP_COMMANDS

../../tools/signer -c opendnssec.xml -f $TMP_COMMANDS -w signed_zones/tjeb.nl

echo "Cleaning up"
rm $TMP_COMMANDS
rm $TMP_ZONE
