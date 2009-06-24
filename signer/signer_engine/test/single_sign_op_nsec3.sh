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
echo ":add_ksk fc9ead5ec20345ca87e61836ff327ce1 7 257" >> $TMP_COMMANDS
echo ":add_zsk e715319b2fe146bfb4fa8e9b2c780d21 7 256" >> $TMP_COMMANDS
# prepare the zone
echo "Preparing zone"
cat unsigned_zones/tjeb.nl > $TMP_ZONE
echo "Adding keys"
../../tools/create_dnskey -r test -c opendnssec.xml -o tjeb.nl -a 7 -f 257 -t 3600 fc9ead5ec20345ca87e61836ff327ce1 >> $TMP_ZONE
../../tools/create_dnskey -r test -c opendnssec.xml -o tjeb.nl -a 7 -f 256 -t 3600 e715319b2fe146bfb4fa8e9b2c780d21 >> $TMP_ZONE
# sort, nsec, and sign it
echo "Signing zone"
../../tools/zone_reader -f $TMP_ZONE -o tjeb.nl -n -t 5 -s beef |\
../../tools/nsec3er -t 5 -s 998E54C0A50BBD71AF22B70CE0B51C733F3288ABF0586A81FA63BEEC779320C98AE23CE336434D01F0629CC20A478DAFEE5DAA0C883DA29679D22FE8D7047FD3A1E0D5192745C8EE21069A302600CE342B1102508DBB6A97F0736BF06268ED03DAF30B562270D81D6321C956A29B79E8071853D18B2EFCD3FC74D7718610FD641941351218DF4BCC55056BB48D8D7CE4FABF56A7BD473961CB9AAC9A0F21EF77 -o tjeb.nl >> $TMP_COMMANDS

../../tools/signer -c opendnssec.xml -p signed_zones/tjeb.nl.signed -f $TMP_COMMANDS -w signed_zones/tjeb.nl.tmp
mv signed_zones/tjeb.nl.tmp signed_zones/tjeb.nl.signed
../../tools/finalizer -f signed_zones/tjeb.nl.signed > signed_zones/tjeb.nl

echo "Cleaning up"
rm $TMP_COMMANDS
rm $TMP_ZONE
