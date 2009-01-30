#!/usr/bin/env perl
use strict;

system("rm -f zones/*");
system("rm -f keys/*");

open(INIT_SCRIPT, ">init_script");

for (my $i = 1; $i < 10; $i++) {
  my $zone_name = "zone$i.example";
  system("cat input_zone | sed 's/tjeb.nl/$zone_name/g' > zones/$zone_name");
  my @key = `cd keys && ldns-keygen -a rsasha1 -r /dev/urandom zone$i.example && cd ..`;
  print INIT_SCRIPT "add zone $zone_name test/zones/$zone_name test/signed_zones/$zone_name.signed\n";
  print INIT_SCRIPT "add key $zone_name test/keys/$key[0]";
  print INIT_SCRIPT "set interval $zone_name 60\n";
}

close(INIT_SCRIPT);
