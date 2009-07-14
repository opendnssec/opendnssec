#!/usr/bin/perl
#
# $Id$
#
# Copyright (c) 2008-2009 .SE (The Internet Infrastructure Foundation).
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# ************************************************************
# *
# * This perl script generates zone files 
# *
# ************************************************************

use strict;
use Getopt::Long;
use Pod::Usage;

######################################################################

sub main {
    my $help = 0;
    my $zone_name;
    my $number_zones = 0;
    my $ttl = 3600;
    my $number_rr = 0;
    my $percent_ns = 0;
    my $number_ns = 0;
    my $percent_ds = 0;
    my $percent_a = 0;
    my $percent_aaaa = 0;
    my $output_path;
    my $add_to_ksm = 0;
    my $config_path;
    my $signer_output_path;
    my $ksm_policy;

    GetOptions(
        'help|?'         => \$help,
        'zonename=s'     => \$zone_name,
        'nzones=i'       => \$number_zones,
        'ttl=i'          => \$ttl,
        'nrr=i'          => \$number_rr,
        'pns=i'          => \$percent_ns,
        'nns=i'          => \$number_ns,
        'pds=i'          => \$percent_ds,
        'pa=i'           => \$percent_a,
        'paaaa=i'        => \$percent_aaaa,
        'output=s'       => \$output_path,
        'addtoksm'       => \$add_to_ksm,
        'config=s'       => \$config_path,
        'signeroutput=s' => \$signer_output_path,
        'policy=s'       => \$ksm_policy
    ) or pod2usage(1);
    pod2usage(1) if ($help);

    unless($zone_name) {
        print "Error: You must specify the name of the zone/zones.\n";
        pod2usage(1);
    }
    if($number_zones <= 0) {
        print "Error: You must specify the number of zones to be generated.\n";
        pod2usage(1);
    }
    if($ttl <= 0) {
        print "Error: You must specify the TTL for the RR.\n";
        pod2usage(1);
    }
    if($number_rr <= 0) {
        print "Error: You must specify the number of RR to create per zone (not including zone apex).\n";
        pod2usage(1);
    }
    if($percent_ns < 0 || $percent_ds < 0 || $percent_a < 0 || $percent_aaaa < 0) {
        print "Error: The number of percent must be between 0 and 100.\n";
        pod2usage(1);
    }
    if($percent_ns > 100 || $percent_ds > 100 || $percent_a > 100 || $percent_aaaa > 100) {
        print "Error: The number of percent must be between 0 and 100.\n";
        pod2usage(1);
    }
    if(($percent_ns + $percent_a + $percent_aaaa) == 0) {
        print "Error: You must specify a number greater than 0 for one of NS, A, and AAAA.\n";
        pod2usage(1);
    }
    if($percent_ns > 0 && $number_ns <= 0) {
        print "Error: You must specify how many NS there should be in a NS RRset.\n";
       pod2usage(1);
    } 
    unless($output_path) {
        print "Error: You must specify a path where the zones will be stored.\n";
        pod2usage(1);
    }
    unless(-d $output_path) {
        print "Error: The output path is not a directory.\n";
        exit 1;
    }
    unless(-w $output_path) {
        print "Error: The output path is not writable.\n";
        exit 1;
    }
    if($add_to_ksm) {
        unless($config_path) {
            print "Error: You must specify a path where communicated should output the signing configuration\n";
            pod2usage(1);
        }
        unless(-d $config_path) {
            print "Error: The config path is not a directory.\n";
            exit 1;
        }
        unless(-w $config_path) {
            print "Error: The config path is not writable.\n";
            exit 1;
        }
        unless($signer_output_path) {
            print "Error: You must specify a path where the Signer Engine should save the signed zones.\n";
            pod2usage(1);
        }
        unless(-d $signer_output_path) {
            print "Error: The signer output path is not a directory.\n";
            exit 1;
        }
        unless($ksm_policy) {
            print "Error: You must specify the policy that the zones should be signed with.\n";
            pod2usage(1);
        }
    }

    my $zone_counter = 1;
    for($zone_counter = 1; $zone_counter <= $number_zones; $zone_counter++) {
        createZone($number_zones, $zone_counter, $zone_name, $ttl, $number_rr, $percent_ns, $number_ns, $percent_ds, 
                   $percent_a, $percent_aaaa, $output_path, $add_to_ksm, $config_path, $signer_output_path, $ksm_policy);
    }
}

sub createZone {
    my $number_zones = shift;
    my $zone_counter = shift;
    my $old_zone_name = shift;
    my $ttl = shift;
    my $number_rr = shift;
    my $percent_ns = shift;
    my $number_ns = shift;
    my $percent_ds = shift;
    my $percent_a = shift;
    my $percent_aaaa = shift;
    my $output_path = shift;
    my $add_to_ksm = shift;
    my $config_path = shift;
    my $signer_output_path = shift;
    my $ksm_policy = shift;

    my $zone_name;
    if($number_zones == 1) {
        $zone_name = $old_zone_name;
    } else {
        $zone_name = sprintf("%i%s", $zone_counter, $old_zone_name);
    }

    open my $file_handle, ">", "$output_path/$zone_name" or die("Error: Could not open file for output.");

    createZoneApex($file_handle, $zone_name, $ttl);

    my $rr_counter = 0;
    my $label_counter = 0;
    while($rr_counter < $number_rr) {
        my $label_name = sprintf("label%i.%s", $label_counter + 1, $zone_name);
        $rr_counter += createLabel($file_handle, $label_name, $ttl, $percent_ns, $number_ns, 
                                   $percent_ds, $percent_a, $percent_aaaa);
        $label_counter++;
    }

    close $file_handle;

    if($add_to_ksm) {
        my $full_config = "$config_path/$zone_name.xml";
        $full_config =~ s/\/\//\//g;
        my $full_output = "$output_path/$zone_name";
        $full_output =~ s/\/\//\//g;
        my $full_signer_output = "$signer_output_path/$zone_name";
        $full_signer_output =~ s/\/\//\//g;

        system("ksmutil", "addzone", $zone_name, $ksm_policy, $full_config, $full_output, $full_signer_output);
    }
}

sub createZoneApex {
    my $file_handle = shift;
    my $zone_name = shift;
    my $ttl = shift;

    print $file_handle "$zone_name. $ttl IN SOA ns1.$zone_name. hostmaster.$zone_name. 1000 1200 180 1209600 $ttl\n";
    print $file_handle "$zone_name. $ttl IN MX 10 mail.$zone_name.\n";
    print $file_handle "$zone_name. $ttl IN NS ns1.$zone_name.\n";
    print $file_handle "$zone_name. $ttl IN NS ns2.$zone_name.\n";
    print $file_handle "$zone_name. $ttl IN A 192.0.2.1\n";
    print $file_handle "mail.$zone_name. $ttl IN A 192.0.2.1\n";
    print $file_handle "ns1.$zone_name. $ttl IN A 192.0.2.1\n";
    print $file_handle "ns2.$zone_name. $ttl IN A 192.0.2.1\n";
}

sub createLabel() {
    my $file_handle = shift;
    my $domain_name = shift;
    my $ttl = shift;
    my $percent_ns = shift;
    my $number_ns = shift;
    my $percent_ds = shift;
    my $percent_a = shift;
    my $percent_aaaa = shift;

    my $rr_counter = 0;
    my $loop_counter = 0;

    while($rr_counter == 0) {
        # Create NS, delegation
        my $random_number = int(rand(100));
        if($random_number < $percent_ns) {
            for($loop_counter = 1; $loop_counter <= $number_ns; $loop_counter++) {
                print $file_handle "$domain_name. $ttl IN NS ns$loop_counter.$domain_name.\n";
                print $file_handle "ns$loop_counter.$domain_name. $ttl IN A 192.0.2.1\n";
                $rr_counter += 2;
            }
            # Create DS
            $random_number = int(rand(100));
            if($random_number < $percent_ds) {
                print $file_handle "$domain_name. $ttl IN DS 22922 7 1 f62411de95a5b7bcabe976c0e65034a35a9fa937\n";
                $rr_counter++;
            }
        } else {
            # Create A
            $random_number = int(rand(100));
            if($random_number < $percent_a) {
                print $file_handle "$domain_name. $ttl IN A 192.0.2.1\n";
                $rr_counter++;
            }
            # Create AAAA
            $random_number = int(rand(100));
            if($random_number < $percent_aaaa) {
                print $file_handle "$domain_name. $ttl IN AAAA 2001:0db8:85a3:0000:0000:8a2e:0370:7334\n";
                $rr_counter++;
            }
        }
    }

    return $rr_counter;
}

main;

__END__

=head1 NAME

zonegen - a simple script that generates zone and can add them via ksmutil

=head1 SYNOPSIS

zonegen [options]

Options:

 --help           brief help message
 --zonename S     The name of the zone. E.g. largetld or suffix.org. Multiple zones will get a number as a prefix
 --nzones N       Number of zones to generate
 --ttl N          The TTL to use
 --nrr N          Minimum number of RR per zone (not including zone apex, 8 RR)
 --pns N          0-100 % chance that a subdomain will get a NS RR with A RR as glue, thus delegated
 --nns N          Number of NS in a NS RRset, if delegated
 --pds N          0-100 % chance that a delegation will get a DS RR
 --pa N           0-100 % chance that a subdomain will get an A RR
 --paaaa N        0-100 % chance that a subdomain will get an AAAA RR
 --output S       Directory where the generated zones can be stored
 --addtoksm       If the zones should be added to OpenDNSSEC via the ksmutil.
                  Use with --config, --signeroutput, and --policy
 --config S       Directory where the zone signing configuration can be stored
 --signeroutput S Directory where the signed zone will go
 --policy S       The policy that OpenDNSSEC will use to sign the zone

zonegen will generate zone files and can add them to OpenDNSSEC via ksmutil.

Example - To generate many small zones (ISP). 5000 zones, each with an apex of 8 RR. Minimum 2 extra RR, where each new sub domain get an A RR and only 5 percent get an AAAA RR:

  perl zonegen.pl --zonename suffix.org --nzones 5000 --nrr 2 --pa 100 --paaaa 5 --output ./

Example - To generate a single large zone (e.g. TLD). A single zone with minimum one million RR. Each deletegation gets new NS with glue and 10 percent will have a DS RR:

  perl zonegen.pl --zonename largetld --nzones 1 --nrr 1000000 --nns 2 --pns 100 --pds 10 --output ./
