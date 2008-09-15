#!/usr/bin/perl
#
# $Id$
#
# Copyright (c) 2008 Kirei AB. All rights reserved.
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
######################################################################

require 5.8.0;
use warnings;
use strict;

use Getopt::Long;
use File::Basename;

my $checkzone = "/usr/sbin/named-checkzone";
my $tempdir   = "/var/tmp";

######################################################################

sub main {
    my $zone;
    my $serial;
    my $destdir;

    GetOptions(
        'zone=s'    => \$zone,
        'serial=i'  => \$serial,
        'destdir=s' => \$destdir,
    ) or usage();

    my $input = shift @ARGV;

    usage() unless ($input);

    my $zonefile = basename($input);

    $zone    = $zonefile unless ($zone);
    $serial  = time()    unless ($serial);
    $destdir = "."       unless ($destdir);

    my $tempfile = sprintf("%s/%s.%d", $tempdir, $zonefile, $$);

    system(
        sprintf("%s -q -D -o %s %s %s", $checkzone, $tempfile, $zone, $input));

    if ($?) {
        print STDERR "$checkzone returned error for $input\n";
        exit(-1);
    }

    open(INPUT,  "< $tempfile");
    open(OUTPUT, "> $destdir/$zonefile");

    while (<INPUT>) {
        chomp;

        if (/(.*\s+IN\s+SOA\s+\S+\s+\S+\s+)(\d+)(\s+.+)$/) {
            printf OUTPUT ("%s%d%s\n", $1, $serial, $3);
            next;
        }

        print OUTPUT $_, "\n";
    }

    close(OUTPUT);
    close(INPUT);

    unlink($tempfile);
}

sub usage {
    print
      "usage: dns-installzone [--zone=ZONE] [--serial=NUM] [--destdir=DIR] zonefile\n";
    exit(-1);
}

main();
