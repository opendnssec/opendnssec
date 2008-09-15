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

require 5.6.0;
use warnings;
use strict;

use Getopt::Long;
use Pod::Usage;
use File::Temp;

my $svnlook   = "/usr/local/bin/svnlook";
my $checkzone = "/usr/sbin/named-checkzone";

######################################################################

sub main {
    my $help    = 0;
    my $pattern = undef;

    GetOptions(
        'help|?'      => \$help,
        'svnlook=s'   => \$svnlook,
        'checkzone=s' => \$checkzone,
        'pattern=s'   => \$pattern,
    ) or pod2usage(2);
    pod2usage(1) if ($help);

    my $repos = shift @ARGV;
    my $txn   = shift @ARGV;

    pod2usage(1) unless ($repos && $txn && $pattern);

    my %changeset = changeset($repos, $txn);
    my $retval = 0;

    foreach my $filepath (keys %changeset) {

        if ($filepath =~ /^$pattern$/) {
            my $zone = $1;

            if (   $changeset{$filepath} eq "A"
                || $changeset{$filepath} eq "U")
            {
                my $fh = extract($repos, $txn, $filepath);

                if (checkzone($fh->filename, $zone)) {
                    print STDERR "named-checkzone failed for $filepath\n";
                    $retval++;
                } else {
		   print STDERR "named-checkzone successful for $filepath\n";
		}
            }
        }
    }

    exit($retval);
}

sub checkzone ($$) {
    my $filename = shift;
    my $zone     = shift;

    my $retval = undef;

    system(sprintf("%s -q %s %s", $checkzone, $zone, $filename));

    if ($? == 1) {
        warn "failed to execute: $!\n";
        $retval = -1;
    } elsif ($? & 127) {
        warn sprintf(
            "child died with signal %d, %s coredump",
            ($? & 127),
            ($? & 128) ? 'with' : 'without'
        );
        $retval = -2;
    } else {
        $retval = $? >> 8;
    }

    return $retval;
}

sub changeset ($$) {
    my $repos    = shift;
    my $selector = shift;

    my %changeset = ();
    my $opt       = undef;

    if ($selector =~ /^\d+-\d+$/) {
        $opt = "-t";    # transaction
    } elsif ($selector =~ /^\d+$/) {
        $opt = "-r";    # revision
    } else {
        return undef;
    }

    open(SVNLOOK,
        sprintf("%s changed %s %s %s |", $svnlook, $opt, $selector, $repos));

    while (<SVNLOOK>) {
        chomp;

        # added or updated file
        if (/^(A|U|D)\s+(.*)/) {
            $changeset{$2} = $1;
            next;
        }
    }

    close(SVNLOOK);

    return %changeset;
}

sub extract ($$$) {
    my $repos    = shift;
    my $selector = shift;
    my $filepath = shift;

    my $output = shift;

    my $opt = undef;

    if ($selector =~ /^\d+-\d+$/) {
        $opt = "-t";    # transaction
    } elsif ($selector =~ /^\d+$/) {
        $opt = "-r";    # revision
    } else {
        return undef;
    }

    my $fh = new File::Temp(
        TEMPLATE => "svnXXXXXXXX",
        DIR      => "/var/tmp"
    );

    open(SVNLOOK,
        sprintf(
            "%s cat %s %s %s %s |",
            $svnlook, $opt, $selector, $repos, $filepath, $output
        )
    );

    while (<SVNLOOK>) {
        print $fh $_;
    }

    close(SVNLOOK);
    close($fh);

    return $fh;
}

main();

__END__

=head1 NAME

svn-checkzone - Subversion pre-commit hook for checking DNS zones

=head1 SYNOPSIS

svn-checkzone [options] [repos] [txn]

Options:

 --help             brief help message
 --svnlook=FILE     filename of svnlook binary
 --checkzone=FILE   filename of named-checkzone binary
 --pattern=REGEXP   pattern used to select DNS zone files (required)


=head1 ABSTRACT

svn-checkzone can be used as a subversion pre-commit hook and will
only allow commits if the the file contents are passed by named-checkzone.
