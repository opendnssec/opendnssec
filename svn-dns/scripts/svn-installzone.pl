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

my $svnlook = "/usr/local/bin/svnlook";
my $install = "/usr/bin/install";

######################################################################

sub main {
    my $help    = 0;
    my $pattern = undef;
    my $destdir = undef;

    GetOptions(
        'help|?'    => \$help,
        'svnlook=s' => \$svnlook,
        'install=s' => \$install,
        'pattern=s' => \$pattern,
        'destdir=s' => \$destdir,
    ) or pod2usage(2);
    pod2usage(1) if ($help);

    my $repos = shift @ARGV;
    my $rev   = shift @ARGV;

    pod2usage(1) unless ($repos && $rev && $destdir);

    my %changeset = changeset($repos, $rev);
    my $retval = 0;

    foreach my $filepath (keys %changeset) {
        if ($filepath =~ /^$pattern$/) {
            my $zone = $1;

            if (   $changeset{$filepath} eq "A"
                || $changeset{$filepath} eq "U")
            {
                my $fh = extract($repos, $rev, $filepath);

                if (installzone($fh->filename, $zone, $destdir)) {
                    print STDERR "zone install failed for $filepath\n";
                    $retval++;
                }
            }
        }
    }

    exit($retval);
}

sub installzone ($$$) {
    my $filename = shift;
    my $zone     = shift;
    my $destdir  = shift;

    my $retval = undef;

    system(sprintf("%s -m 444 %s %s/%s", $install, $filename, $destdir, $zone));

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

svn-zoneinstall - Subversion post-commit hook for installing DNS zones

=head1 SYNOPSIS

svn-zoneinstall [options] [repos] [txn]

Options:

 --help             brief help message
 --svnlook=FILE     filename of svnlook binary
 --install=FILE     filename of install binary
 --pattern=REGEXP   pattern used to select DNS zone files (required)
 --destdir=DIR      destination directory for zonefiles (required)


=head1 ABSTRACT

svn-zoneinstall can be used as a subversion post-commit hook and will
copy committed zone files to a directory.
