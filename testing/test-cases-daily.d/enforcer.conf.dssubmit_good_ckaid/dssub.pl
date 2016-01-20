#!/usr/bin/env perl
#===============================================================================
#
#         FILE: dssub.pl
#
#        USAGE: ./dssub.pl  
#
#===============================================================================

use strict;
use warnings;
use File::Basename;

my $dirname = dirname(__FILE__);

my	$temp_file_name = "$dirname/dssub.out";		# output file name

open  my $temp, '>>', $temp_file_name
	or die  "$0 : failed to open  output file '$temp_file_name' : $!\n";

print $temp "\n**********************\n";

while (<STDIN>) {
	print $temp "$_";
}

close  $temp
	or warn "$0 : failed to close output file '$temp_file_name' : $!\n";


