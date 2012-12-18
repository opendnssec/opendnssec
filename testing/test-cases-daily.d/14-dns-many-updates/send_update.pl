#!/usr/bin/env perl

# send_update.pl

# send an update from a simple text file

use strict;

use Getopt::Std     qw(getopts);
use Net::DNS;
use Net::DNS::SEC;


use IO::Handle;
*STDOUT->autoflush();

sub send_update;	# takes update, returns result
sub check_result;	# takes result & expected result


my $usage = 
"send_update.pl
\tusage: send_update.pl -z <zone> -k <keyfile> -u <updatefile> [-p <port>] [-s <server>] [-l <log>] 
\t(default port is 10053, default server is 127.0.0.1)
";

my %options=();
getopts("p:s:k:z:u:l:", \%options);

# options with defaults
my $MASTER = defined($options{s}) ? $options{s} : '127.0.0.1';
my $MASTER_PORT = defined($options{p}) ? $options{p} : 10053;

# options without defaults
die "missing zone\n $usage" if !defined $options{z};
my $zone = $options{z};
die "missing update file\n $usage" if !defined $options{k}; 
my $keyfile = $options{k};
die "missing tsig key file\n $usage" if !defined $options{u};
my $updates_file = $options{u};

# options where empty is OK
my $log_file = $options{l};

# open keyfile & get secrets
my $TSIG_KEY_SECRET;
my $TSIG_KEY_NAME;

open(my $fh_tsig, "<", $keyfile) or die "failed to open $keyfile";
while (<$fh_tsig>) {
	chomp (my $line=$_);
	$TSIG_KEY_NAME = $1
		if $line =~ /key\s*\"(.+)\"/;
	$TSIG_KEY_SECRET = $1
		if $line =~ /secret\s*\"(.+)\"/;
}
close $fh_tsig;
die "failed to find name in tsig file \"$keyfile\"" if !$TSIG_KEY_NAME;
die "failed to find secret in tsig file \"$keyfile\"" if !$TSIG_KEY_SECRET;


# check we can open updates files before we worry about BIND
open(my $fh_updates, "<", $updates_file) or die "failed to open $updates_file";

# check BIND is ready
my $count_check_named = 0;
CHECK_NAMED:
{
	# Set up a resolver object
	my $SOAres = Net::DNS::Resolver->new() or die "failed to create resolver";
	$SOAres->port($MASTER_PORT);
	$SOAres->nameservers($MASTER);
	$SOAres->debug(1); 
	$SOAres->recurse(0);   # No recursion
	$SOAres->usevc(1);

	# message if we had to wait'
	print "waiting for bind...\n" if $count_check_named;

	my $SOApacket = $SOAres->query($zone, 'SOA');
	last CHECK_NAMED if $SOApacket;

	sleep 1;
	redo CHECK_NAMED if ++$count_check_named;

	## couldn't talk to it
	system ("./run_bind.sh stop");
	die "unable to connect to BIND\n";
}
print "bind ready\n" if $count_check_named;


# Send an update to the zone's primary master.
my $res = Net::DNS::Resolver->new() or die "failed to create resolver";
$res->port($MASTER_PORT);
$res->nameservers($MASTER);
$res->recurse(0);   # No recursion
$res->usevc(1);     # Force use of TCP instead of UDP

my $update;     # Our update packet
$update = Net::DNS::Update->new($zone) or die "failed to create update";


my $expected_result = "NOERROR";	# overridden by "expect FOO" in script

# create update from input file
while (my $line = <$fh_updates>) {
	next if $line =~ /^\s*#/;	# comment
	next if $line =~ /^\s*$/;	# blank
	chomp($line);
	$line =~ s/#.*$//;	# strip comments
	$line =~ s/\s*$//;	# & trailing whitespace
	
#	print "line==>$line<==\n";
	
	if ($line =~ /^(rr_add|rr_del)\s+(.*)/) {
		if ($1 eq "rr_add") {
			$update->push('update'=>rr_add($2)) or die "failed to add RR \"".$2."\" to update";
		}
		elsif ($1 eq "rr_del") {
			$update->push('update'=>rr_del($2)) or die "failed to remove RR \"".$2."\" to update";
		}
		else {
			die "expected update rr_add or rr_del";
		}
	}
	elsif ($line =~ /^expect\s+(\S+)$/) {
		$expected_result = $1;
	}
	elsif ($line =~ /^send_update/) {
		# send the update now
		my $result = send_update ($update);
		# & check the result
		check_result ($result, $expected_result);
		
		# reset
		$update = Net::DNS::Update->new($zone) or die "failed to create update";
		$expected_result = "NOERROR";
	}
	
	else {
		die "expected update rr_add or rr_del";
	}
}
close $fh_updates;

# send any remaining updates i.e. don't bother sending empty 
if (scalar $update->authority() > 0) {
	# send the update now
	my $result = send_update ($update);
	# & check the result
	check_result ($result, $expected_result);
}

# done
exit 0;



sub check_result()
{
	my ($result, $expected_result) = @_;

	# check result: by default we expect NOERROR but this can be overridden in input file
	if (!$result) {
		print "no reply\n";	# BIND disappeared?
		exit 2;
	}
	elsif($result eq $expected_result) {
		# OK
   		return;
   	}
   	else {
   		print "error: we expected \"$expected_result\"\n";
   		exit 1;
   	}
}



sub send_update()
{
	my $update = shift;

	# sign the update
	$update->sign_tsig($TSIG_KEY_NAME, $TSIG_KEY_SECRET) or die "failed to sign";

	# dump if requested
	if (defined $log_file) {
	#	print "dumping to log $log_file\n";
		open (my $fh_log, ">>", $log_file) or die "failed to write \"$log_file\"";
		print {$fh_log} "update sent==>\n";
		print {$fh_log} $update->string;
		close $fh_log;
	}

	# send the update
	my $reply = $res->send($update);
	# check response
	if ($reply) {
		# dump reply if requested
		if (defined $log_file) {
			open (my $fh_log, ">>", $log_file) or die "failed to write \"$log_file\"";
			print {$fh_log} "\nreply received==>\n";
			print {$fh_log} $reply->string;
			close $fh_log;
		}

		print $reply->header->rcode."\n";
		
		return $reply->header->rcode;
	}
	else {
		return undef;
	}
}

