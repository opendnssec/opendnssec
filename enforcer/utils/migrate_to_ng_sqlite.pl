#!/usr/bin/perl 
#===============================================================================
#
#         FILE: migrate_to_ng_sqlite.pl
#
#        USAGE: ./migrate_to_ng_sqlite.pl  
#
#  DESCRIPTION: export state from a kasp.db file to xml.
#
#      OPTIONS: ---
# REQUIREMENTS: ---
#         BUGS: ---
#        NOTES: ---
#       AUTHOR: Siôn Lloyd (SL), sion@nominet.org.uk
#      COMPANY: Nominet
#      VERSION: 1.0
#      CREATED: 26/01/12 11:12:07
#     REVISION: ---
#===============================================================================

use strict;
use warnings;

use DBI;
use DBD::SQLite;
use Getopt::Std     qw(getopts);

my %sm;
my %policy;

use vars (
    q!$opt_d!,      # Database file fo convert
    q!$opt_f!,      # Force commit if view has changed
);

getopts('d:f')
    or die "Please supply a database file to work on with the -d flag";

if (!$opt_d) {
    print STDERR "Please supply a database file to work on with the -d flag\n";
    exit 1;
}

open  my $OUT, '>', "enforcerstate.xml"
    or die  "$0 : failed to open  output file 'enforcerstate.xml' : $!\n";

my $date = localtime;
print $OUT "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
print $OUT "<!-- Exported enforcer state from $opt_d at $date -->\n\n";
print $OUT "<EnforcerState>\n";

###
# Make sure that we can connect to this database
my $dbh = DBI->connect("dbi:SQLite:dbname=$opt_d","","")
    or die "Couldn't connect: $!";

###
# Prepare a keys statement that we will need later
my $keys_sth = $dbh->prepare("select id, keypair_id, keytype, state, publish, ready, active, retire, dead from dnsseckeys where zone_id = ?")
	or die  "Couldn't prepare keys_sth $!";
my $KEYPAIR_ID=1; my $KEYTYPE=2; my $STATE=3; my $PUBLISH=4; my $READY=5; my $ACTIVE=6; my $RETIRE=7; my $DEAD=8;

###
# Create hashmap of securitymodules table
my $sm_sth = $dbh->prepare("select id, name from securitymodules")
	or die  "Couldn't prepare sm_sth $!";
$sm_sth->execute();
while (my @row = $sm_sth->fetchrow_array) {
	$sm{ $row[0] } = $row[1];
}

###
# Create a hashmap of the policy info we need
my $policy_sth = $dbh->prepare("select p.id, name, salt, salt_stamp, pp.value from policies p, parameters_policies pp where p.id = pp.policy_id and pp.parameter_id = 9")
	or  die  "Couldn't prepare policy_sth $!";
$policy_sth->execute();
while (my @row = $policy_sth->fetchrow_array) {
	@{ $policy { $row[0] }} = @row;
}
my $ID=0; my $NAME=1; my $SALT=2; my $SALT_STAMP=3; my $NSEC=4;

###
# Let's go to work. Loop over zones
my $zone_sth = $dbh->prepare("select id, name, policy_id from zones")
	or die  "Couldn't prepare zone_sth $!";
$zone_sth->execute();

print $OUT "  <Zones>\n";
while (my @row = $zone_sth->fetchrow_array) {
	print $OUT "    <Zone name=\"$row[1]\">\n";

	# Get and write keys
	$keys_sth->execute( $row[0] );
	print $OUT "      <Keys>\n";
	while (my @key = $keys_sth->fetchrow_array) {
		print $OUT "        <Key id=\"$key[$ID]\">\n";
		print $OUT "          <KeyPairId>$key[$KEYPAIR_ID]</KeyPairId>\n";

		print $OUT "          <Type>ZSK</Type>\n" if $key[$KEYTYPE] == 256;
		print $OUT "          <Type>KSK</Type>\n" if $key[$KEYTYPE] == 257;

		print $OUT "          </Standby>\n" if $key[$STATE] > 6;

		print $OUT "          <Publish>$key[$PUBLISH]</Publish>\n" if $key[$PUBLISH];
		print $OUT "          <Ready>$key[$READY]</Ready>\n" if $key[$READY];
		print $OUT "          <Active>$key[$ACTIVE]</Active>\n" if $key[$ACTIVE];
		print $OUT "          <Retire>$key[$RETIRE]</Retire>\n" if $key[$RETIRE];
		print $OUT "          <Dead>$key[$DEAD]</Dead>\n" if $key[$DEAD];

		print $OUT "        </Key>\n";
	}
	print $OUT "      </Keys>\n";

	if (${ $policy{$row[0]} }[$NSEC] == 3) {
		print $OUT "\n      <NSEC3>\n";
		print $OUT "        <Salt>${ $policy{$row[0]} }[$SALT]</Salt>\n";
		print $OUT "        <Generated>${ $policy{$row[0]} }[$SALT_STAMP]</Generated>\n";
		print $OUT "      </NSEC3>\n";
	}

	print $OUT "    </Zone>\n";
}
print $OUT "  </Zones>\n\n";

###
# Now add the keypairs
my $keypair_sth = $dbh->prepare("select id, algorithm, size, securitymodule_id, HSMkey_id, policy_id, generate, backup, compromisedflag from keypairs")
	or die  "Couldn't prepare keypair_sth $!";
$keypair_sth->execute();
my $ALGORITHM=1; my $SIZE=2; my $SM_ID=3; my $HSMKEY_ID=4; my $POLICY_ID=5; my $GENERATE=6; my $BACKUP=7; my $COMPROMISED=8;

print $OUT "  <KeyPairs>\n";
while (my @row = $keypair_sth->fetchrow_array) {
print $OUT "    <KeyPair id=\"$row[$ID]\">\n";

print $OUT "      <Algorithm>$row[$ALGORITHM]</Algorithm>\n";
print $OUT "      <Size>$row[$SIZE]</Size>\n";
print $OUT "      <Repository>$sm{ $row[$SM_ID] }</Repository>\n";
print $OUT "      <Locator>$row[$HSMKEY_ID]</Locator>\n";
print $OUT "      <Policy>${ $policy{ $row[$POLICY_ID] }}[$NAME]</Policy>\n";
print $OUT "      <Generated>$row[$GENERATE]</Generated>\n";
print $OUT "      <LastBackup>$row[$BACKUP]</LastBackup>\n" if $row[$BACKUP];
print $OUT "      </Compromised>\n" if $row[$COMPROMISED];

print $OUT "    </KeyPair>\n";
}
print $OUT "  </KeyPairs>\n";

print $OUT "</EnforcerState>\n";
close $OUT;
$dbh->disconnect;
