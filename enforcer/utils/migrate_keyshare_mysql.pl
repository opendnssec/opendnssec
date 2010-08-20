#!/usr/bin/perl 
#===============================================================================
#
#         FILE:  migrate_keyshare_mysql.pl
#
#        USAGE:  ./migrate_keyshare_mysql.pl -d <DB> -u <USER> -p <PASSWORD>
#
#  DESCRIPTION:  
#
#      OPTIONS:  ---
# REQUIREMENTS:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Sion, 
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  09/08/10 08:31:13
#     REVISION:  ---
#===============================================================================

use strict;
use warnings;
use DBI;
use DBD::mysql;
use Getopt::Std     qw(getopts);
use File::Copy;
use File::Compare;

use vars (
    q!$opt_d!,      # Database to convert
    q!$opt_f!,      # Force commit if view has changed
    q!$opt_p!,      # Database password
    q!$opt_u!,      # Database user
);

getopts('d:fp:u:')
    or die "Please supply a database to work on with the -d flag";

if (!$opt_d) {
    print STDERR "Please supply a database file to work on with the -d flag\n";
    exit 1;
}

###
# First Create a backup of the existing file
system("mysqldump $opt_d -u $opt_u -p$opt_p > $opt_d.PRE_KEY_SHARE") == 0
    or die "Backup failed: $!";

###
# Make sure that we can connect to this database
my $dbh = DBI->connect("dbi:mysql:$opt_d:localhost",$opt_u,$opt_p,
    {AutoCommit => 0} )
    or die "Couldn't connect: $!";

###
# Save copy of keydataview
my $keydata_sql = "select * from KEYDATA_VIEW";
my $keydata_sth = $dbh->prepare($keydata_sql)
    or die  "Couldn't prepare keydata_sql: $!";
$keydata_sth->execute()
    or die  "Couldn't execute keydata_sql: $!";

open  my $VIEW_FILE, '>', $opt_d.".KEYDATA_BEFORE"
    or die  "$0 : failed to open  output file '$opt_d.KEYDATA_BEFORE' : $!\n";

no warnings 'uninitialized';
while (my @view_row = $keydata_sth->fetchrow_array) {
    my $temp = join('|', @view_row);
    print $VIEW_FILE $temp;
    print $VIEW_FILE "\n";
}
use warnings;

close  $VIEW_FILE
    or warn "$0 : failed to close output file '$opt_d.KEYDATA_BEFORE' : $!\n";

###
# Create new columns
$dbh->do("alter table dnsseckeys add column state tinyint")
    or die "Couldn't add column state: $!";
$dbh->do("alter table dnsseckeys add column publish timestamp null default null")
    or die "Couldn't add column publish: $!";
$dbh->do("alter table dnsseckeys add column ready timestamp null default null")
    or die "Couldn't add column ready: $!";
$dbh->do("alter table dnsseckeys add column active timestamp null default null")
    or die "Couldn't add column active: $!";
$dbh->do("alter table dnsseckeys add column retire timestamp null default null")
    or die "Couldn't add column retire: $!";
$dbh->do("alter table dnsseckeys add column dead timestamp null default null")
    or die "Couldn't add column dead: $!";

###
# Migrate existing data
my $keypairs_sth = $dbh->prepare("select id, state, publish, ready, active, retire, dead from keypairs")
    or die  "Couldn't prepare keypairs_sql: $!";

my $update_sql = "update dnsseckeys set state = ?, publish = ?, ready = ?, active = ?, retire = ?, dead = ? where keypair_id = ?";
my $update_sth = $dbh->prepare($update_sql)
    or die  "Couldn't prepare update_sql: $!";

$keypairs_sth->execute();
while (my @key_row = $keypairs_sth->fetchrow_array) {
    $update_sth->execute($key_row[1], $key_row[2], $key_row[3], $key_row[4], $key_row[5], $key_row[6], $key_row[0])
        or die "Couldn't execute update command: $!";
}

###
# Remove old columns
$dbh->do("alter table keypairs drop column state")
    or die "Couldn't drop column state: $!";
$dbh->do("alter table keypairs drop column publish")
    or die "Couldn't drop column publish: $!";
$dbh->do("alter table keypairs drop column ready")
    or die "Couldn't drop column ready: $!";
$dbh->do("alter table keypairs drop column active")
    or die "Couldn't drop column active: $!";
$dbh->do("alter table keypairs drop column retire")
    or die "Couldn't drop column retire: $!";
$dbh->do("alter table keypairs drop column dead")
    or die "Couldn't drop column dead: $!";

###
# Fix old views (add new view)
$dbh->do("drop view if exists KEYDATA_VIEW")
    or die "Couldn't drop view KEYDATA_VIEW";
$dbh->do("create view KEYDATA_VIEW as
select k.id as id, d.state as state, k.generate as generate, d.publish as publish,
    d.ready as ready, d.active as active, d.retire as retire, d.dead as dead, 
    d.keytype as keytype, k.algorithm as algorithm, k.HSMkey_id as location,
    d.zone_id as zone_id, k.policy_id as policy_id, 
    k.securitymodule_id as securitymodule_id, k.size as size,
    k.compromisedflag as compromisedflag,
    k.fixedDate as fixedDate
from  keypairs k left outer join dnsseckeys d
on k.id = d.keypair_id")
or die "Couldn't recreate view KEYDATA_VIEW";

$dbh->do("create or replace view INT_KEYALLOC_VIEW_FOR_MYSQL as
select k.id as id, k.HSMkey_id as location, z.id as zone_id, k.algorithm as algorithm, k.policy_id as policy_id, k.securitymodule_id as securitymodule_id, k.size as size,
    k.compromisedflag as compromisedflag
from keypairs k left join zones z 
on k.policy_id = z.policy_id")
or die "Couldn't create view INT_KEYALLOC_VIEW_FOR_MYSQL";

$dbh->do("create or replace view KEYALLOC_VIEW as
select v.id as id, location, algorithm, policy_id, securitymodule_id, size, compromisedflag, d.zone_id as zone_id from
INT_KEYALLOC_VIEW_FOR_MYSQL v left outer join dnsseckeys d
on d.zone_id = v.zone_id
and d.keypair_id = v.id")
or die "Couldn't recreate view KEYALLOC_VIEW";

###
# Compare keydataview with saved copy
$keydata_sth->execute();

open  my $NEW_VIEW_FILE, '>', $opt_d.".KEYDATA_AFTER"
    or die  "$0 : failed to open  output file '$opt_d.KEYDATA_AFTER' : $!\n";

no warnings 'uninitialized';
while (my @view_row = $keydata_sth->fetchrow_array) {
    my $temp = join('|', @view_row);
    print $NEW_VIEW_FILE $temp;
    print $NEW_VIEW_FILE "\n";
}
use warnings;

close  $NEW_VIEW_FILE
    or warn "$0 : failed to close output file '$opt_d.KEYDATA_AFTER' : $!\n";

if (compare("$opt_d.KEYDATA_BEFORE","$opt_d.KEYDATA_AFTER") != 0) {
    print "keydata_view changed, this is probably bad.\n";
    if ($opt_f) {
        print "Forcing commit due to -f flag\n";
    } else {
        print "Compare the files $opt_d.KEYDATA_BEFORE and $opt_d.KEYDATA_AFTER; if you are happy that the changes are not important then run again with the -f flag to force a commit.\n";
        $dbh->rollback;     # This is slightly bad... this will not rollback and DDL
        exit 1;
    }
}

###
# Add new pre_backup column
$dbh->do("alter table keypairs add column pre_backup timestamp null default null")
    or die "Couldn't add column pre_backup: $!";

###
# Update DB version number
$dbh->do("update dbadmin set version = 2")
    or die "Couldn't update dbadmin: $!";

$dbh->commit;
$dbh->disconnect;
