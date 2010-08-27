#!/usr/bin/perl 
#===============================================================================
#
#         FILE:  migrate_keyshare_sqlite3.pl
#
#        USAGE:  ./migrate_keyshare_sqlite3.pl -d <KASP.DB>
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
use DBD::SQLite;
use Getopt::Std     qw(getopts);
use File::Copy;
use File::Compare;

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

###
# First Create a backup of the existing file
copy($opt_d, $opt_d.".PRE_KEY_SHARE")
    or die "Backup failed: $!";

###
# Make sure that we can connect to this database
my $dbh = DBI->connect("dbi:SQLite:dbname=$opt_d","","")
    or die "Couldn't connect: $!";

###
# Save copy of keydataview
my $keydata_sql = "select * from keydata_view";
my $keydata_sth = $dbh->prepare($keydata_sql)
    or die  "Couldn't prepare keydata_sql: $!";
$keydata_sth->execute();

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
$dbh->do("alter table dnsseckeys add column publish varchar(64) null default null")
    or die "Couldn't add column publish: $!";
$dbh->do("alter table dnsseckeys add column ready varchar(64) null default null")
    or die "Couldn't add column ready: $!";
$dbh->do("alter table dnsseckeys add column active varchar(64) null default null")
    or die "Couldn't add column active: $!";
$dbh->do("alter table dnsseckeys add column retire varchar(64) null default null")
    or die "Couldn't add column retire: $!";
$dbh->do("alter table dnsseckeys add column dead varchar(64) null default null")
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
# Arrgghhhh sqlite can't drop columns... Do it the long way
$dbh->do("alter table keypairs rename to keypairs_temp")
    or die "Couldn't rename keypairs: $!";

$dbh->do("create table keypairs(
  id     integer primary key autoincrement,
  HSMkey_id  varchar(255) not null,
  algorithm     tinyint not null,             -- algorithm code
  size          smallint,
  securitymodule_id          tinyint,                      -- where the key is stored
  generate      varchar(64) null default null,  -- time key inserted into database
  policy_id        mediumint,
  compromisedflag tinyint,
  publickey     varchar(1024),                -- public key data
  pre_backup    varchar(64) null default null,  -- time when backup was started
  backup        varchar(64) null default null,  -- time when backup was finished
  fixedDate     tinyint default 0,            -- Set to 1 to stop dates from being set according to the policy timings        
  
  foreign key (securitymodule_id) references securitymodules (id),
  foreign key (policy_id) references policies (id)
)")
or die "Couldn't recreate keypairs: $!";

$dbh->do("insert into keypairs select id, HSMkey_id, algorithm, size, securitymodule_id, generate, policy_id, compromisedflag, publickey, backup, fixedDate from keypairs_temp")
or die "Couldn't repopulate keypairs: $!";

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

$dbh->do("create view KEYALLOC_VIEW as
select v.id as id, location, algorithm, policy_id, securitymodule_id, size, compromisedflag, d.zone_id as zone_id from
(select k.id as id, k.HSMkey_id as location, z.id as zone_id, k.algorithm as algorithm, k.policy_id as policy_id, k.securitymodule_id as securitymodule_id, k.size as size,
    k.compromisedflag as compromisedflag
from keypairs k left join zones z where k.policy_id = z.policy_id )  v 
left outer join dnsseckeys d
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
        $dbh->disconnect;
        move($opt_d.".PRE_KEY_SHARE", $opt_d)
            or die "Move of backup failed: $!";
        exit 1;
    }
}

###
# Add new columns to zones table
$dbh->do("alter table zones add column signconf varchar(4096)")
    or die "Couldn't add column signconf: $!";
$dbh->do("alter table zones add column input varchar(4096)")
    or die "Couldn't add column input: $!";
$dbh->do("alter table zones add column output varchar(4096)")
    or die "Couldn't add column output: $!";

###
# Update DB version number
$dbh->do("update dbadmin set version = 2")
    or die "Couldn't update dbadmin: $!";

$dbh->commit;

###
# Clean up the temp table
$dbh->do("drop table keypairs_temp")
    or die "Couldn't drop keypairs_temp: $!";

$dbh->disconnect;
