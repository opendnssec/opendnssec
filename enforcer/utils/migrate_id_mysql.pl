#!/usr/bin/perl 
#===============================================================================
#
#         FILE:  migrate_id_mysql.pl
#
#        USAGE:  ./migrate_id_mysql.pl -d <DB> -u <USER> -p <PASSWORD>
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
#      CREATED:  11/02/11 14:25:45
#     REVISION:  ---
#===============================================================================

use strict;
use warnings;
use DBI;
use DBD::mysql;
use Getopt::Std     qw(getopts);

use vars (
    q!$opt_d!,      # Database to convert
    q!$opt_f!,      # Force commit if view has changed
    q!$opt_p!,      # Database password
    q!$opt_u!,      # Database user
);

getopts('d:fp:u:')
    or die "USAGE:  ./migrate_id_mysql.pl -d <DB> -u <USER> -p <PASSWORD>";

if (!$opt_d) {
    print STDERR "Please supply a database file to work on with the -d flag\nUSAGE:  ./migrate_id_mysql.pl -d <DB> -u <USER> -p <PASSWORD>";
    exit 1;
}
if (!$opt_u) {
    print STDERR "Please supply a database user with the -u flag\nUSAGE:  ./migrate_id_mysql.pl -d <DB> -u <USER> -p <PASSWORD>";
    exit 1;
}
if (!$opt_p) {
    print STDERR "Please supply a database password with the -p flag\nUSAGE:  ./migrate_id_mysql.pl -d <DB> -u <USER> -p <PASSWORD>";
    exit 1;
}

###
# First Create a backup of the existing file
system("mysqldump $opt_d -u $opt_u -p$opt_p > $opt_d.PRE_ID_GROW") == 0
    or die "Backup failed: $!";

###
# Make sure that we can connect to this database
my $dbh = DBI->connect("dbi:mysql:$opt_d:localhost",$opt_u,$opt_p,
    {AutoCommit => 0} )
    or die "Couldn't connect: $!";

###
# Find the name of the foreign key that we need to drop
my $fk_name = "";
my $fk_name_sql = "show create table dnsseckeys";
my $fk_name_sth = $dbh->prepare($fk_name_sql)
    or die  "Couldn't prepare fk_name_sql: $!";
$fk_name_sth->execute()
    or die  "Couldn't execute fk_name_sql: $!";
while (my @fk_row = $fk_name_sth->fetchrow_array) {
    my $temp = join('|', @fk_row);
	if ($temp =~ /CONSTRAINT `(.*?)` FOREIGN KEY \(`keypair_id`\) REFERENCES `keypairs` \(`id`\)/) {
		$fk_name = $1;
	} else {
		die("Could not extract foreign key name from: $temp");
	}
}

###
# Drop FK
print STDERR "Dropping foreign key $fk_name\n";
$dbh->do("alter table dnsseckeys drop foreign key $fk_name")
    or die "Couldn't drop foreign key: $!";

###
# Change the datatype of the 2 columns
print STDERR "Altering column types\n";
$dbh->do("ALTER TABLE keypairs MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT")
    or die "Couldn't modify keypairs: $!";
$dbh->do("ALTER TABLE dnsseckeys MODIFY COLUMN keypair_id INT")
    or die "Couldn't modify dnsseckeys: $!";

###
# put the FK back in
print STDERR "Replacing foreign key $fk_name\n";
$dbh->do("ALTER TABLE dnsseckeys add constraint `$fk_name` foreign key (keypair_id) references keypairs (id)")
    or die "Couldn't reapply foreign key: $!";

$dbh->commit;
$dbh->disconnect;

print STDERR "Successfuly altered keypairs(id)\n";
