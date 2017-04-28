#!/usr/bin/env perl
#
# Copyright (c) 2012 OpenDNSSEC AB (svb). All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
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

use strict;
use warnings;

use DBI;
use Getopt::Long ();
use Pod::Usage ();
use File::Basename ();

# Try to require Term::ReadKey, ignore if it does not exist
eval {
    require Term::ReadKey;
};

my ($sth, $row);

my $schema_path;
my $from;
my $from_username;
my $from_password;
my $to;
my $to_username;
my $to_password;
my $help;

Pod::Usage::pod2usage(1) unless (@ARGV);
Getopt::Long::GetOptions(
    'help|?' => \$help,
    'schema-path:s' => \$schema_path,
    'from=s' => \$from,
    'from-username:s' => \$from_username,
    'from-password:s' => \$from_password,
    'to=s' => \$to,
    'to-username:s' => \$to_username,
    'to-password:s' => \$to_password
) or Pod::Usage::pod2usage(2);
Pod::Usage::pod2usage(-verbose => 99, -exitval => 1) if $help;

#
# Check schema path and existence of database creation scripts
#

unless (defined $schema_path) {
    $schema_path = File::Basename::dirname($0);
}

unless (-r $schema_path.'/database_create.sqlite3' and -r $schema_path.'/database_create.mysql') {
    print STDERR $0, ': Can not find database creation schemas, please set or correct --schema-path.', "\n";
    exit(-1);
}

#
# Check --from, let DBI parse it and check that the correct data sources are used
#

unless (defined $from) {
    print STDERR $0, ': Missing required option --from.', "\n";
    exit(-1);
}

my (undef, $from_data_source) = DBI->parse_dsn($from);

unless (defined $from_data_source and ($from_data_source eq 'mysql' or $from_data_source eq 'SQLite')) {
    print STDERR $0, ': Invalid data source used in --from DSN, only mysql or SQLite allowed (case sensitive).', "\n";
    exit(-1);
}

#
# Check --to, let DBI parse it and check that the correct data sources are used
#

unless (defined $to) {
    print STDERR $0, ': Missing required option --to.', "\n";
    exit(-1);
}

my (undef, $to_data_source) = DBI->parse_dsn($to);

unless (defined $to_data_source and ($to_data_source eq 'mysql' or $to_data_source eq 'SQLite')) {
    print STDERR $0, ': Invalid data source used in --to DSN, only mysql or SQLite allowed (case sensitive).', "\n";
    exit(-1);
}

#
# Prompt for --from-password if from DSN is MySQL and password not given
#

if (!defined $from_password and $from_data_source eq 'mysql') {
    print 'Enter exporting database password (--from-password): ';

    # Try Term::ReadKey
    eval {
        ReadMode('noecho');
        $from_password = ReadLine(0);
        ReadMode('echo');
    };
    
    # Fallback if Term::ReadKey does not exist
    if ($@) {
        $from_password = <STDIN>;
    }
    
    unless ($from_password) {
        print STDERR $0, ': No password given for exporting database.', "\n";
    }

    $from_password =~ s/[\r\n]+$//o;
}

#
# Connect to exporting database and get the schema version
#

my $from_dbh;
my $from_version;

unless ($from_dbh = DBI->connect($from, $from_username, $from_password, { AutoCommit => 1 })) {
    print STDERR $0, ': Unable to connect to exporting database [', $from, ']: ', $DBI::errstr, "\n";
    exit(-1);
}
print 'Connected to exporting database ', $from, "\n";

$sth = prepare_or_die($from_dbh, 'SELECT version FROM dbadmin');
unless ($sth->execute and defined ($row = $sth->fetchrow_hashref) and defined ($from_version = $row->{version})) {
    $sth->finish;
    print STDERR $0, ': Unable to get schema version from exporting database', "\n";
    exit(-1);
}
$sth->finish;

#
# Check for supported database schema version
#

my $from_version_valid = 0;
if ($from_version == 4) {
    $from_version_valid = 1;
}

unless ($from_version_valid) {
    print STDERR $0, ': Exporting database schema version is not supported for conversion.', "\n";
    exit(-1);
}

#
# Validate existing data depending on importing data source
#

if ($to_data_source eq 'mysql') {
    if ($from_version == 4) {
        my $valid = 1;
        print 'Validating existing data', "\n";
        
        $sth = prepare_or_die($from_dbh, 'SELECT COUNT(*) AS "count" FROM securitymodules WHERE id > 127');
        unless ($sth->execute and defined ($row = $sth->fetchrow_hashref) and defined ($row->{count})) {
            $sth->finish;
            print STDERR $0, ': Unable to validate table securitymodules', "\n";
            exit(-1);
        }
        if ($row->{count}) {
            print 'Table securitymodules field id contains too large values', "\n";
            $valid = 0;
        }
        $sth->finish;
        
        $sth = prepare_or_die($from_dbh, 'SELECT COUNT(*) AS "count" FROM categories WHERE id > 127');
        unless ($sth->execute and defined ($row = $sth->fetchrow_hashref) and defined ($row->{count})) {
            $sth->finish;
            print STDERR $0, ': Unable to validate table categories', "\n";
            exit(-1);
        }
        if ($row->{count}) {
            print 'Table categories field id contains too large values', "\n";
            $valid = 0;
        }
        $sth->finish;
        
        $sth = prepare_or_die($from_dbh, 'SELECT COUNT(*) AS "count" FROM parameters WHERE id > 8388607');
        unless ($sth->execute and defined ($row = $sth->fetchrow_hashref) and defined ($row->{count})) {
            $sth->finish;
            print STDERR $0, ': Unable to validate table parameters', "\n";
            exit(-1);
        }
        if ($row->{count}) {
            print 'Table parameters field id contains too large values', "\n";
            $valid = 0;
        }
        $sth->finish;
        
        $sth = prepare_or_die($from_dbh, 'SELECT COUNT(*) AS "count" FROM serialmodes WHERE id > 127');
        unless ($sth->execute and defined ($row = $sth->fetchrow_hashref) and defined ($row->{count})) {
            $sth->finish;
            print STDERR $0, ': Unable to validate table serialmodes', "\n";
            exit(-1);
        }
        if ($row->{count}) {
            print 'Table serialmodes field id contains too large values', "\n";
            $valid = 0;
        }
        $sth->finish;
        
        $sth = prepare_or_die($from_dbh, 'SELECT COUNT(*) AS "count" FROM policies WHERE id > 8388607');
        unless ($sth->execute and defined ($row = $sth->fetchrow_hashref) and defined ($row->{count})) {
            $sth->finish;
            print STDERR $0, ': Unable to validate table policies', "\n";
            exit(-1);
        }
        if ($row->{count}) {
            print 'Table policies field id contains too large values', "\n";
            $valid = 0;
        }
        $sth->finish;
        
        $sth = prepare_or_die($from_dbh, 'SELECT COUNT(*) AS "count" FROM zones WHERE id > 8388607');
        unless ($sth->execute and defined ($row = $sth->fetchrow_hashref) and defined ($row->{count})) {
            $sth->finish;
            print STDERR $0, ': Unable to validate table zones', "\n";
            exit(-1);
        }
        if ($row->{count}) {
            print 'Table zones field id contains too large values', "\n";
            $valid = 0;
        }
        $sth->finish;
        
        $sth = prepare_or_die($from_dbh, 'SELECT COUNT(*) AS "count" FROM parameters_policies WHERE id > 8388607');
        unless ($sth->execute and defined ($row = $sth->fetchrow_hashref) and defined ($row->{count})) {
            $sth->finish;
            print STDERR $0, ': Unable to validate table parameters_policies', "\n";
            exit(-1);
        }
        if ($row->{count}) {
            print 'Table parameters_policies field id contains too large values', "\n";
            $valid = 0;
        }
        $sth->finish;
        
        unless ($valid) {
            print STDERR $0, ': Unable to get schema version from exporting database', "\n";
            exit(-1);
        }
    }
}

#
# Ask the user if he really wants to create the importing database and delete existing data
#

print 'Create the importing database, this will delete existing data? [NO/yes] ';
my $answer = <STDIN>;
chomp($answer);
unless ($answer =~ /^yes$/io) {
    exit(0);
}

if ($to_data_source eq 'mysql') {
    $to .= ';mysql_multi_statements=1';
}

#
# Prompt for --to-password if from DSN is MySQL and password not given
#

if (!defined $to_password and $to_data_source eq 'mysql') {
    print 'Enter importing database password (--to-password): ';

    # Try Term::ReadKey
    eval {
        ReadMode('noecho');
        $to_password = ReadLine(0);
        ReadMode('echo');
    };
    
    # Fallback if Term::ReadKey does not exist
    if ($@) {
        $to_password = <STDIN>;
    }
    
    unless ($to_password) {
        print STDERR $0, ': No password given for importing database.', "\n";
    }

    $to_password =~ s/[\r\n]+$//o;
}

#
# Connect to importing database
#

my $to_dbh;
my $to_version;

unless ($to_dbh = DBI->connect($to, $to_username, $to_password, { AutoCommit => 1 })) {
    print STDERR $0, ': Unable to connect to importing database [', $to, ']: ', $DBI::errstr, "\n";
    exit(-1);
}
print 'Connected to importing database ', $to, "\n";

#
# Create the importing database tables
#

if ($to_data_source eq 'mysql') {
    unless (open(FILE, $schema_path.'/database_create.mysql')) {
        print STDERR $0, ': ', "\n";
        exit(-1);
    }
    
    my $sql = '';
    while ((my $line = <FILE>)) {
        if ($line =~ /^\s*--/o) {
            next;
        }
        
        $line =~ s/\r//go;
        $sql .= $line;
        
        if ($sql =~ /\;$/o) {
            unless ($to_dbh->do($sql)) {
                print STDERR $0, ': Unable to create importing database, statement "', $sql, '" failed: ', $to_dbh->errstr, "\n";
                exit(-1);
            }
            $sql = '';
        }
    }
}
elsif ($to_data_source eq 'SQLite') {
    unless (open(FILE, $schema_path.'/database_create.sqlite3')) {
        print STDERR $0, ': ', "\n";
        exit(-1);
    }
    
    my $sql = '';
    while ((my $line = <FILE>)) {
        if ($line =~ /^\s*--/o) {
            next;
        }
        
        $line =~ s/\r//go;
        $sql .= $line;
        
        if ($sql =~ /\;$/o) {
            unless ($to_dbh->do($sql)) {
                print STDERR $0, ': Unable to create importing database, statement "', $sql, '" failed: ', $to_dbh->errstr, "\n";
                exit(-1);
            }
            $sql = '';
        }
    }
}
else {
    print STDERR $0, ': Invalid data source, internal bug? please report this', "\n";
    exit(-1);
}

#
# Get the schema version of the importing database
#

$sth = prepare_or_die($to_dbh, 'SELECT version FROM dbadmin');
unless ($sth->execute and defined ($row = $sth->fetchrow_hashref) and defined ($to_version = $row->{version})) {
    $sth->finish;
    print STDERR $0, ': Unable to get schema version from importing database', "\n";
    exit(-1);
}
$sth->finish;

#
# Validate that we are using the same exporting and importing schema version
#

unless ($from_version == $to_version) {
    print STDERR $0, ': Database schema version missmatch [from: ', $from_version, ' to: ', $to_version, '], can not convert databases of different schema versions, please upgrade existing installation first.', "\n";
    exit(-1);
}

#
# Convert the database
#

if ($from_version == 4) {
    #
    # Schema version 3 does not need any data modifications so just dump it out and in
    #
    
    my @tables = (
        { securitymodules => {
            delete => 'DELETE FROM securitymodules',
            select => 'SELECT * FROM securitymodules',
            insert => 'INSERT INTO securitymodules VALUES ( ?, ?, ?, ? )'
        }},
        { categories => {
            delete => 'DELETE FROM categories',
            select => 'SELECT * FROM categories',
            insert => 'INSERT INTO categories VALUES ( ?, ? )'
        }},
        { parameters => {
            delete => 'DELETE FROM parameters',
            select => 'SELECT * FROM parameters',
            insert => 'INSERT INTO parameters VALUES ( ?, ?, ?, ? )'
        }},
        { serialmodes => {
            delete => 'DELETE FROM serialmodes',
            select => 'SELECT * FROM serialmodes',
            insert => 'INSERT INTO serialmodes VALUES ( ?, ?, ? )'
        }},
        { policies => {
            delete => 'DELETE FROM policies',
            select => 'SELECT * FROM policies',
            insert => 'INSERT INTO policies VALUES ( ?, ?, ?, ?, ?, ? )'
        }},
        { zones => {
            delete => 'DELETE FROM zones',
            select => 'SELECT * FROM zones',
            insert => 'INSERT INTO zones VALUES ( ?, ?, ?, ?, ?, ?, ?, ? )'
        }},
        { keypairs => {
            delete => 'DELETE FROM keypairs',
            select => 'SELECT * FROM keypairs',
            insert => 'INSERT INTO keypairs VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )'
        }},
        { dnsseckeys => {
            delete => 'DELETE FROM dnsseckeys',
            select => 'SELECT * FROM dnsseckeys',
            insert => 'INSERT INTO dnsseckeys VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )'
        }},
        { parameters_policies => {
            delete => 'DELETE FROM parameters_policies',
            select => 'SELECT * FROM parameters_policies',
            insert => 'INSERT INTO parameters_policies VALUES ( ?, ?, ?, ? )'
        }}
    );
    
    print 'Initializing conversion', "\n";
    
    foreach my $table (@tables) {
        my ($name) = keys %$table;
        
        $table->{$name}->{del_sth} = prepare_or_die($to_dbh, $table->{$name}->{delete});
        $table->{$name}->{sel_sth} = prepare_or_die($from_dbh, $table->{$name}->{select});
        $table->{$name}->{ins_sth} = prepare_or_die($to_dbh, $table->{$name}->{insert});
    }
    
    print 'Deleting existing data in importing database', "\n";
    
    foreach my $table (reverse(@tables)) {
        my ($name) = keys %$table;
        
        unless ($table->{$name}->{del_sth}->execute) {
            $table->{$name}->{del_sth}->finish;
            print STDERR $0, ': Unable to delete existing data in importing database table ', $name, ': ', $table->{$name}->{del_sth}->errstr, "\n";
            exit(-1);
        }
        
        $table->{$name}->{del_sth}->finish;
    }
    
    print 'Converting database', "\n";
    
    foreach my $table (@tables) {
        my ($name) = keys %$table;
        
        print "\t", $name, "\n";
        
        unless ($table->{$name}->{sel_sth}->execute) {
            $table->{$name}->{sel_sth}->finish;
            print STDERR $0, ': Unable to select from exporting database table ', $name, ': ', $table->{$name}->{sel_sth}->errstr, "\n";
            exit(-1);
        }
        while (defined (my $row = $table->{$name}->{sel_sth}->fetchrow_arrayref)) {
            unless ($table->{$name}->{ins_sth}->execute(@$row)) {
                $table->{$name}->{ins_sth}->finish;
                print STDERR $0, ': Unable to insert into importing database table ', $name, ': ', $table->{$name}->{ins_sth}->errstr, "\n";
                exit(-1);
            }
            $table->{$name}->{ins_sth}->finish;
        }
        $table->{$name}->{sel_sth}->finish;
    }
    
    print 'Optimizing database', "\n";
    
    if ($to_data_source eq 'mysql') {
        foreach my $table (@tables) {
            my ($name) = keys %$table;
            
            unless ($to_dbh->do('OPTIMIZE TABLE '.$name)) {
                print STDERR $0, ': Unable to OPTIMIZE TABLE ', $name, ': ', $to_dbh->errstr, "\n";
                exit(-1);
            }
        }
    }
    elsif ($to_data_source eq 'SQLite') {
        unless ($to_dbh->do('VACUUM')) {
            print STDERR $0, ': Unable to VACUUM database: ', $to_dbh->errstr, "\n";
            exit(-1);
        }
        
        unless ($to_dbh->do('ANALYZE')) {
            print STDERR $0, ': Unable to ANALYZE database: ', $to_dbh->errstr, "\n";
            exit(-1);
        }
    }
    else {
        print STDERR $0, ': Invalid data source, internal bug? please report this', "\n";
        exit(-1);
    }
}

print 'Done', "\n";

exit 0;

#
# Close connections on exit() if they exist
#

END {
    if (defined $from_dbh) {
        $from_dbh->disconnect;
    }
    if (defined $to_dbh) {
        $to_dbh->disconnect;
    }
}

#
# Prepare a statement or die trying
#

sub prepare_or_die {
    my ($dbh, $statement) = @_;
    my $sth;
    
    unless (defined ($sth = $dbh->prepare($statement))) {
        print STDERR $0, ': Unable to prepare statement "', $statement, '": ', $dbh->errstr, "\n";
        exit(-1);
    }
    
    $sth;
}

__END__

=head1 NAME

convert_database.pl - OpenDNSSEC database conversion tool

=head1 SYNOPSIS

convert_database.pl [options]

=head1 OPTIONS

=over 8

=item B<--schema-path <schema path>>

Specify the path to the directory containing the database schemas. (default to same path as convert_database.pl)

=item B<--from <dsn>>

Specify DBI DSN database connection string to use as the exporting database, see man/perldoc DBD::mysql or DBD::SQLite for more information. (Required)

=item B<--from-username <username>>

Username for the exporting database (default current logged in user).

=item B<--from-password <password>>

Password to the exporting database (default prompted if MySQL).

=item B<--to <dsn>>

Specify DBI DSN database connection string to use as the importing database, see man/perldoc DBD::mysql or DBD::SQLite for more information. (Required)

=item B<--to-username <username>>

Username for the importing database (default current logged in user).

=item B<--to-password <password>>

Password to the importing database (default prompted if MySQL).

=item B<--help>

Print a brief help message and exits.

=back

=head1 DESCRIPTION

This program converts OpenDNSSEC Enforcer database from one backend to another.

=head1 EXAMPLES

This example converts from a SQLite to a MySQL database using default installation paths:

convert_database.pl --from dbi:SQLite:dbname=/var/opendnssec/kasp.db --to dbi:mysql:database=kasp;host=localhost --to-username kasp --to-password kasp

=cut
