#!/usr/bin/env perl

use common::sense;
use JSON::XS;
use utf8;
use Carp;

my $JSON = JSON::XS->new;

open(FILE, $ARGV[0]) or die;
my $file;
while (<FILE>) {
    $file .= $_;
}
close(FILE);

my %DB_TYPE_TO_DIA = (
    DB_TYPE_PRIMARY_KEY => '',
    DB_TYPE_INT32 => 'int',
    DB_TYPE_UINT32 => 'uint',
    DB_TYPE_INT64 => 'int64',
    DB_TYPE_UINT64 => 'uint64',
    DB_TYPE_TEXT => 'text',
    DB_TYPE_ENUM => 'enum',
    DB_TYPE_ANY => 'any'
);

my $objects = $JSON->decode($file);

foreach my $object (@$objects) {
    my $name = $object->{name};
    my $tname = $name;
    $tname =~ s/_/ /go;

print '<!-- ', $name, ' -->
';

foreach my $field (@{$object->{fields}}) {
    my $primary_key = 'false';
    my $unique = 'false';

    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
        $primary_key = 'true';
        $unique = 'true';
    }
    if ($field->{unique}) {
        $unique = 'true';
    }
print '        <dia:composite type="table_attribute">
          <dia:attribute name="name">
            <dia:string>#', $field->{name}, '#</dia:string>
          </dia:attribute>
          <dia:attribute name="type">
            <dia:string>#', $DB_TYPE_TO_DIA{$field->{type}}, '#</dia:string>
          </dia:attribute>
          <dia:attribute name="comment">
            <dia:string>##</dia:string>
          </dia:attribute>
          <dia:attribute name="primary_key">
            <dia:boolean val="', $primary_key, '"/>
          </dia:attribute>
          <dia:attribute name="nullable">
            <dia:boolean val="false"/>
          </dia:attribute>
          <dia:attribute name="unique">
            <dia:boolean val="', $unique, '"/>
          </dia:attribute>
        </dia:composite>
';
}

}
