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

my %DB_TYPE_TO_C_TYPE = (
    DB_TYPE_PRIMARY_KEY => 'should_not_be_used',
    DB_TYPE_INT32 => 'int',
    DB_TYPE_UINT32 => 'unsigned int',
    DB_TYPE_INT64 => 'long long',
    DB_TYPE_UINT64 => 'unsigned long long',
    DB_TYPE_TEXT => 'char*'
);

my %DB_TYPE_TO_SQLITE = (
    DB_TYPE_PRIMARY_KEY => 'INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL',
    DB_TYPE_INT32 => 'INT NOT NULL',
    DB_TYPE_UINT32 => 'UNSIGNED INT NOT NULL',
    DB_TYPE_INT64 => 'BIGINT NOT NULL',
    DB_TYPE_UINT64 => 'UNSIGNED BIGINT NOT NULL',
    DB_TYPE_TEXT => 'TEXT NOT NULL',
    DB_TYPE_ENUM => 'INT NOT NULL',
    DB_TYPE_REVISION => 'INTEGER NOT NULL DEFAULT 1'
);

my %DB_TYPE_TO_MYSQL = (
    DB_TYPE_PRIMARY_KEY => 'BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT NOT NULL',
    DB_TYPE_INT32 => 'INT NOT NULL',
    DB_TYPE_UINT32 => 'INT UNSIGNED NOT NULL',
    DB_TYPE_INT64 => 'BIGINT NOT NULL',
    DB_TYPE_UINT64 => 'BIGINT UNSIGNED NOT NULL',
    DB_TYPE_TEXT => 'TEXT NOT NULL',
    DB_TYPE_ENUM => 'INT NOT NULL',
    DB_TYPE_REVISION => 'INT UNSIGNED NOT NULL DEFAULT 1'
);

my %DB_TYPE_TO_FUNC = (
    DB_TYPE_PRIMARY_KEY => 'should_not_be_used',
    DB_TYPE_INT32 => 'int32',
    DB_TYPE_UINT32 => 'uint32',
    DB_TYPE_INT64 => 'int64',
    DB_TYPE_UINT64 => 'uint64',
    DB_TYPE_TEXT => 'text'
);

my %DB_TYPE_TO_TEXT = (
    DB_TYPE_PRIMARY_KEY => 'a primary key database value',
    DB_TYPE_INT32 => 'an integer',
    DB_TYPE_UINT32 => 'an unsigned integer',
    DB_TYPE_INT64 => 'a long long',
    DB_TYPE_UINT64 => 'an unsigned long long',
    DB_TYPE_TEXT => 'a character pointer'
);

sub camelize {
    my $string = shift || confess;
    my $camelize = "";
    my @parts = split(/_/o, $string);

    $camelize = shift(@parts);
    foreach my $part (@parts) {
        $camelize .= ucfirst($part);
    }
    return $camelize;
}

my $objects = $JSON->decode($file);

foreach my $object (@$objects) {
    my $name = $object->{name};
    my $tname = $name;
    $tname =~ s/_/ /go;

open(HEADER, '>:encoding(UTF-8)', $name.'.h') or die;

    print HEADER '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __', $name, '_h
#define __', $name, '_h

#include "db_object.h"

struct ', $name, ';
struct ', $name, '_list;
typedef struct ', $name, ' ', $name, '_t;
typedef struct ', $name, '_list ', $name, '_list_t;

';

foreach my $field (@{$object->{fields}}) {
    if ($field->{type} ne 'DB_TYPE_ENUM') {
        next;
    }

    print HEADER 'typedef enum ', $name, '_', $field->{name}, ' {
    ', uc($name.'_'.$field->{name}), '_INVALID = -1';

    foreach my $enum (@{$field->{enum}}) {
        print HEADER ",\n", '    ', uc($name.'_'.$field->{name}), '_', $enum->{name}, ' = ', $enum->{value};
    }

    print HEADER '
} ', $name, '_', $field->{name}, '_t;
extern const db_enum_t ', $name, '_enum_set_', $field->{name}, '[];

';
}

print HEADER

#include "', $name, '_ext.h"
';
my %included = ();
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign} and !exists $included{$field->{foreign}}) {
print HEADER '#include "', $field->{foreign}, '.h"
';        
        $included{$field->{foreign}} = 1;
    }
}
print HEADER '

/**
 * A ', $tname, ' object.
 */
struct ', $name, ' {
    db_object_t* dbo;
';

foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
    print HEADER '    db_value_t ', $field->{name}, ";\n";
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        print HEADER '    ', $name, '_', $field->{name}, '_t ', $field->{name}, ";\n";
        next;
    }
    if ($field->{foreign}) {
        print HEADER '    db_value_t ', $field->{name}, ";\n";
        print HEADER '    const ', $field->{foreign},'_t* associated_', $field->{name}, ";\n";
        print HEADER '    ', $field->{foreign},'_t* private_', $field->{name}, ";\n";
        next;
    }
    print HEADER '    ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ";\n";
}

foreach my $associated (@{$object->{association}}) {
    print HEADER '    ', $associated->{foreign},'_list_t* ', $associated->{foreign}, "_list;\n";
}

print HEADER '};

/**
 * Create a new ', $tname, ' object.
 * \param[in] connection a db_connection_t pointer.
 * \return a ', $name, '_t pointer or NULL on error.
 */
', $name, '_t* ', $name, '_new(const db_connection_t* connection);

/**
 * Create a new ', $tname, ' object that is a copy of another ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return a ', $name, '_t pointer or NULL on error.
 */
', $name, '_t* ', $name, '_new_copy(const ', $name, '_t* ', $name, ');

/**
 * Delete a ', $tname, ' object, this does not delete it from the database.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 */
void ', $name, '_free(', $name, '_t* ', $name, ');

/**
 * Reset the content of a ', $tname, ' object making it as if its new. This does not change anything in the database.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 */
void ', $name, '_reset(', $name, '_t* ', $name, ');

/**
 * Copy the content of a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] ', $name, '_copy a ', $name, '_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_copy(', $name, '_t* ', $name, ', const ', $name, '_t* ', $name, '_copy);

/**
 * Compare two ', $tname, ' objects and return less than, equal to,
 * or greater than zero if A is found, respectively, to be less than, to match,
 * or be greater than B.
 * \param[in] ', $name, '_a a ', $name, '_t pointer.
 * \param[in] ', $name, '_b a ', $name, '_t pointer.
 * \return less than, equal to, or greater than zero if A is found, respectively,
 * to be less than, to match, or be greater than B.
 */
int ', $name, '_cmp(const ', $name, '_t* ', $name, '_a, const ', $name, '_t* ', $name, '_b);

/**
 * Set the content of a ', $tname, ' object based on a database result.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_from_result(', $name, '_t* ', $name, ', const db_result_t* result);

';

foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{foreign}) {
        print HEADER '/**
 * Get the ', $field->{name}, ' of a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return a db_value_t pointer or NULL on error.
 */
const db_value_t* ', $name, '_', $field->{name}, '(const ', $name, '_t* ', $name, ');

';
        if ($field->{foreign}) {
            my $func_name = $field->{name};
            $func_name =~ s/_id//o;
        print HEADER '/**
 * Cache the ', $field->{name}, ' object related to a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_cache_', $func_name, '(', $name, '_t* ', $name, ');

';
        print HEADER '/**
 * Get the ', $field->{name}, ' object related to a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return a ', $field->{foreign}, '_t pointer or NULL on error or if no object could be found.
 */
const ', $field->{foreign}, '_t* ', $name, '_', $func_name, '(const ', $name, '_t* ', $name, ');

';
        print HEADER '/**
 * Get the ', $field->{name}, ' object related to a ', $tname, ' object.
 * The caller will be given ownership of this object and is responsible for freeing it.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return a ', $field->{foreign}, '_t pointer or NULL on error or if no object could be found.
 */
', $field->{foreign}, '_t* ', $name, '_get_', $func_name, '(const ', $name, '_t* ', $name, ');

';
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        print HEADER '/**
 * Get the ', $field->{name}, ' of a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return a ', $name, '_', $field->{name}, '_t which may be ', uc($name.'_'.$field->{name}), '_INVALID on error or if no ', $field->{name}, ' has been set.
 */
', $name, '_', $field->{name}, '_t ', $name, '_', $field->{name}, '(const ', $name, '_t* ', $name, ');

/**
 * Get the ', $field->{name}, ' as text of a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return a character pointer or NULL on error or if no ', $field->{name}, ' has been set.
 */
const char* ', $name, '_', $field->{name}, '_text(const ', $name, '_t* ', $name, ');

';        
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
        print HEADER '/**
 * Get the ', $field->{name}, ' of a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return a character pointer or NULL on error or if no ', $field->{name}, ' has been set.
 */
const char* ', $name, '_', $field->{name}, '(const ', $name, '_t* ', $name, ');

';
        next;
    }

    print HEADER '/**
 * Get the ', $field->{name}, ' of a ', $tname, ' object. Undefined behavior if `', $name, '` is NULL.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return ', $DB_TYPE_TO_TEXT{$field->{type}}, '.
 */
', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $name, '_', $field->{name}, '(const ', $name, '_t* ', $name, ');

';
}

foreach my $associated (@{$object->{association}}) {
    print HEADER '/**
 * Get the ', $associated->{foreign}, ' objects related to a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return a ', $associated->{foreign}, '_list_t pointer or NULL on error.
 */
', $associated->{foreign}, '_list_t* ', $name, '_', $associated->{foreign}, '_list(', $name, '_t* ', $name, ');

';
    print HEADER '/**
 * Retrieve ', $associated->{foreign}, ' objects related to a ', $tname, ' object.
 * Use ', $name, '_', $associated->{foreign}, '_list() to get the list afterwards.
 * This will refetch objects if already retrieved.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_retrieve_', $associated->{foreign}, '_list(', $name, '_t* ', $name, ');

';
}

foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
        next;
    }
    if ($field->{foreign}) {
    print HEADER '/**
 * Set the ', $field->{name}, ' of a ', $tname, ' object. If this fails the original value may have been lost.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] ', $field->{name}, ' a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_set_', $field->{name}, '(', $name, '_t* ', $name, ', const db_value_t* ', $field->{name}, ');

';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        print HEADER '/**
 * Set the ', $field->{name}, ' of a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] ', $field->{name}, ' a ', $name, '_', $field->{name}, '_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_set_', $field->{name}, '(', $name, '_t* ', $name, ', ', $name, '_', $field->{name}, '_t ', $field->{name}, ');

/**
 * Set the ', $field->{name}, ' of a ', $tname, ' object from text.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] ', $field->{name}, ' a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_set_', $field->{name}, '_text(', $name, '_t* ', $name, ', const char* ', $field->{name}, ');

';        
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
        print HEADER '/**
 * Set the ', $field->{name}, ' of a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] ', $field->{name}, '_text a character pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_set_', $field->{name}, '(', $name, '_t* ', $name, ', const char* ', $field->{name}, '_text);

';
        next;
    }

    print HEADER '/**
 * Set the ', $field->{name}, ' of a ', $tname, ' object.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] ', $field->{name}, ' ', $DB_TYPE_TO_TEXT{$field->{type}};
if ($field->{min}) {
    print HEADER ' with a minimum value of ', $field->{min};
}
if ($field->{max}) {
    if ($field->{min}) {
        print HEADER ' and a maximum value of ', $field->{max};
    }
    else {
        print HEADER ' with a maximum value of ', $field->{max};
    }
}
print HEADER '.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_set_', $field->{name}, '(', $name, '_t* ', $name, ', ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ');

';
}

foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
        next;
    }
    if ($field->{foreign}) {
    print HEADER '/**
 * Create a clause for ', $field->{name}, ' of a ', $tname, ' object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] ', $field->{name}, ' a db_value_t pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* ', $name, '_', $field->{name}, '_clause(db_clause_list_t* clause_list, const db_value_t* ', $field->{name}, ');

';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        print HEADER '/**
 * Create a clause for ', $field->{name}, ' of a ', $tname, ' object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] ', $field->{name}, ' a ', $name, '_', $field->{name}, '_t.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* ', $name, '_', $field->{name}, '_clause(db_clause_list_t* clause_list, ', $name, '_', $field->{name}, '_t ', $field->{name}, ');

';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
        print HEADER '/**
 * Create a clause for ', $field->{name}, ' of a ', $tname, ' object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] ', $field->{name}, '_text a character pointer.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* ', $name, '_', $field->{name}, '_clause(db_clause_list_t* clause_list, const char* ', $field->{name}, '_text);

';
        next;
    }

    print HEADER '/**
 * Create a clause for ', $field->{name}, ' of a ', $tname, ' object and add it to a database clause list.
 * The clause operator is set to DB_CLAUSE_OPERATOR_AND and the clause type is
 * set to DB_CLAUSE_EQUAL, if you want to change these you can do it with the
 * returned db_clause_t pointer.
 * \param[in] clause_list db_clause_list_t pointer.
 * \param[in] ', $field->{name}, ' ', $DB_TYPE_TO_TEXT{$field->{type}}, '.
 * \return a db_clause_t pointer to the added clause or NULL on error.
 */
db_clause_t* ', $name, '_', $field->{name}, '_clause(db_clause_list_t* clause_list, ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ');

';
}

print HEADER '/**
 * Create a ', $tname, ' object in the database.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_create(', $name, '_t* ', $name, ');

';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
print HEADER '/**
 * Get a ', $tname, ' object from the database by a ', $field->{name}, ' specified in `', $field->{name}, '`.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] ', $field->{name}, ' a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_get_by_', $field->{name}, '(', $name, '_t* ', $name, ', const db_value_t* ', $field->{name}, ');

/**
 * Get a new ', $tname, ' object from the database by a ', $field->{name}, ' specified in `', $field->{name}, '`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] ', $field->{name}, ' a db_value_t pointer.
 * \return a ', $name, '_t pointer or NULL on error or if it does not exist.
 */
', $name, '_t* ', $name, '_new_get_by_', $field->{name}, '(const db_connection_t* connection, const db_value_t* ', $field->{name}, ');

';
        next;
    }
    if ($field->{unique}) {
        if ($field->{type} eq 'DB_TYPE_TEXT') {
print HEADER '/**
 * Get a ', $tname, ' object from the database by a ', $field->{name}, ' specified in `', $field->{name}, '`.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] ', $field->{name}, ' ', $DB_TYPE_TO_TEXT{$field->{type}}, '.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_get_by_', $field->{name}, '(', $name, '_t* ', $name, ', const ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ');

/**
 * Get a new ', $tname, ' object from the database by a ', $field->{name}, ' specified in `', $field->{name}, '`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] ', $field->{name}, ' ', $DB_TYPE_TO_TEXT{$field->{type}}, '.
 * \return a ', $name, '_t pointer or NULL on error or if it does not exist.
 */
', $name, '_t* ', $name, '_new_get_by_', $field->{name}, '(const db_connection_t* connection, const ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ');

';
        next;
        }
print HEADER '/**
 * Get a ', $tname, ' object from the database by a ', $field->{name}, ' specified in `', $field->{name}, '`.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] ', $field->{name}, ' ', $DB_TYPE_TO_TEXT{$field->{type}}, '.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_get_by_', $field->{name}, '(', $name, '_t* ', $name, ', ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ');

/**
 * Get a new ', $tname, ' object from the database by a ', $field->{name}, ' specified in `', $field->{name}, '`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] ', $field->{name}, ' ', $DB_TYPE_TO_TEXT{$field->{type}}, '.
 * \return a ', $name, '_t pointer or NULL on error or if it does not exist.
 */
', $name, '_t* ', $name, '_new_get_by_', $field->{name}, '(const db_connection_t* connection, ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ');

';
        next;
    }
}
print HEADER '/**
 * Update a ', $tname, ' object in the database.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_update(', $name, '_t* ', $name, ');

/**
 * Delete a ', $tname, ' object from the database.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_delete(', $name, '_t* ', $name, ');

/**
 * Count the number of ', $tname, ' objects in the database, if a selection of
 * objects should be counted then it can be limited by a database clause list
 * otherwise all objects are counted.
 * \param[in] ', $name, ' a ', $name, '_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer or NULL if all objects.
 * \param[out] count a size_t pointer to where the count should be stored.
 * should be counted.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_count(', $name, '_t* ', $name, ', db_clause_list_t* clause_list, size_t* count);

/**
 * A list of ', $tname, ' objects.
 */
struct ', $name, '_list {
    db_object_t* dbo;
    db_result_list_t* result_list;
    const db_result_t* result;
    ', $name, '_t* ', $name, ';
    int object_store;
    ', $name, '_t** object_list;
    size_t object_list_size;
    size_t object_list_position;
    int object_list_first;
    int associated_fetch;
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
        print HEADER '    ', $field->{foreign}, '_list_t* ', $field->{name}, '_list;
';
    }
}
print HEADER '};

/**
 * Create a new ', $tname, ' object list.
 * \param[in] connection a db_connection_t pointer.
 * \return a ', $name, '_list_t pointer or NULL on error.
 */
', $name, '_list_t* ', $name, '_list_new(const db_connection_t* connection);

/**
 * Create a new ', $tname, ' object list that is a copy of another.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \return a ', $name, '_list_t pointer or NULL on error.
 */
', $name, '_list_t* ', $name, '_list_new_copy(const ', $name, '_list_t* ', $name, '_copy);

/**
 * Specify that objects should be stored within the list as they are fetch,
 * this is optimal if the list is to be iterated over more then once.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_list_object_store(', $name, '_list_t* ', $name, '_list);

/**
 * Specify that the list should also fetch associated objects in a more optimal
 * way then fetching them for each individual object later on. This also forces
 * the list to store all objects (see ', $name, '_list_object_store()).
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_list_associated_fetch(', $name, '_list_t* ', $name, '_list);

/**
 * Delete a ', $tname, ' object list.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 */
void ', $name, '_list_free(', $name, '_list_t* ', $name, '_list);

/**
 * Copy the content of another ', $tname, ' object list.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \param[in] from_', $name, '_list a ', $name, '_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_list_copy(', $name, '_list_t* ', $name, '_list, const ', $name, '_list_t* from_', $name, '_list);

/**
 * Get all ', $tname, ' objects.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_list_get(', $name, '_list_t* ', $name, '_list);

/**
 * Get a new list with all ', $tname, ' objects.
 * \param[in] connection a db_connection_t pointer.
 * \return a ', $name, '_list_t pointer or NULL on error.
 */
', $name, '_list_t* ', $name, '_list_new_get(const db_connection_t* connection);

/**
 * Get ', $tname, ' objects from the database by a clause list.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_list_get_by_clauses(', $name, '_list_t* ', $name, '_list, const db_clause_list_t* clause_list);

/**
 * Get a new list of ', $tname, ' objects from the database by a clause list.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] clause_list a db_clause_list_t pointer.
 * \return a ', $name, '_list_t pointer or NULL on error.
 */
', $name, '_list_t* ', $name, '_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list);

';
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
print HEADER '/**
 * Get ', $tname, ' objects from the database by a ', $field->{name}, ' specified in `', $field->{name}, '`.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \param[in] ', $field->{name}, ' a db_value_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int ', $name, '_list_get_by_', $field->{name}, '(', $name, '_list_t* ', $name, '_list, const db_value_t* ', $field->{name}, ');

/**
 * Get a new list of ', $tname, ' objects from the database by a ', $field->{name}, ' specified in `', $field->{name}, '`.
 * \param[in] connection a db_connection_t pointer.
 * \param[in] ', $field->{name}, ' a db_value_t pointer.
 * \return a ', $name, '_list_t pointer or NULL on error.
 */
', $name, '_list_t* ', $name, '_list_new_get_by_', $field->{name}, '(const db_connection_t* connection, const db_value_t* ', $field->{name}, ');

';
    }
}
print HEADER '/**
 * Get the first ', $tname, ' object in a ', $tname, ' object list and reset the
 * position of the list.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \return a ', $name, '_t pointer or NULL on error or if there are no
 * ', $tname, ' objects in the ', $tname, ' object list.
 */
const ', $name, '_t* ', $name, '_list_begin(', $name, '_list_t* ', $name, '_list);

/**
 * Get the first ', $tname, ' object in a ', $tname, ' object list and reset the
 * position of the list. The caller will be given ownership of this object and
 * is responsible for freeing it.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \return a ', $name, '_t pointer or NULL on error or if there are no
 * ', $tname, ' objects in the ', $tname, ' object list.
 */
', $name, '_t* ', $name, '_list_get_begin(', $name, '_list_t* ', $name, '_list);

/**
 * Get the next ', $tname, ' object in a ', $tname, ' object list.
 * Ownership of this object is retained within the list and the object is only
 * valid until the next call to this function.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \return a ', $name, '_t pointer or NULL on error or if there are no more
 * ', $tname, ' objects in the ', $tname, ' object list.
 */
const ', $name, '_t* ', $name, '_list_next(', $name, '_list_t* ', $name, '_list);

/**
 * Get the next ', $tname, ' object in a ', $tname, ' object list.
 * The caller will be given ownership of this object and is responsible for
 * freeing it.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \return a ', $name, '_t pointer or NULL on error or if there are no more
 * ', $tname, ' objects in the ', $tname, ' object list.
 */
', $name, '_t* ', $name, '_list_get_next(', $name, '_list_t* ', $name, '_list);

/**
 * Get the size of a ', $tname, ' object list.
 * \param[in] ', $name, '_list a ', $name, '_list_t pointer.
 * \return a size_t with the size of the list or zero on error, if the list is
 * empty or if the backend does not support returning the size.
 */
size_t ', $name, '_list_size(', $name, '_list_t* ', $name, '_list);

#endif
';
close(HEADER);

if (!-f $name.'_ext.h') {
open(HEADER, '>:encoding(UTF-8)', $name.'_ext.h') or die;

    print HEADER '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __', $name, '_ext_h
#define __', $name, '_ext_h

#endif
';
close(HEADER);
}

################################################################################

open(SOURCE, '>:encoding(UTF-8)', $name.'.c') or die;

print SOURCE '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "', $name, '.h"
#include "db_error.h"


#include <string.h>

';

foreach my $field (@{$object->{fields}}) {
    if ($field->{type} ne 'DB_TYPE_ENUM') {
        next;
    }

print SOURCE
'const db_enum_t ', $name, '_enum_set_', $field->{name}, '[] = {
';
    foreach my $enum (@{$field->{enum}}) {
print SOURCE '    { "', $enum->{text}, '", (', $name, '_', $field->{name}, '_t)', uc($name.'_'.$field->{name}), '_', $enum->{name}, ' },
';
    }
print SOURCE '    { NULL, 0 }
};

';
}

print SOURCE '/**
 * Create a new ', $tname, ' object.
 * \param[in] connection a db_connection_t pointer.
 * \return a ', $name, '_t pointer or NULL on error.
 */
static db_object_t* __', $name, '_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    if (!(object = db_object_new())
        || db_object_set_connection(object, connection)
        || db_object_set_table(object, "', camelize($object->{name}), '")
        || db_object_set_primary_key_name(object, "id")
        || !(object_field_list = db_object_field_list_new()))
    {
        db_object_free(object);
        return NULL;
    }

';
foreach my $field (@{$object->{fields}}) {
print SOURCE '    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "', camelize($field->{name}), '")
        || db_object_field_set_type(object_field, ', $field->{type}, ')
';
if ($field->{type} eq 'DB_TYPE_ENUM') {
    print SOURCE '        || db_object_field_set_enum_set(object_field, ', $name, '_enum_set_', $field->{name}, ')
';
}
print SOURCE '        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

';
}
print SOURCE '    if (db_object_set_object_field_list(object, object_field_list)) {
        db_object_field_list_free(object_field_list);
        db_object_free(object);
        return NULL;
    }

    return object;
}

/* ', uc($tname), ' */



', $name, '_t* ', $name, '_new(const db_connection_t* connection) {
    ', $name, '_t* ', $name, ' =
        (', $name, '_t*)calloc(1, sizeof(', $name, '_t));

    if (', $name, ') {
        if (!(', $name, '->dbo = __', $name, '_new_object(connection))) {
            free(');
            return NULL;
        }
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{foreign} or $field->{type} eq 'DB_TYPE_REVISION') {
print SOURCE '        db_value_reset(&(', $name, '->', $field->{name}, '));
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        if ($field->{default}) {
print SOURCE '        ', $name, '->', $field->{name}, ' = ', uc($name.'_'.$field->{name}), '_', $field->{default}, ';
';
        }
        else {
print SOURCE '        ', $name, '->', $field->{name}, ' = ', uc($name.'_'.$field->{name}), '_INVALID;
';
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
        if (exists $field->{default}) {
print SOURCE '        ', $name, '->', $field->{name}, ' = strdup("', $field->{default}, '");
';
        }
        next;
    }

    if (exists $field->{default}) {
print SOURCE '        ', $name, '->', $field->{name}, ' = ', $field->{default}, ';
';
    }
}
print SOURCE '    }

    return ', $name, ';
}

', $name, '_t* ', $name, '_new_copy(const ', $name, '_t* ', $name, ') {
    ', $name, '_t* new_', $name, ';

    if (!', $name, ') {
        return NULL;
    }
    if (!', $name, '->dbo) {
        return NULL;
    }

    if (!(new_', $name, ' = ', $name, '_new(db_object_connection(', $name, '->dbo)))
        || ', $name, '_copy(new_', $name, ', ', $name, '))
    {
        ', $name, '_free(new_', $name, ');
        return NULL;
    }
    return new_', $name, ';
}

void ', $name, '_free(', $name, '_t* ', $name, ') {
    if (', $name, ') {
        if (', $name, '->dbo) {
            db_object_free(', $name, '->dbo);
        }
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{foreign} or $field->{type} eq 'DB_TYPE_REVISION') {
print SOURCE '        db_value_reset(&(', $name, '->', $field->{name}, '));
';
        if ($field->{foreign}) {
print SOURCE '        if (', $name, '->private_', $field->{name}, ') {
            ', $field->{foreign}, '_free(', $name, '->private_', $field->{name}, ');
        }
';
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '        if (', $name, '->', $field->{name}, ') {
            free(', $name, '->', $field->{name}, ');
        }
';
    }
}
foreach my $associated (@{$object->{association}}) {
print SOURCE '        if (', $name, '->', $associated->{foreign}, '_list) {
            ', $associated->{foreign}, '_list_free(', $name, '->', $associated->{foreign}, '_list);
        }
';
}
print SOURCE '        free(');
    }
}

void ', $name, '_reset(', $name, '_t* ', $name, ') {
    if (', $name, ') {
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{foreign} or $field->{type} eq 'DB_TYPE_REVISION') {
print SOURCE '        db_value_reset(&(', $name, '->', $field->{name}, '));
';
        if ($field->{foreign}) {
print SOURCE '        if (', $name, '->private_', $field->{name}, ') {
            ', $field->{foreign}, '_free(', $name, '->private_', $field->{name}, ');
            ', $name, '->private_', $field->{name}, ' = NULL;
        }
        ', $name, '->associated_', $field->{name}, ' = NULL;
';
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        if ($field->{default}) {
print SOURCE '        ', $name, '->', $field->{name}, ' = ', uc($name.'_'.$field->{name}), '_', $field->{default}, ';
';
        }
        else {
print SOURCE '        ', $name, '->', $field->{name}, ' = ', uc($name.'_'.$field->{name}), '_INVALID;
';
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '        if (', $name, '->', $field->{name}, ') {
            free(', $name, '->', $field->{name}, ');
';
        if (!exists $field->{default}) {
print SOURCE '            ', $name, '->', $field->{name}, ' = NULL;
';
        }
print SOURCE '        }
';
        if (exists $field->{default}) {
print SOURCE '        ', $name, '->', $field->{name}, ' = strdup("', $field->{default}, '");
';
        }
        next;
    }

    if (exists $field->{default}) {
print SOURCE '        ', $name, '->', $field->{name}, ' = ', $field->{default}, ';
';
    }
    else {
print SOURCE '        ', $name, '->', $field->{name}, ' = 0;
';
    }
}
foreach my $associated (@{$object->{association}}) {
print SOURCE '        if (', $name, '->', $associated->{foreign}, '_list) {
            ', $associated->{foreign}, '_list_free(', $name, '->', $associated->{foreign}, '_list);
            ', $name, '->', $associated->{foreign}, '_list = NULL;
        }
';
}
print SOURCE '    }
}

int ', $name, '_copy(', $name, '_t* ', $name, ', const ', $name, '_t* ', $name, '_copy) {
';
my $newline = 0;
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    char* ', $field->{name}, '_text = NULL;
';
        $newline = 1;
    }
}
if ($newline) {
    print SOURCE '
';
}
print SOURCE '    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '_copy) {
        return DB_ERROR_UNKNOWN;
    }

';
my @free = ();
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    if (', $name, '_copy->', $field->{name}, ') {
        if (!(', $field->{name}, '_text = strdup(', $name, '_copy->', $field->{name}, '))) {
';
foreach my $field2 (@free) {
    if ($field2->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '            if (', $field2->{name}, '_text) {
                free(', $field2->{name}, '_text);
            }
';
    }
}
print SOURCE '            return DB_ERROR_UNKNOWN;
        }
    }
';
        push(@free, $field);
    }
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{foreign} or $field->{type} eq 'DB_TYPE_REVISION') {
print SOURCE '    if (db_value_copy(&(', $name, '->', $field->{name}, '), &(', $name, '_copy->', $field->{name}, '))) {
';
foreach my $field2 (@free) {
    if ($field2->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '        if (', $field2->{name}, '_text) {
            free(', $field2->{name}, '_text);
        }
';
    }
}
print SOURCE '        return DB_ERROR_UNKNOWN;
    }
';
        if ($field->{foreign}) {
print SOURCE '    if (', $name, '->private_', $field->{name}, ') {
        ', $field->{foreign}, '_free(', $name, '->private_', $field->{name}, ');
        ', $name, '->private_', $field->{name}, ' = NULL;
    }
    if (', $name, '_copy->private_', $field->{name}, '
        && !(', $name, '->private_', $field->{name}, ' = ', $field->{foreign}, '_new_copy(', $name, '_copy->private_', $field->{name}, ')))
    {
';
foreach my $field2 (@free) {
    if ($field2->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '        if (', $field2->{name}, '_text) {
            free(', $field2->{name}, '_text);
        }
';
    }
}
print SOURCE '        return DB_ERROR_UNKNOWN;
    }
    ', $name, '->associated_', $field->{name}, ' = NULL;
    if (!', $name, '_copy->private_', $field->{name}, '
        && ', $name, '_copy->associated_', $field->{name}, '
        && !(', $name, '->private_', $field->{name}, ' = ', $field->{foreign}, '_new_copy(', $name, '_copy->associated_', $field->{name}, ')))
    {
';
foreach my $field2 (@free) {
    if ($field2->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '        if (', $field2->{name}, '_text) {
            free(', $field2->{name}, '_text);
        }
';
    }
}
print SOURCE '        return DB_ERROR_UNKNOWN;
    }
';
        }
        next;
    }
}
foreach my $associated (@{$object->{association}}) {
print SOURCE '    if (', $name, '->', $associated->{foreign}, '_list) {
        ', $associated->{foreign}, '_list_free(', $name, '->', $associated->{foreign}, '_list);
        ', $name, '->', $associated->{foreign}, '_list = NULL;
    }
    if (', $name, '_copy->', $associated->{foreign}, '_list
        && !(', $name, '->', $associated->{foreign}, '_list = ', $associated->{foreign}, '_list_new_copy(', $name, '_copy->', $associated->{foreign}, '_list)))
    {
';
foreach my $field2 (@free) {
    if ($field2->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '        if (', $field2->{name}, '_text) {
            free(', $field2->{name}, '_text);
        }
';
    }
}
print SOURCE '        return DB_ERROR_UNKNOWN;
    }
';
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{foreign} or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    if (', $name, '->', $field->{name}, ') {
        free(', $name, '->', $field->{name}, ');
    }
    ', $name, '->', $field->{name}, ' = ', $field->{name}, '_text;
';
        next;
    }
print SOURCE '    ', $name, '->', $field->{name}, ' = ', $name, '_copy->', $field->{name}, ';
';
}
print SOURCE '    return DB_OK;
}

int ', $name, '_cmp(const ', $name, '_t* ', $name, '_a, const ', $name, '_t* ', $name, '_b) {
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{foreign} or $field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    int ret;

';
        last;
    }
}
print SOURCE '    if (!', $name, '_a && !', $name, '_b) {
        return 0;
    }
    if (!', $name, '_a && ', $name, '_b) {
        return -1;
    }
    if (', $name, '_a && !', $name, '_b) {
        return 1;
    }
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{foreign}) {
print SOURCE '
    ret = 0;
    db_value_cmp(&(', $name, '_a->', $field->{name}, '), &(', $name, '_b->', $field->{name}, '), &ret);
    if (ret) {
        return ret;
    }
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '
    if (', $name, '_a->', $field->{name}, ' && ', $name, '_b->', $field->{name}, ') {
        if ((ret = strcmp(', $name, '_a->', $field->{name}, ', ', $name, '_b->', $field->{name}, '))) {
            return ret;
        }
    }
    else {
        if (!', $name, '_a->', $field->{name}, ' && ', $name, '_b->', $field->{name}, ') {
            return -1;
        }
        if (', $name, '_a->', $field->{name}, ' && !', $name, '_b->', $field->{name}, ') {
            return -1;
        }
    }
';
        next;
    }
print SOURCE '
    if (', $name, '_a->', $field->{name}, ' != ', $name, '_b->', $field->{name}, ') {
        return ', $name, '_a->', $field->{name}, ' < ', $name, '_b->', $field->{name}, ' ? -1 : 1;
    }
';
}
print SOURCE '    return 0;
}

int ', $name, '_from_result(', $name, '_t* ', $name, ', const db_result_t* result) {
    const db_value_set_t* value_set;
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_ENUM') {
print SOURCE '    int ', $field->{name}, ';
';
    }
}
print SOURCE '
    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }

';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{foreign} or $field->{type} eq 'DB_TYPE_REVISION') {
print SOURCE '    db_value_reset(&(', $name, '->', $field->{name}, '));
';
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    if (', $name, '->', $field->{name}, ') {
        free(', $name, '->', $field->{name}, ');
    }
    ', $name, '->', $field->{name}, ' = NULL;
';
    }
}
print SOURCE '    if (!(value_set = db_result_value_set(result))
        || db_value_set_size(value_set) != ', (scalar @{$object->{fields}});
my $count = 0;
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{foreign} or $field->{type} eq 'DB_TYPE_REVISION') {
print SOURCE '
        || db_value_copy(&(', $name, '->', $field->{name}, '), db_value_set_at(value_set, ', $count++, '))';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
print SOURCE '
        || db_value_to_enum_value(db_value_set_at(value_set, ', $count++, '), &', $field->{name}, ', ', $name, '_enum_set_', $field->{name}, ')';
        next;
    }
print SOURCE '
        || db_value_to_', $DB_TYPE_TO_FUNC{$field->{type}}, '(db_value_set_at(value_set, ', $count++, '), &(', $name, '->', $field->{name}, '))';
}
print SOURCE ')
    {
        return DB_ERROR_UNKNOWN;
    }

';

foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        my $first = 1;
        foreach my $enum (@{$field->{enum}}) {
print SOURCE '    ', ($first ? '' : 'else '),'if (', $field->{name}, ' == (', $name, '_', $field->{name}, '_t)', uc($name.'_'.$field->{name}), '_', $enum->{name}, ') {
        ', $name, '->', $field->{name}, ' = ', uc($name.'_'.$field->{name}), '_', $enum->{name}, ';
    }
';
            $first = 0;
        }
print SOURCE '    else {
        return DB_ERROR_UNKNOWN;
    }

';
    }
}

print SOURCE '    return DB_OK;
}

';

foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{foreign}) {
print SOURCE 'const db_value_t* ', $name, '_', $field->{name}, '(const ', $name, '_t* ', $name, ') {
    if (!', $name, ') {
        return NULL;
    }

    return &(', $name, '->', $field->{name}, ');
}

';
        if ($field->{foreign}) {
            my $func_name = $field->{name};
            $func_name =~ s/_id//o;
print SOURCE 'int ', $name, '_cache_', $func_name, '(', $name, '_t* ', $name, ') {
    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }

    if (', $name, '->associated_', $field->{name}, '
        || ', $name, '->private_', $field->{name}, ')
    {
        return DB_OK;
    }

    if (!(', $name, '->private_', $field->{name}, ' = ', $field->{foreign}, '_new(db_object_connection(', $name, '->dbo)))) {
        return DB_ERROR_UNKNOWN;
    }
    if (', $field->{foreign}, '_get_by_id(', $name, '->private_', $field->{name}, ', &(', $name, '->', $field->{name}, '))) {
        ', $field->{foreign}, '_free(', $name, '->private_', $field->{name}, ');
        ', $name, '->private_', $field->{name}, ' = NULL;
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

';
print SOURCE 'const ', $field->{foreign}, '_t* ', $name, '_', $func_name, '(const ', $name, '_t* ', $name, ') {
    if (!', $name, ') {
        return NULL;
    }

    if (', $name, '->private_', $field->{name}, ') {
        return ', $name, '->private_', $field->{name}, ';
    }
    return ', $name, '->associated_', $field->{name}, ';
}

';
print SOURCE $field->{foreign}, '_t* ', $name, '_get_', $func_name, '(const ', $name, '_t* ', $name, ') {
    ', $field->{foreign}, '_t* ', $field->{name}, ' = NULL;

    if (!', $name, ') {
        return NULL;
    }
    if (!', $name, '->dbo) {
        return NULL;
    }
    if (db_value_not_empty(&(', $name, '->', $field->{name}, '))) {
        return NULL;
    }

    if (!(', $field->{name}, ' = ', $field->{foreign}, '_new(db_object_connection(', $name, '->dbo)))) {
        return NULL;
    }
    if (', $name, '->private_', $field->{name}, ') {
        if (', $field->{foreign}, '_copy(', $field->{name}, ', ', $name, '->private_', $field->{name}, ')) {
            ', $field->{foreign}, '_free(', $field->{name}, ');
            return NULL;
        }
    }
    else if (', $name, '->associated_', $field->{name}, ') {
        if (', $field->{foreign}, '_copy(', $field->{name}, ', ', $name, '->associated_', $field->{name}, ')) {
            ', $field->{foreign}, '_free(', $field->{name}, ');
            return NULL;
        }
    }
    else {
        if (', $field->{foreign}, '_get_by_id(', $field->{name}, ', &(', $name, '->', $field->{name}, '))) {
            ', $field->{foreign}, '_free(', $field->{name}, ');
            return NULL;
        }
    }

    return ', $field->{name}, ';
}

';
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
print SOURCE $name, '_', $field->{name}, '_t ', $name, '_', $field->{name}, '(const ', $name, '_t* ', $name, ') {
    if (!', $name, ') {
        return ', uc($name.'_'.$field->{name}), '_INVALID;
    }

    return ', $name, '->', $field->{name}, ';
}

const char* ', $name, '_', $field->{name}, '_text(const ', $name, '_t* ', $name, ') {
    const db_enum_t* enum_set = ', $name, '_enum_set_', $field->{name}, ';

    if (!', $name, ') {
        return NULL;
    }

    while (enum_set->text) {
        if (enum_set->value == ', $name, '->', $field->{name}, ') {
            return enum_set->text;
        }
        enum_set++;
    }
    return NULL;
}

';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE 'const char* ', $name, '_', $field->{name}, '(const ', $name, '_t* ', $name, ') {
    if (!', $name, ') {
        return NULL;
    }

    return ', $name, '->', $field->{name}, ';
}

';
        next;
    }

print SOURCE $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $name, '_', $field->{name}, '(const ', $name, '_t* ', $name, ') {
    if (!', $name, ') {
        return 0;
    }

    return ', $name, '->', $field->{name}, ';
}

';
}

foreach my $associated (@{$object->{association}}) {
    print SOURCE $associated->{foreign}, '_list_t* ', $name, '_', $associated->{foreign}, '_list(', $name, '_t* ', $name, ') {

    if (!', $name, ') {
        return NULL;
    }
    if (!', $name, '->dbo) {
        return NULL;
    }

    if (!', $name, '->', $associated->{foreign}, '_list
        && ', $name, '_retrieve_', $associated->{foreign}, '_list(', $name, '))
    {
        return NULL;
    }

    return ', $name, '->', $associated->{foreign}, '_list;
}

int ', $name, '_retrieve_', $associated->{foreign}, '_list(', $name, '_t* ', $name, ') {
    db_clause_list_t* clause_list;

    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (', $name, '->', $associated->{foreign}, '_list) {
        ', $associated->{foreign}, '_list_free(', $name, '->', $associated->{foreign}, '_list);
        ', $name, '->', $associated->{foreign}, '_list = NULL;
    }

    if (!(clause_list = db_clause_list_new())
        || !', $associated->{foreign}, '_', $associated->{foreign_name}, '_clause(clause_list, ', $name, '_', $associated->{name}, '(', $name, '))
        || !(', $name, '->', $associated->{foreign}, '_list = ', $associated->{foreign}, '_list_new(db_object_connection(', $name, '->dbo)))
        || ', $associated->{foreign}, '_list_object_store(', $name, '->', $associated->{foreign}, '_list)
        || ', $associated->{foreign}, '_list_get_by_clauses(', $name, '->', $associated->{foreign}, '_list, clause_list))
    {
        ', $associated->{foreign}, '_list_free(', $name, '->', $associated->{foreign}, '_list);
        ', $name, '->', $associated->{foreign}, '_list = NULL;
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    db_clause_list_free(clause_list);

    return DB_OK;
}

';
}

foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
print SOURCE 'int ', $name, '_set_', $field->{name}, '(', $name, '_t* ', $name, ', ', $name, '_', $field->{name}, '_t ', $field->{name}, ') {
    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (', $field->{name}, ' == ', uc($name.'_'.$field->{name}), '_INVALID) {
        return DB_ERROR_UNKNOWN;
    }

    ', $name, '->', $field->{name}, ' = ', $field->{name}, ';

    return DB_OK;
}

int ', $name, '_set_', $field->{name}, '_text(', $name, '_t* ', $name, ', const char* ', $field->{name}, ') {
    const db_enum_t* enum_set = ', $name, '_enum_set_', $field->{name}, ';

    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }

    while (enum_set->text) {
        if (!strcmp(enum_set->text, ', $field->{name}, ')) {
            ', $name, '->', $field->{name}, ' = enum_set->value;
            return DB_OK;
        }
        enum_set++;
    }
    return DB_ERROR_UNKNOWN;
}

';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE 'int ', $name, '_set_', $field->{name}, '(', $name, '_t* ', $name, ', const char* ', $field->{name}, '_text) {
    char* new_', $field->{name}, ';

    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $field->{name}, '_text) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_', $field->{name}, ' = strdup(', $field->{name}, '_text))) {
        return DB_ERROR_UNKNOWN;
    }

    if (', $name, '->', $field->{name}, ') {
        free(', $name, '->', $field->{name}, ');
    }
    ', $name, '->', $field->{name}, ' = new_', $field->{name}, ';

    return DB_OK;
}

';
        next;
    }

    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
        next;
    }
    if ($field->{foreign}) {
print SOURCE 'int ', $name, '_set_', $field->{name}, '(', $name, '_t* ', $name, ', const db_value_t* ', $field->{name}, ') {
    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $field->{name}, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(', $field->{name}, ')) {
        return DB_ERROR_UNKNOWN;
    }

    db_value_reset(&(', $name, '->', $field->{name}, '));
    if (db_value_copy(&(', $name, '->', $field->{name}, '), ', $field->{name}, ')) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

';
        next;
    }
print SOURCE 'int ', $name, '_set_', $field->{name}, '(', $name, '_t* ', $name, ', ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ') {
    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
';
if ($field->{min}) {
print SOURCE '
    if (', $field->{name}, ' < ', $field->{min}, ') {
        return DB_ERROR_UNKNOWN;
    }
';
}
if ($field->{max}) {
print SOURCE '
    if (', $field->{name}, ' > ', $field->{max}, ') {
        return DB_ERROR_UNKNOWN;
    }
';
}
print SOURCE '
    ', $name, '->', $field->{name}, ' = ', $field->{name}, ';

    return DB_OK;
}

';
}

foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
        next;
    }
    if ($field->{foreign}) {
    print SOURCE 'db_clause_t* ', $name, '_', $field->{name}, '_clause(db_clause_list_t* clause_list, const db_value_t* ', $field->{name}, ') {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!', $field->{name}, ') {
        return NULL;
    }
    if (db_value_not_empty(', $field->{name}, ')) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "', camelize($field->{name}), '")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_copy(db_clause_get_value(clause), ', $field->{name}, ')
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        print SOURCE 'db_clause_t* ', $name, '_', $field->{name}, '_clause(db_clause_list_t* clause_list, ', $name, '_', $field->{name}, '_t ', $field->{name}, ') {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "', camelize($field->{name}), '")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_enum_value(db_clause_get_value(clause), ', $field->{name}, ', ', $name, '_enum_set_', $field->{name}, ')
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
        print SOURCE 'db_clause_t* ', $name, '_', $field->{name}, '_clause(db_clause_list_t* clause_list, const char* ', $field->{name}, '_text) {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }
    if (!', $field->{name}, '_text) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "', camelize($field->{name}), '")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_text(db_clause_get_value(clause), ', $field->{name}, '_text)
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

';
        next;
    }

    print SOURCE 'db_clause_t* ', $name, '_', $field->{name}, '_clause(db_clause_list_t* clause_list, ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ') {
    db_clause_t* clause;

    if (!clause_list) {
        return NULL;
    }

    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "', camelize($field->{name}), '")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_AND)
        || db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(db_clause_get_value(clause), ', $field->{name}, ')
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        return NULL;
    }

    return clause;
}

';
}

print SOURCE 'int ', $name, '_create(', $name, '_t* ', $name, ') {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    int ret;

    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '->dbo) {
        return DB_ERROR_UNKNOWN;
    }
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
print SOURCE '    if (!db_value_not_empty(&(', $name, '->', $field->{name}, '))) {
        return DB_ERROR_UNKNOWN;
    }
';
        next;
    }
    if ($field->{foreign}) {
print SOURCE '    if (db_value_not_empty(&(', $name, '->', $field->{name}, '))) {
        return DB_ERROR_UNKNOWN;
    }
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    if (!', $name, '->', $field->{name}, ') {
        return DB_ERROR_UNKNOWN;
    }
';
        next;
    }
}
print SOURCE '    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

';
my $fields = 0;
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
print SOURCE '    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "', camelize($field->{name}), '")
        || db_object_field_set_type(object_field, ', $field->{type}, ')
';
if ($field->{type} eq 'DB_TYPE_ENUM') {
    print SOURCE '        || db_object_field_set_enum_set(object_field, ', $name, '_enum_set_', $field->{name}, ')
';
}
print SOURCE '        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

';
    $fields++;
}
if (!$fields) {
    $fields = 1;
}
print SOURCE '    if (!(value_set = db_value_set_new(', $fields, '))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

';
if ($fields) {
print SOURCE '    if (';
my $count = 0;
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($count) {
        print SOURCE '
        || ';
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
print SOURCE 'db_value_from_enum_value(db_value_set_get(value_set, ', $count++, '), ', $name, '->', $field->{name}, ', ', $name, '_enum_set_', $field->{name}, ')';
        next;
    }
    if ($field->{foreign}) {
print SOURCE 'db_value_copy(db_value_set_get(value_set, ', $count++, '), &(', $name, '->', $field->{name}, '))';
        next;
    }
print SOURCE 'db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(db_value_set_get(value_set, ', $count++, '), ', $name, '->', $field->{name}, ')';
}
print SOURCE ')
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

';
}
print SOURCE '    ret = db_object_create(', $name, '->dbo, object_field_list, value_set);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    return ret;
}

';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
print SOURCE 'int ', $name, '_get_by_', $field->{name}, '(', $name, '_t* ', $name, ', const db_value_t* ', $field->{name}, ') {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $field->{name}, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(', $field->{name}, ')) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "', camelize($field->{name}), '")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), ', $field->{name}, ')
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    result_list = db_object_read(', $name, '->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            if (', $name, '_from_result(', $name, ', result)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

', $name, '_t* ', $name, '_new_get_by_', $field->{name}, '(const db_connection_t* connection, const db_value_t* ', $field->{name}, ') {
    ', $name, '_t* ', $name, ';

    if (!connection) {
        return NULL;
    }
    if (!', $field->{name}, ') {
        return NULL;
    }
    if (db_value_not_empty(', $field->{name}, ')) {
        return NULL;
    }

    if (!(', $name, ' = ', $name, '_new(connection))
        || ', $name, '_get_by_', $field->{name}, '(', $name, ', ', $field->{name}, '))
    {
        ', $name, '_free(', $name, ');
        return NULL;
    }

    return ', $name, ';
}

';
        next;
    }
    if ($field->{unique}) {
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE 'int ', $name, '_get_by_', $field->{name}, '(', $name, '_t* ', $name, ', const char* ', $field->{name}, ') {
';
    }
    else {
print SOURCE 'int ', $name, '_get_by_', $field->{name}, '(', $name, '_t* ', $name, ', ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ') {
';
    }
print SOURCE '    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;

    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '->dbo) {
        return DB_ERROR_UNKNOWN;
    }
';
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    if (!', $field->{name}, ') {
        return DB_ERROR_UNKNOWN;
    }
';
    }
print SOURCE '
    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "', camelize($field->{name}), '")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(db_clause_get_value(clause), ', $field->{name}, ')
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    result_list = db_object_read(', $name, '->dbo, NULL, clause_list);
    db_clause_list_free(clause_list);

    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            if (', $name, '_from_result(', $name, ', result)) {
                db_result_list_free(result_list);
                return DB_ERROR_UNKNOWN;
            }

            db_result_list_free(result_list);
            return DB_OK;
        }
    }

    db_result_list_free(result_list);
    return DB_ERROR_UNKNOWN;
}

';
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE $name, '_t* ', $name, '_new_get_by_', $field->{name}, '(const db_connection_t* connection, const char* ', $field->{name}, ') {
';
    }
    else {
print SOURCE $name, '_t* ', $name, '_new_get_by_', $field->{name}, '(const db_connection_t* connection, ', $DB_TYPE_TO_C_TYPE{$field->{type}}, ' ', $field->{name}, ') {
';
    }
print SOURCE '    ', $name, '_t* ', $name, ';

    if (!connection) {
        return NULL;
    }
';
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    if (!', $field->{name}, ') {
        return NULL;
    }
';
    }
print SOURCE '
    if (!(', $name, ' = ', $name, '_new(connection))
        || ', $name, '_get_by_', $field->{name}, '(', $name, ', ', $field->{name}, '))
    {
        ', $name, '_free(', $name, ');
        return NULL;
    }

    return ', $name, ';
}

';
    }
}
print SOURCE 'int ', $name, '_update(', $name, '_t* ', $name, ') {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '->dbo) {
        return DB_ERROR_UNKNOWN;
    }
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{foreign} or $field->{type} eq 'DB_TYPE_REVISION') {
print SOURCE '    if (db_value_not_empty(&(', $name, '->', $field->{name}, '))) {
        return DB_ERROR_UNKNOWN;
    }
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    if (!', $name, '->', $field->{name}, ') {
        return DB_ERROR_UNKNOWN;
    }
';
        next;
    }
}
print SOURCE '    /* TODO: validate content more */

    if (!(object_field_list = db_object_field_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

';
my $fields = 0;
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
print SOURCE '    if (!(object_field = db_object_field_new())
        || db_object_field_set_name(object_field, "', camelize($field->{name}), '")
        || db_object_field_set_type(object_field, ', $field->{type}, ')
';
if ($field->{type} eq 'DB_TYPE_ENUM') {
    print SOURCE '        || db_object_field_set_enum_set(object_field, ', $name, '_enum_set_', $field->{name}, ')
';
}
print SOURCE '        || db_object_field_list_add(object_field_list, object_field))
    {
        db_object_field_free(object_field);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

';
    $fields++;
}
if (!$fields) {
    $fields = 1;
}
print SOURCE '    if (!(value_set = db_value_set_new(', $fields, '))) {
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

';
if ($fields) {
print SOURCE '    if (';
my $count = 0;
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($count) {
        print SOURCE '
        || ';
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
print SOURCE 'db_value_from_enum_value(db_value_set_get(value_set, ', $count++, '), ', $name, '->', $field->{name}, ', ', $name, '_enum_set_', $field->{name}, ')';
        next;
    }
    if ($field->{foreign}) {
print SOURCE 'db_value_copy(db_value_set_get(value_set, ', $count++, '), &(', $name, '->', $field->{name}, '))';
        next;
    }
print SOURCE 'db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(db_value_set_get(value_set, ', $count++, '), ', $name, '->', $field->{name}, ')';
}
print SOURCE ')
    {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

';
}
print SOURCE '    if (!(clause_list = db_clause_list_new())) {
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
print SOURCE '    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "', camelize($field->{name}), '")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(', $name, '->', $field->{name}, '))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        db_value_set_free(value_set);
        db_object_field_list_free(object_field_list);
        return DB_ERROR_UNKNOWN;
    }

';
    }
}
print SOURCE '    ret = db_object_update(', $name, '->dbo, object_field_list, value_set, clause_list);
    db_value_set_free(value_set);
    db_object_field_list_free(object_field_list);
    db_clause_list_free(clause_list);
    return ret;
}

int ', $name, '_delete(', $name, '_t* ', $name, ') {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret;

    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '->dbo) {
        return DB_ERROR_UNKNOWN;
    }
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
print SOURCE '    if (db_value_not_empty(&(', $name, '->', $field->{name}, '))) {
        return DB_ERROR_UNKNOWN;
    }
';
    }
}
print SOURCE '
    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }

';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
print SOURCE '    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "', camelize($field->{name}), '")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), &(', $name, '->', $field->{name}, '))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

';
    }
}
print SOURCE '    ret = db_object_delete(', $name, '->dbo, clause_list);
    db_clause_list_free(clause_list);
    return ret;
}

int ', $name, '_count(', $name, '_t* ', $name, ', db_clause_list_t* clause_list, size_t* count) {
    if (!', $name, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!count) {
        return DB_ERROR_UNKNOWN;
    }

    return db_object_count(', $name, '->dbo, NULL, clause_list, count);
}

/* ', uc($tname), ' LIST */



', $name, '_list_t* ', $name, '_list_new(const db_connection_t* connection) {
    ', $name, '_list_t* ', $name, '_list =
        (', $name, '_list_t*)calloc(1, sizeof(', $name, '_list_t));

    if (', $name, '_list) {
        if (!(', $name, '_list->dbo = __', $name, '_new_object(connection))) {
            free('_list);
            return NULL;
        }
    }

    return ', $name, '_list;
}

', $name, '_list_t* ', $name, '_list_new_copy(const ', $name, '_list_t* from_', $name, '_list) {
    ', $name, '_list_t* ', $name, '_list;

    if (!from_', $name, '_list) {
        return NULL;
    }
    if (!from_', $name, '_list->dbo) {
        return NULL;
    }

    if (!(', $name, '_list = ', $name, '_list_new(db_object_connection(from_', $name, '_list->dbo)))
        || ', $name, '_list_copy(', $name, '_list, from_', $name, '_list))
    {
        ', $name, '_list_free(', $name, '_list);
        return NULL;
    }
    return ', $name, '_list;
}

int ', $name, '_list_object_store(', $name, '_list_t* ', $name, '_list) {
    if (!', $name, '_list) {
        return DB_ERROR_UNKNOWN;
    }

    ', $name, '_list->object_store = 1;

    return DB_OK;
}

int ', $name, '_list_associated_fetch(', $name, '_list_t* ', $name, '_list) {
    if (!', $name, '_list) {
        return DB_ERROR_UNKNOWN;
    }

    ', $name, '_list->object_store = 1;
    ', $name, '_list->associated_fetch = 1;

    return DB_OK;
}

void ', $name, '_list_free(', $name, '_list_t* ', $name, '_list) {
    size_t i;

    if (', $name, '_list) {
        if (', $name, '_list->dbo) {
            db_object_free(', $name, '_list->dbo);
        }
        if (', $name, '_list->result_list) {
            db_result_list_free(', $name, '_list->result_list);
        }
        if (', $name, '_list->', $name, ') {
            ', $name, '_free(', $name, '_list->', $name, ');
        }
        for (i = 0; i < ', $name, '_list->object_list_size; i++) {
            if (', $name, '_list->object_list[i]) {
                ', $name, '_free(', $name, '_list->object_list[i]);
            }
        }
        if (', $name, '_list->object_list) {
            free(', $name, '_list->object_list);
        }
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
print SOURCE '        if (', $name, '_list->', $field->{name}, '_list) {
            ', $field->{foreign}, '_list_free(', $name, '_list->', $field->{name}, '_list);
        }
';
    }
}
print SOURCE '        free('_list);
    }
}

int ', $name, '_list_copy(', $name, '_list_t* ', $name, '_list, const ', $name, '_list_t* from_', $name, '_list) {
    size_t i;

    if (!', $name, '_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!from_', $name, '_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (from_', $name, '_list->object_list && !from_', $name, '_list->object_list_size) {
        return DB_ERROR_UNKNOWN;
    }

    if (', $name, '_list->result_list) {
        db_result_list_free(', $name, '_list->result_list);
        ', $name, '_list->result_list = NULL;
    }
    if (from_', $name, '_list->result_list
        && !(', $name, '_list->result_list = db_result_list_new_copy(from_', $name, '_list->result_list)))
    {
        return DB_ERROR_UNKNOWN;
    }

    ', $name, '_list->object_store = from_', $name, '_list->object_store;
    for (i = 0; i < ', $name, '_list->object_list_size; i++) {
        if (', $name, '_list->object_list[i]) {
            ', $name, '_free(', $name, '_list->object_list[i]);
        }
    }
    ', $name, '_list->object_list_size = 0;
    if (', $name, '_list->object_list) {
        free(', $name, '_list->object_list);
        ', $name, '_list->object_list = NULL;
    }
    if (from_', $name, '_list->object_list) {
        if (!(', $name, '_list->object_list = (', $name, '_t**)calloc(from_', $name, '_list->object_list_size, sizeof(', $name, '_t*)))) {
            return DB_ERROR_UNKNOWN;
        }
        ', $name, '_list->object_list_size = from_', $name, '_list->object_list_size;
        for (i = 0; i < from_', $name, '_list->object_list_size; i++) {
            if (!from_', $name, '_list->object_list[i]) {
                continue;
            }
            if (!(', $name, '_list->object_list[i] = ', $name, '_new_copy(from_', $name, '_list->object_list[i]))) {
                return DB_ERROR_UNKNOWN;
            }
        }
    }
    ', $name, '_list->object_list_position = 0;;
    ', $name, '_list->object_list_first = 1;
    ', $name, '_list->associated_fetch = from_', $name, '_list->associated_fetch;

';
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
        print SOURCE '    if (from_', $name, '_list->', $field->{name}, '_list
        && !(', $name, '_list->', $field->{name}, '_list = ', $field->{foreign}, '_list_new_copy(from_', $name, '_list->', $field->{name}, '_list)))
    {
        return DB_ERROR_UNKNOWN;
    }

';
    }
}
print SOURCE '    return DB_OK;
}

';
my $has_associated = 0;
my $has_associated2 = 0;
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
        $has_associated = 1;
    }
}
if (scalar @{$object->{association}}) {
    $has_associated2 = 1;
}
print SOURCE 'static int ', $name, '_list_get_associated(', $name, '_list_t* ', $name, '_list) {
';
if (!$has_associated && !$has_associated2) {
    print SOURCE '    (void)', $name, '_list;
';
}
if ($has_associated) {
print SOURCE '    const db_clause_t* clause_walk;
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
print SOURCE '    const ', $field->{foreign}, '_t* ', $field->{foreign}, '_', $field->{name}, ';
';
    }
}
}
if ($has_associated2) {
print SOURCE '    size_t j, count;
';
}
if ($has_associated || $has_associated2) {
print SOURCE '    int cmp;
    size_t i;
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    const ', $name, '_t* ', $name, ';
';
foreach my $associated (@{$object->{association}}) {
print SOURCE '    ', $associated->{foreign}, '_list_t* ', $associated->{foreign}, '_list;
    const ', $associated->{foreign}, '_t* ', $associated->{foreign}, ';
';
}
print SOURCE '
    if (!', $name, '_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '_list->associated_fetch) {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '_list->result_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (', $name, '_list->object_list) {
        return DB_ERROR_UNKNOWN;
    }
';
if ($has_associated) {
    print SOURCE '
';
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
print SOURCE '    if (', $name, '_list->', $field->{name}, '_list) {
        ', $field->{foreign}, '_list_free(', $name, '_list->', $field->{name}, '_list);
        ', $name, '_list->', $field->{name}, '_list = NULL;
    }
';
    }
}
if (!$has_associated && $has_associated2) {
print SOURCE '
    ', $name, ' = ', $name, '_list_begin(', $name, '_list);
    while (', $name, ') {
        ', $name, ' = ', $name, '_list_next(', $name, '_list);
    }
';
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
print SOURCE '
    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    ', $name, ' = ', $name, '_list_begin(', $name, '_list);
    while (', $name, ') {
        cmp = 1;
        clause_walk = db_clause_list_begin(clause_list);
        while (clause_walk) {
            if (db_value_cmp(db_clause_value(clause_walk), ', $name, '_', $field->{name}, '(', $name, '), &cmp)) {
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
            if (!cmp) {
                break;
            }
            clause_walk = db_clause_next(clause_walk);
        }
        if (cmp) {
            if (!(clause = db_clause_new())
                || db_clause_set_field(clause, "', camelize($field->{foreign_name}), '")
                || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
                || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_OR)
                || db_value_copy(db_clause_get_value(clause), ', $name, '_', $field->{name}, '(', $name, '))
                || db_clause_list_add(clause_list, clause))
            {
                db_clause_free(clause);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
        }

        ', $name, ' = ', $name, '_list_next(', $name, '_list);
    }

    if (!(', $name, '_list->', $field->{name}, '_list = ', $field->{foreign}, '_list_new(db_object_connection(', $name, '_list->dbo)))
        || ', $field->{foreign}, '_list_object_store(', $name, '_list->', $field->{name}, '_list)
        || ', $field->{foreign}, '_list_get_by_clauses(', $name, '_list->', $field->{name}, '_list, clause_list))
    {
        if (', $name, '_list->', $field->{name}, '_list) {
            ', $field->{foreign}, '_list_free(', $name, '_list->', $field->{name}, '_list);
            ', $name, '_list->', $field->{name}, '_list = NULL;
        }
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    db_clause_list_free(clause_list);

    for (i = 0; i < ', $name, '_list->object_list_size; i++) {
        if (!(', $name, '_list->object_list[i])) {
            return DB_ERROR_UNKNOWN;
        }

        ', $field->{foreign}, '_', $field->{name}, ' = ', $field->{foreign}, '_list_begin(', $name, '_list->', $field->{name}, '_list);
        while (', $field->{foreign}, '_', $field->{name}, ') {
            if (db_value_cmp(', $name, '_', $field->{name}, '(', $name, '_list->object_list[i]), ', $field->{foreign}, '_', $field->{foreign_name}, '(', $field->{foreign}, '_', $field->{name}, '), &cmp)) {
                return DB_ERROR_UNKNOWN;
            }
            if (!cmp) {
                ', $name, '_list->object_list[i]->associated_', $field->{name}, ' = ', $field->{foreign}, '_', $field->{name}, ';
            }

            ', $field->{foreign}, '_', $field->{name}, ' = ', $field->{foreign}, '_list_next(', $name, '_list->', $field->{name}, '_list);
        }
    }
';
    }
}
my $prev_associated;
foreach my $associated (sort {$a->{foreign_name} cmp $b->{foreign_name}} @{$object->{association}}) {
    if (!$prev_associated || $prev_associated->{foreign_name} ne $associated->{foreign_name}) {
if ($prev_associated) {
print SOURCE '
    db_clause_list_free(clause_list);
';
}
print SOURCE '
    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    ', $name, ' = ', $name, '_list_begin(', $name, '_list);
    while (', $name, ') {
        if (!(clause = db_clause_new())
            || db_clause_set_field(clause, "', camelize($associated->{foreign_name}), '")
            || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
            || db_clause_set_operator(clause, DB_CLAUSE_OPERATOR_OR)
            || db_value_copy(db_clause_get_value(clause), ', $name, '_', $associated->{name}, '(', $name, '))
            || db_clause_list_add(clause_list, clause))
        {
            db_clause_free(clause);
            db_clause_list_free(clause_list);
            return DB_ERROR_UNKNOWN;
        }

        ', $name, ' = ', $name, '_list_next(', $name, '_list);
    }
';
    }
print SOURCE '
    if (!(', $associated->{foreign}, '_list = ', $associated->{foreign}, '_list_new(db_object_connection(', $name, '_list->dbo)))
        || ', $associated->{foreign}, '_list_object_store(', $associated->{foreign}, '_list)
        || ', $associated->{foreign}, '_list_get_by_clauses(', $associated->{foreign}, '_list, clause_list))
    {
        ', $associated->{foreign}, '_list_free(', $associated->{foreign}, '_list);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    for (i = 0; i < ', $name, '_list->object_list_size; i++) {
        if (!(', $name, '_list->object_list[i])) {
            return DB_ERROR_UNKNOWN;
        }

        count = 0;
        ', $associated->{foreign}, ' = ', $associated->{foreign}, '_list_begin(', $associated->{foreign}, '_list);
        while (', $associated->{foreign}, ') {
            if (db_value_cmp(', $name, '_', $associated->{name}, '(', $name, '_list->object_list[i]), ', $associated->{foreign}, '_', $associated->{foreign_name}, '(', $associated->{foreign}, '), &cmp)) {
                ', $associated->{foreign}, '_list_free(', $associated->{foreign}, '_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
            if (!cmp) {
                count++;
            }
            ', $associated->{foreign}, ' = ', $associated->{foreign}, '_list_next(', $associated->{foreign}, '_list);
        }
        if (', $name, '_list->object_list[i]->', $associated->{foreign}, '_list) {
            ', $associated->{foreign}, '_list_free(', $name, '_list->object_list[i]->', $associated->{foreign}, '_list);
            ', $name, '_list->object_list[i]->', $associated->{foreign}, '_list = NULL;
        }
        if (!(', $name, '_list->object_list[i]->', $associated->{foreign}, '_list = ', $associated->{foreign}, '_list_new(db_object_connection(', $name, '_list->dbo)))) {
            ', $associated->{foreign}, '_list_free(', $associated->{foreign}, '_list);
            db_clause_list_free(clause_list);
            return DB_ERROR_UNKNOWN;
        }
        if (count) {
            if (!(', $name, '_list->object_list[i]->', $associated->{foreign}, '_list->object_list = (', $associated->{foreign}, '_t**)calloc(count, sizeof(', $associated->{foreign}, '_t*)))) {
                ', $associated->{foreign}, '_list_free(', $associated->{foreign}, '_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }

            j = 0;
            ', $associated->{foreign}, ' = ', $associated->{foreign}, '_list_begin(', $associated->{foreign}, '_list);
            while (', $associated->{foreign}, ') {
                if (j >= count) {
                    ', $associated->{foreign}, '_list_free(', $associated->{foreign}, '_list);
                    db_clause_list_free(clause_list);
                    return DB_ERROR_UNKNOWN;
                }
                if (db_value_cmp(', $name, '_', $associated->{name}, '(', $name, '_list->object_list[i]), ', $associated->{foreign}, '_', $associated->{foreign_name}, '(', $associated->{foreign}, '), &cmp)) {
                    ', $associated->{foreign}, '_list_free(', $associated->{foreign}, '_list);
                    db_clause_list_free(clause_list);
                    return DB_ERROR_UNKNOWN;
                }
                if (!cmp) {
                    if (!(', $name, '_list->object_list[i]->', $associated->{foreign}, '_list->object_list[j] = ', $associated->{foreign}, '_new_copy(', $associated->{foreign}, '))) {
                        ', $associated->{foreign}, '_list_free(', $associated->{foreign}, '_list);
                        db_clause_list_free(clause_list);
                        return DB_ERROR_UNKNOWN;
                    }
                    j++;
                }
                ', $associated->{foreign}, ' = ', $associated->{foreign}, '_list_next(', $associated->{foreign}, '_list);
            }
            if (j != count) {
                ', $associated->{foreign}, '_list_free(', $associated->{foreign}, '_list);
                db_clause_list_free(clause_list);
                return DB_ERROR_UNKNOWN;
            }
        }
        ', $name, '_list->object_list[i]->', $associated->{foreign}, '_list->object_store = 1;
        ', $name, '_list->object_list[i]->', $associated->{foreign}, '_list->object_list_size = count;
        ', $name, '_list->object_list[i]->', $associated->{foreign}, '_list->object_list_first = 1;
    }
';
    $prev_associated = $associated;
}
if ($prev_associated) {
print SOURCE '    db_clause_list_free(clause_list);
';
}
print SOURCE '
    ', $name, '_list->object_list_first = 1;
';
}
print SOURCE '    return DB_OK;
}

int ', $name, '_list_get(', $name, '_list_t* ', $name, '_list) {
    size_t i;

    if (!', $name, '_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (', $name, '_list->result_list) {
        db_result_list_free(', $name, '_list->result_list);
    }
    if (', $name, '_list->object_list_size) {
        for (i = 0; i < ', $name, '_list->object_list_size; i++) {
            if (', $name, '_list->object_list[i]) {
                ', $name, '_free(', $name, '_list->object_list[i]);
            }
        }
        ', $name, '_list->object_list_size = 0;
        ', $name, '_list->object_list_first = 0;
    }
    if (', $name, '_list->object_list) {
        free(', $name, '_list->object_list);
        ', $name, '_list->object_list = NULL;
    }
    if (!(', $name, '_list->result_list = db_object_read(', $name, '_list->dbo, NULL, NULL))
        || db_result_list_fetch_all(', $name, '_list->result_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    if (', $name, '_list->associated_fetch
        && ', $name, '_list_get_associated(', $name, '_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

', $name, '_list_t* ', $name, '_list_new_get(const db_connection_t* connection) {
    ', $name, '_list_t* ', $name, '_list;

    if (!connection) {
        return NULL;
    }

    if (!(', $name, '_list = ', $name, '_list_new(connection))
        || ', $name, '_list_get(', $name, '_list))
    {
        ', $name, '_list_free(', $name, '_list);
        return NULL;
    }

    return ', $name, '_list;
}

int ', $name, '_list_get_by_clauses(', $name, '_list_t* ', $name, '_list, const db_clause_list_t* clause_list) {
    size_t i;

    if (!', $name, '_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!clause_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }

    if (', $name, '_list->result_list) {
        db_result_list_free(', $name, '_list->result_list);
    }
    if (', $name, '_list->object_list_size) {
        for (i = 0; i < ', $name, '_list->object_list_size; i++) {
            if (', $name, '_list->object_list[i]) {
                ', $name, '_free(', $name, '_list->object_list[i]);
            }
        }
        ', $name, '_list->object_list_size = 0;
        ', $name, '_list->object_list_first = 0;
    }
    if (', $name, '_list->object_list) {
        free(', $name, '_list->object_list);
        ', $name, '_list->object_list = NULL;
    }
    if (!(', $name, '_list->result_list = db_object_read(', $name, '_list->dbo, NULL, clause_list))
        || db_result_list_fetch_all(', $name, '_list->result_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    if (', $name, '_list->associated_fetch
        && ', $name, '_list_get_associated(', $name, '_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

', $name, '_list_t* ', $name, '_list_new_get_by_clauses(const db_connection_t* connection, const db_clause_list_t* clause_list) {
    ', $name, '_list_t* ', $name, '_list;

    if (!connection) {
        return NULL;
    }
    if (!clause_list) {
        return NULL;
    }

    if (!(', $name, '_list = ', $name, '_list_new(connection))
        || ', $name, '_list_get_by_clauses(', $name, '_list, clause_list))
    {
        ', $name, '_list_free(', $name, '_list);
        return NULL;
    }

    return ', $name, '_list;
}

';
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
print SOURCE 'int ', $name, '_list_get_by_', $field->{name}, '(', $name, '_list_t* ', $name, '_list, const db_value_t* ', $field->{name}, ') {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    size_t i;

    if (!', $name, '_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $name, '_list->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!', $field->{name}, ') {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(', $field->{name}, ')) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "', camelize($field->{name}), '")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), ', $field->{name}, ')
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (', $name, '_list->result_list) {
        db_result_list_free(', $name, '_list->result_list);
    }
    if (', $name, '_list->object_list_size) {
        for (i = 0; i < ', $name, '_list->object_list_size; i++) {
            if (', $name, '_list->object_list[i]) {
                ', $name, '_free(', $name, '_list->object_list[i]);
            }
        }
        ', $name, '_list->object_list_size = 0;
        ', $name, '_list->object_list_first = 0;
    }
    if (', $name, '_list->object_list) {
        free(', $name, '_list->object_list);
        ', $name, '_list->object_list = NULL;
    }
    if (!(', $name, '_list->result_list = db_object_read(', $name, '_list->dbo, NULL, clause_list))
        || db_result_list_fetch_all(', $name, '_list->result_list))
    {
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }
    db_clause_list_free(clause_list);
    if (', $name, '_list->associated_fetch
        && ', $name, '_list_get_associated(', $name, '_list))
    {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

', $name, '_list_t* ', $name, '_list_new_get_by_', $field->{name}, '(const db_connection_t* connection, const db_value_t* ', $field->{name}, ') {
    ', $name, '_list_t* ', $name, '_list;

    if (!connection) {
        return NULL;
    }
    if (!', $field->{name}, ') {
        return NULL;
    }
    if (db_value_not_empty(', $field->{name}, ')) {
        return NULL;
    }

    if (!(', $name, '_list = ', $name, '_list_new(connection))
        || ', $name, '_list_get_by_', $field->{name}, '(', $name, '_list, ', $field->{name}, '))
    {
        ', $name, '_list_free(', $name, '_list);
        return NULL;
    }

    return ', $name, '_list;
}

';
    }
}
print SOURCE 'const ', $name, '_t* ', $name, '_list_begin(', $name, '_list_t* ', $name, '_list) {
    const db_result_t* result;

    if (!', $name, '_list) {
        return NULL;
    }

    if (', $name, '_list->object_store) {
        if (!', $name, '_list->object_list) {
            if (!', $name, '_list->result_list) {
                return NULL;
            }
            if (!db_result_list_size(', $name, '_list->result_list)) {
                return NULL;
            }
            if (!(', $name, '_list->object_list = (', $name, '_t**)calloc(db_result_list_size(', $name, '_list->result_list), sizeof(', $name, '_t**)))) {
                return NULL;
            }
            ', $name, '_list->object_list_size = db_result_list_size(', $name, '_list->result_list);
        }
        if (!(', $name, '_list->object_list[0])) {
            if (!', $name, '_list->result_list) {
                return NULL;
            }
            if (!(result = db_result_list_begin(', $name, '_list->result_list))) {
                return NULL;
            }
            if (!(', $name, '_list->object_list[0] = ', $name, '_new(db_object_connection(', $name, '_list->dbo)))) {
                return NULL;
            }
            if (', $name, '_from_result(', $name, '_list->object_list[0], result)) {
                return NULL;
            }
        }
        ', $name, '_list->object_list_position = 0;
        return ', $name, '_list->object_list[0];
    }

    if (!', $name, '_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(', $name, '_list->result_list))) {
        return NULL;
    }
    if (!', $name, '_list->', $name, ') {
        if (!(', $name, '_list->', $name, ' = ', $name, '_new(db_object_connection(', $name, '_list->dbo)))) {
            return NULL;
        }
    }
    if (', $name, '_from_result(', $name, '_list->', $name, ', result)) {
        return NULL;
    }
    return ', $name, '_list->', $name, ';
}

', $name, '_t* ', $name, '_list_get_begin(', $name, '_list_t* ', $name, '_list) {
    const db_result_t* result;
    ', $name, '_t* ', $name, ';

    if (!', $name, '_list) {
        return NULL;
    }

    if (', $name, '_list->object_store) {
        if (!(', $name, ' = ', $name, '_new(db_object_connection(', $name, '_list->dbo)))) {
            return NULL;
        }
        if (', $name, '_copy(', $name, ', ', $name, '_list_begin(', $name, '_list))) {
            ', $name, '_free(', $name, ');
            return NULL;
        }
        return ', $name, ';
    }

    if (!', $name, '_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_begin(', $name, '_list->result_list))) {
        return NULL;
    }
    if (!(', $name, ' = ', $name, '_new(db_object_connection(', $name, '_list->dbo)))) {
        return NULL;
    }
    if (', $name, '_from_result(', $name, ', result)) {
        ', $name, '_free(', $name, ');
        return NULL;
    }
    return ', $name, ';
}

const ', $name, '_t* ', $name, '_list_next(', $name, '_list_t* ', $name, '_list) {
    const db_result_t* result;

    if (!', $name, '_list) {
        return NULL;
    }

    if (', $name, '_list->object_store) {
        if (!', $name, '_list->object_list) {
            if (!', $name, '_list->result_list) {
                return NULL;
            }
            if (!db_result_list_size(', $name, '_list->result_list)) {
                return NULL;
            }
            if (!(', $name, '_list->object_list = (', $name, '_t**)calloc(db_result_list_size(', $name, '_list->result_list), sizeof(', $name, '_t**)))) {
                return NULL;
            }
            ', $name, '_list->object_list_size = db_result_list_size(', $name, '_list->result_list);
            ', $name, '_list->object_list_position = 0;
        }
        else if (', $name, '_list->object_list_first) {
            ', $name, '_list->object_list_first = 0;
            ', $name, '_list->object_list_position = 0;
        }
        else {
            ', $name, '_list->object_list_position++;
        }
        if (', $name, '_list->object_list_position >= ', $name, '_list->object_list_size) {
            return NULL;
        }
        if (!(', $name, '_list->object_list[', $name, '_list->object_list_position])) {
            if (!', $name, '_list->result_list) {
                return NULL;
            }
            if (!(result = db_result_list_next(', $name, '_list->result_list))) {
                return NULL;
            }
            if (!(', $name, '_list->object_list[', $name, '_list->object_list_position] = ', $name, '_new(db_object_connection(', $name, '_list->dbo)))) {
                return NULL;
            }
            if (', $name, '_from_result(', $name, '_list->object_list[', $name, '_list->object_list_position], result)) {
                return NULL;
            }
        }
        return ', $name, '_list->object_list[', $name, '_list->object_list_position];
    }

    if (!', $name, '_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(', $name, '_list->result_list))) {
        return NULL;
    }
    if (!', $name, '_list->', $name, ') {
        if (!(', $name, '_list->', $name, ' = ', $name, '_new(db_object_connection(', $name, '_list->dbo)))) {
            return NULL;
        }
    }
    if (', $name, '_from_result(', $name, '_list->', $name, ', result)) {
        return NULL;
    }
    return ', $name, '_list->', $name, ';
}

', $name, '_t* ', $name, '_list_get_next(', $name, '_list_t* ', $name, '_list) {
    const db_result_t* result;
    ', $name, '_t* ', $name, ';

    if (!', $name, '_list) {
        return NULL;
    }

    if (', $name, '_list->object_store) {
        if (!(', $name, ' = ', $name, '_new(db_object_connection(', $name, '_list->dbo)))) {
            return NULL;
        }
        if (', $name, '_copy(', $name, ', ', $name, '_list_next(', $name, '_list))) {
            ', $name, '_free(', $name, ');
            return NULL;
        }
        return ', $name, ';
    }

    if (!', $name, '_list->result_list) {
        return NULL;
    }

    if (!(result = db_result_list_next(', $name, '_list->result_list))) {
        return NULL;
    }
    if (!(', $name, ' = ', $name, '_new(db_object_connection(', $name, '_list->dbo)))) {
        return NULL;
    }
    if (', $name, '_from_result(', $name, ', result)) {
        ', $name, '_free(', $name, ');
        return NULL;
    }
    return ', $name, ';
}

size_t ', $name, '_list_size(', $name, '_list_t* ', $name, '_list) {
    if (!', $name, '_list) {
        return 0;
    }

    if (', $name, '_list->object_store
        && ', $name, '_list->object_list)
    {
        return ', $name, '_list->object_list_size;
    }

    if (!', $name, '_list->result_list) {
        return 0;
    }

    return db_result_list_size(', $name, '_list->result_list);
}
';
close(SOURCE);

if (!-f $name.'_ext.c') {
open(SOURCE, '>:encoding(UTF-8)', $name.'_ext.c') or die;

print SOURCE '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "', $name, '.h"

';
close(SOURCE);
}
}


open(SQLITE, '>:encoding(UTF-8)', 'schema.sqlite') or die;

    print SQLITE '-- Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
-- Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
-- Copyright (c) 2014 OpenDNSSEC AB (svb)
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
-- IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-- WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
-- DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
-- GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-- INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
-- IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
-- OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
-- IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
';
foreach my $object (@$objects) {
    my $name = $object->{name};
    my $tname = $name;
    $tname =~ s/_/ /go;

print SQLITE '
CREATE TABLE ', camelize($name), ' (
';
my $first = 1;
foreach my $field (@{$object->{fields}}) {
    if (!$first) {
        print SQLITE ',
';
    }
    $first = 0;
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
        print SQLITE '    ', camelize($field->{name}), ' ', $DB_TYPE_TO_SQLITE{'DB_TYPE_PRIMARY_KEY'};
        next;
    }
    if ($field->{foreign}) {
        print SQLITE '    ', camelize($field->{name}), ' INTEGER NOT NULL';
        next;
    }
        print SQLITE '    ', camelize($field->{name}), ' ', $DB_TYPE_TO_SQLITE{$field->{type}};
}
print SQLITE '
);
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
print SQLITE 'CREATE INDEX ', camelize($name.'_'.$field->{name}), ' ON ', camelize($name),' ( ', camelize($field->{name}), ' );
';
        next;
    }
    if ($field->{unique}) {
print SQLITE 'CREATE UNIQUE INDEX ', camelize($name.'_'.$field->{name}), ' ON ', camelize($name),' ( ', camelize($field->{name}), ' );
';
        next;
    }
}
}
close(SQLITE);

open(SQLITE, '>:encoding(UTF-8)', 'db_schema_sqlite.h') or die;

    print SQLITE '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __db_schema_sqlite_h
#define __db_schema_sqlite_h

extern const char* db_schema_sqlite_create[];
extern const char* db_schema_sqlite_drop[];

#endif
';
close(SQLITE);

open(SQLITE, '>:encoding(UTF-8)', 'db_schema_sqlite.c') or die;

    print SQLITE '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

const char* db_schema_sqlite_create[] = {
';
foreach my $object (@$objects) {
    my $name = $object->{name};
    my $tname = $name;
    $tname =~ s/_/ /go;

    my $first = 1;
    my $str = 'CREATE TABLE '.camelize($name).' (';
foreach my $field (@{$object->{fields}}) {
    if (!$first) {
        $str .= ', ';
    }
    $first = 0;
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
        $str .= ' '.camelize($field->{name}).' '.$DB_TYPE_TO_SQLITE{'DB_TYPE_PRIMARY_KEY'};
        next;
    }
    if ($field->{foreign}) {
        $str .= ' '.camelize($field->{name}).' INTEGER NOT NULL';
        next;
    }
        $str .= ' '.camelize($field->{name}).' '.$DB_TYPE_TO_SQLITE{$field->{type}};
}
$str .= ')';
my @parts = ( $str =~ m/.{1,500}/go );
for my $part (@parts) {
    print SQLITE '    "', $part, '",
';
}
print SQLITE '    0,
';

foreach my $field (@{$object->{fields}}) {
    my $str = '';

    if ($field->{foreign}) {
$str = 'CREATE INDEX '.camelize($name.'_'.$field->{name}).' ON '.camelize($name).' ( '.camelize($field->{name}).' )';
    }
    if ($field->{unique}) {
$str = 'CREATE UNIQUE INDEX '.camelize($name.'_'.$field->{name}).' ON '.camelize($name).' ( '.camelize($field->{name}).' )';
    }
    if (!$str) {
        next;
    }

my @parts = ( $str =~ m/.{1,500}/go );
for my $part (@parts) {
    print SQLITE '    "', $part, '",
';
}
print SQLITE '    0,
';
}
}
print SQLITE '    0
};

const char* db_schema_sqlite_drop[] = {
';
foreach my $object (@$objects) {
    my $name = $object->{name};

print SQLITE '    "DROP TABLE IF EXISTS ', camelize($name), '",
    0,
';
}
print SQLITE '    0
};
';
close(SQLITE);

open(MYSQL, '>:encoding(UTF-8)', 'schema.mysql') or die;

    print MYSQL '-- Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
-- Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
-- Copyright (c) 2014 OpenDNSSEC AB (svb)
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
-- IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-- WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
-- DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
-- GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-- INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
-- IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
-- OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
-- IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
';
foreach my $object (@$objects) {
    my $name = $object->{name};
    my $tname = $name;
    $tname =~ s/_/ /go;

print MYSQL '
CREATE TABLE ', camelize($name), ' (
';
my $first = 1;
foreach my $field (@{$object->{fields}}) {
    if (!$first) {
        print MYSQL ',
';
    }
    $first = 0;
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
        print MYSQL '    ', camelize($field->{name}), ' ', $DB_TYPE_TO_MYSQL{'DB_TYPE_PRIMARY_KEY'};
        next;
    }
    if ($field->{foreign}) {
        print MYSQL '    ', camelize($field->{name}), ' BIGINT UNSIGNED NOT NULL';
        next;
    }
        print MYSQL '    ', camelize($field->{name}), ' ', $DB_TYPE_TO_MYSQL{$field->{type}};
}
print MYSQL '
);
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{foreign}) {
print MYSQL 'CREATE INDEX ', camelize($name.'_'.$field->{name}), ' ON ', camelize($name),' ( ', camelize($field->{name}), ($field->{type} eq 'DB_TYPE_TEXT' ? '(255)' : ''), ' );
';
        next;
    }
    if ($field->{unique}) {
print MYSQL 'CREATE UNIQUE INDEX ', camelize($name.'_'.$field->{name}), ' ON ', camelize($name),' ( ', camelize($field->{name}), ($field->{type} eq 'DB_TYPE_TEXT' ? '(255)' : ''), ' );
';
        next;
    }
}
}
close(MYSQL);

open(MYSQL, '>:encoding(UTF-8)', 'drop.mysql') or die;

    print MYSQL '-- Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
-- Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
-- Copyright (c) 2014 OpenDNSSEC AB (svb)
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
-- IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-- WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
-- DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
-- GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-- INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
-- IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
-- OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
-- IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
';
foreach my $object (@$objects) {
    my $name = $object->{name};
    my $tname = $name;
    $tname =~ s/_/ /go;

print MYSQL '
DROP TABLE IF EXISTS ', camelize($name), ';
';
}
close(MYSQL);

open(MYSQL, '>:encoding(UTF-8)', 'db_schema_mysql.h') or die;

    print MYSQL '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __db_schema_mysql_h
#define __db_schema_mysql_h

extern const char* db_schema_mysql_create[];
extern const char* db_schema_mysql_drop[];

#endif
';
close(MYSQL);

open(MYSQL, '>:encoding(UTF-8)', 'db_schema_mysql.c') or die;

    print MYSQL '/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS\'\' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

const char* db_schema_mysql_create[] = {
';
foreach my $object (@$objects) {
    my $name = $object->{name};
    my $tname = $name;
    $tname =~ s/_/ /go;

    my $first = 1;
    my $str = 'CREATE TABLE '.camelize($name).' (';
foreach my $field (@{$object->{fields}}) {
    if (!$first) {
        $str .= ', ';
    }
    $first = 0;
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY') {
        $str .= ' '.camelize($field->{name}).' '.$DB_TYPE_TO_MYSQL{'DB_TYPE_PRIMARY_KEY'};
        next;
    }
    if ($field->{foreign}) {
        $str .= ' '.camelize($field->{name}).' BIGINT UNSIGNED NOT NULL';
        next;
    }
        $str .= ' '.camelize($field->{name}).' '.$DB_TYPE_TO_MYSQL{$field->{type}};
}
$str .= ')';
my @parts = ( $str =~ m/.{1,500}/go );
for my $part (@parts) {
    print MYSQL '    "', $part, '",
';
}
print MYSQL '    0,
';

foreach my $field (@{$object->{fields}}) {
    my $str = '';

    if ($field->{foreign}) {
$str = 'CREATE INDEX '.camelize($name.'_'.$field->{name}).' ON '.camelize($name).' ( '.camelize($field->{name}).($field->{type} eq 'DB_TYPE_TEXT' ? '(255)' : '').' )';
    }
    if ($field->{unique}) {
$str = 'CREATE UNIQUE INDEX '.camelize($name.'_'.$field->{name}).' ON '.camelize($name).' ( '.camelize($field->{name}).($field->{type} eq 'DB_TYPE_TEXT' ? '(255)' : '').' )';
    }
    if (!$str) {
        next;
    }

my @parts = ( $str =~ m/.{1,500}/go );
for my $part (@parts) {
    print MYSQL '    "', $part, '",
';
}
print MYSQL '    0,
';
}
}
print MYSQL '    0
};

const char* db_schema_mysql_drop[] = {
';
foreach my $object (@$objects) {
    my $name = $object->{name};

print MYSQL '    "DROP TABLE IF EXISTS ', camelize($name), '",
    0,
';
}
print MYSQL '    0
};
';
close(MYSQL);
