#!/usr/bin/env perl

use common::sense;
use JSON::XS;
use utf8;

my $JSON = JSON::XS->new;

open(FILE, $ARGV[0]) or die;
my $file;
while (<FILE>) {
    $file .= $_;
}
close(FILE);

my %DB_TYPE_TO_C_TYPE = (
    DB_TYPE_PRIMARY_KEY => 'int',
    DB_TYPE_INT32 => 'int',
    DB_TYPE_UINT32 => 'unsigned int',
    DB_TYPE_INT64 => 'long long',
    DB_TYPE_UINT64 => 'unsigned long long',
    DB_TYPE_TEXT => 'char*'
);

my %DB_TYPE_TO_FUNC = (
    DB_TYPE_PRIMARY_KEY => 'int32',
    DB_TYPE_INT32 => 'int32',
    DB_TYPE_UINT32 => 'uint32',
    DB_TYPE_INT64 => 'int64',
    DB_TYPE_UINT64 => 'uint64',
    DB_TYPE_TEXT => 'text',
    DB_TYPE_ANY => 'int32'
);

my %DB_TYPE_TO_TEXT = (
    DB_TYPE_PRIMARY_KEY => 'an integer',
    DB_TYPE_INT32 => 'an integer',
    DB_TYPE_UINT32 => 'an unsigned integer',
    DB_TYPE_INT64 => 'a long long',
    DB_TYPE_UINT64 => 'an unsigned long long',
    DB_TYPE_TEXT => 'a character pointer'
);

my $objects = $JSON->decode($file);

foreach my $object (@$objects) {
    my $name = $object->{name};
    my $tname = $name;
    $tname =~ s/_/ /go;

open(HEADER, '>:encoding(UTF-8)', 'test_'.$name.'.h') or die;
    
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

#ifndef __test_', $name, '_h
#define __test_', $name, '_h

#ifdef __cplusplus
extern "C" {
#endif

int test_', $name, '_add_suite(void);

#ifdef __cplusplus
}
#endif

#endif
';
close(HEADER);

open(SOURCE, '>:encoding(UTF-8)', 'test_'.$name.'.c') or die;
    
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

#include "CUnit/Basic.h"

#include "../db_configuration.h"
#include "../db_connection.h"
#include "../', $name, '.h"

#include <string.h>

static db_configuration_list_t* configuration_list = NULL;
static db_configuration_t* configuration = NULL;
static db_connection_t* connection = NULL;

static ', $name, '_t* object = NULL;
static ', $name, '_list_t* object_list = NULL;
static db_value_t id = DB_VALUE_EMPTY;
static db_clause_list_t* clause_list = NULL;

#if defined(ENFORCER_DATABASE_SQLITE3)
int test_', $name, '_init_suite_sqlite(void) {
    if (configuration_list) {
        return 1;
    }
    if (configuration) {
        return 1;
    }
    if (connection) {
        return 1;
    }

    /*
     * Setup the configuration for the connection
     */
    if (!(configuration_list = db_configuration_list_new())) {
        return 1;
    }
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "backend")
        || db_configuration_set_value(configuration, "sqlite")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "file")
        || db_configuration_set_value(configuration, "test.db")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;

    /*
     * Connect to the database
     */
    if (!(connection = db_connection_new())
        || db_connection_set_configuration_list(connection, configuration_list))
    {
        db_connection_free(connection);
        connection = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration_list = NULL;

    if (db_connection_setup(connection)
        || db_connection_connect(connection))
    {
        db_connection_free(connection);
        connection = NULL;
        return 1;
    }

    return 0;
}
#endif

#if defined(ENFORCER_DATABASE_COUCHDB)
int test_', $name, '_init_suite_couchdb(void) {
    if (configuration_list) {
        return 1;
    }
    if (configuration) {
        return 1;
    }
    if (connection) {
        return 1;
    }

    /*
     * Setup the configuration for the connection
     */
    if (!(configuration_list = db_configuration_list_new())) {
        return 1;
    }
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "backend")
        || db_configuration_set_value(configuration, "couchdb")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "url")
        || db_configuration_set_value(configuration, "http://127.0.0.1:5984/opendnssec")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;

    /*
     * Connect to the database
     */
    if (!(connection = db_connection_new())
        || db_connection_set_configuration_list(connection, configuration_list))
    {
        db_connection_free(connection);
        connection = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration_list = NULL;

    if (db_connection_setup(connection)
        || db_connection_connect(connection))
    {
        db_connection_free(connection);
        connection = NULL;
        return 1;
    }

    return 0;
}
#endif

static int test_', $name, '_clean_suite(void) {
    db_connection_free(connection);
    connection = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    db_value_reset(&id);
    db_clause_list_free(clause_list);
    clause_list = NULL;
    return 0;
}

static void test_', $name, '_new(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((object = ', $name, '_new(connection)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_list = ', $name, '_list_new(connection)));
}

static void test_', $name, '_set(void) {
';
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
print SOURCE '    db_value_t ', $field->{name}, ' = DB_VALUE_EMPTY;
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT(!db_value_from_text(&', $field->{name}, ', "', $field->{name}, ' 1");
';
        next;
    }
print SOURCE '    CU_ASSERT(!db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(&', $field->{name}, ', 1));
';
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{foreign}) {
print SOURCE '    CU_ASSERT(!', $name, '_set_', $field->{name}, '(object, &', $field->{name}, '));
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        foreach my $enum (@{$field->{enum}}) {
print SOURCE '    CU_ASSERT(!', $name, '_set_', $field->{name}, '(object, ', uc($name.'_'.$field->{name}), '_', $enum->{name}, '));
';
print SOURCE '    CU_ASSERT(!', $name, '_set_', $field->{name}, '_text(object, "', $enum->{text}, '"));
';
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT(!', $name, '_set_', $field->{name}, '(object, "', $field->{name}, ' 1"));
';
        next;
    }
print SOURCE '    CU_ASSERT(!', $name, '_set_', $field->{name}, '(object, 1));
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
print SOURCE '    db_value_reset(&', $field->{name}, ');
';
}
print SOURCE '}

static void test_', $name, '_get(void) {
';
my $ret = 0;
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if (!$ret) {
print SOURCE '    int ret;
';
        $ret = 1;
    }
print SOURCE '    db_value_t ', $field->{name}, ' = DB_VALUE_EMPTY;
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT(!db_value_from_text(&', $field->{name}, ', "', $field->{name}, ' 1");
';
        next;
    }
print SOURCE '    CU_ASSERT(!db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(&', $field->{name}, ', 1));
';
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{foreign}) {
print SOURCE '    CU_ASSERT(!db_value_cmp(', $name, '_', $field->{name}, '(object), &', $field->{name}, ', &ret));
    CU_ASSERT(!ret);
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        foreach my $enum (reverse @{$field->{enum}}) {
print SOURCE '    CU_ASSERT(', $name, '_', $field->{name}, '(object) == ', uc($name.'_'.$field->{name}), '_', $enum->{name}, ');
';
print SOURCE '    CU_ASSERT_PTR_NOT_NULL_FATAL(', $name, '_', $field->{name}, '_text(object));
';
print SOURCE '    CU_ASSERT(!strcmp(', $name, '_', $field->{name}, '_text(object), "', $enum->{text}, '"));
';
            last;
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT_PTR_NOT_NULL_FATAL(', $name, '_', $field->{name}, '(object));
';
print SOURCE '    CU_ASSERT(!strcmp(', $name, '_', $field->{name}, '(object), "', $field->{name}, ' 1"));
';
        next;
    }
print SOURCE '    CU_ASSERT(', $name, '_', $field->{name}, '(object) == 1);
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
print SOURCE '    db_value_reset(&', $field->{name}, ');
';
}
print SOURCE '}

static void test_', $name, '_create(void) {
    CU_ASSERT_FATAL(!', $name, '_create(object));
}

static void test_', $name, '_clauses(void) {
';
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }

print SOURCE '
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL(', $name, '_', $field->{name}, '_clause(clause_list, ', $name, '_', $field->{name}, '(object)));
    CU_ASSERT(!', $name, '_list_get_by_clauses(object_list, clause_list));
    CU_ASSERT_PTR_NOT_NULL(', $name, '_list_begin(object_list));
    db_clause_list_free(clause_list);
    clause_list = NULL;
';

    if ($field->{foreign}) {
    }
    elsif ($field->{type} eq 'DB_TYPE_ENUM') {
        foreach my $enum (reverse @{$field->{enum}}) {
            last;
        }
    }
    elsif ($field->{type} eq 'DB_TYPE_TEXT') {
    }
    else {
    }
}
print SOURCE '}

static void test_', $name, '_list(void) {
    const ', $name, '_t* item;
    CU_ASSERT_FATAL(!', $name, '_list_get(object_list));
    CU_ASSERT_PTR_NOT_NULL_FATAL((item = ', $name, '_list_begin(object_list)));
    CU_ASSERT_FATAL(!db_value_copy(&id, ', $name, '_id(item)));
}

static void test_', $name, '_read(void) {
    CU_ASSERT_FATAL(!', $name, '_get_by_id(object, &id));
}

static void test_', $name, '_verify(void) {
';
my $ret = 0;
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if (!$ret) {
print SOURCE '    int ret;
';
        $ret = 1;
    }
print SOURCE '    db_value_t ', $field->{name}, ' = DB_VALUE_EMPTY;
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT(!db_value_from_text(&', $field->{name}, ', "', $field->{name}, ' 1");
';
        next;
    }
print SOURCE '    CU_ASSERT(!db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(&', $field->{name}, ', 1));
';
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{foreign}) {
print SOURCE '    CU_ASSERT(!db_value_cmp(', $name, '_', $field->{name}, '(object), &', $field->{name}, ', &ret));
    CU_ASSERT(!ret);
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        foreach my $enum (reverse @{$field->{enum}}) {
print SOURCE '    CU_ASSERT(', $name, '_', $field->{name}, '(object) == ', uc($name.'_'.$field->{name}), '_', $enum->{name}, ');
';
print SOURCE '    CU_ASSERT_PTR_NOT_NULL_FATAL(', $name, '_', $field->{name}, '_text(object));
';
print SOURCE '    CU_ASSERT(!strcmp(', $name, '_', $field->{name}, '_text(object), "', $enum->{text}, '"));
';
            last;
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT_PTR_NOT_NULL_FATAL(', $name, '_', $field->{name}, '(object));
';
print SOURCE '    CU_ASSERT(!strcmp(', $name, '_', $field->{name}, '(object), "', $field->{name}, ' 1"));
';
        next;
    }
print SOURCE '    CU_ASSERT(', $name, '_', $field->{name}, '(object) == 1);
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
print SOURCE '    db_value_reset(&', $field->{name}, ');
';
}
print SOURCE '}

';
foreach my $field (@{$object->{fields}}) {
    if (!$field->{unique}) {
        next;
    }
print SOURCE 'static void test_', $name, '_read_by_', $field->{name}, '(void) {
';
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT_FATAL(!', $name, '_get_by_', $field->{name}, '(object, "', $field->{name}, ' 1"));
';
    }
    else {
print SOURCE '    CU_ASSERT_FATAL(!', $name, '_get_by_', $field->{name}, '(object, 1));
';
    }
print SOURCE '}

static void test_', $name, '_verify_', $field->{name}, '(void) {
';
my $ret = 0;
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if (!$ret) {
print SOURCE '    int ret;
';
        $ret = 1;
    }
print SOURCE '    db_value_t ', $field->{name}, ' = DB_VALUE_EMPTY;
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT(!db_value_from_text(&', $field->{name}, ', "', $field->{name}, ' 1");
';
        next;
    }
print SOURCE '    CU_ASSERT(!db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(&', $field->{name}, ', 1));
';
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{foreign}) {
print SOURCE '    CU_ASSERT(!db_value_cmp(', $name, '_', $field->{name}, '(object), &', $field->{name}, ', &ret));
    CU_ASSERT(!ret);
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        foreach my $enum (reverse @{$field->{enum}}) {
print SOURCE '    CU_ASSERT(', $name, '_', $field->{name}, '(object) == ', uc($name.'_'.$field->{name}), '_', $enum->{name}, ');
';
print SOURCE '    CU_ASSERT_PTR_NOT_NULL_FATAL(', $name, '_', $field->{name}, '_text(object));
';
print SOURCE '    CU_ASSERT(!strcmp(', $name, '_', $field->{name}, '_text(object), "', $enum->{text}, '"));
';
            last;
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT_PTR_NOT_NULL_FATAL(', $name, '_', $field->{name}, '(object));
';
print SOURCE '    CU_ASSERT(!strcmp(', $name, '_', $field->{name}, '(object), "', $field->{name}, ' 1"));
';
        next;
    }
print SOURCE '    CU_ASSERT(', $name, '_', $field->{name}, '(object) == 1);
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
print SOURCE '    db_value_reset(&', $field->{name}, ');
';
}
print SOURCE '}

';
}
print SOURCE 'static void test_', $name, '_change(void) {
';
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
print SOURCE '    db_value_t ', $field->{name}, ' = DB_VALUE_EMPTY;
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT(!db_value_from_text(&', $field->{name}, ', "', $field->{name}, ' 2");
';
        next;
    }
print SOURCE '    CU_ASSERT(!db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(&', $field->{name}, ', 2));
';
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{foreign}) {
print SOURCE '    CU_ASSERT(!', $name, '_set_', $field->{name}, '(object, &', $field->{name}, '));
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        foreach my $enum (@{$field->{enum}}) {
print SOURCE '    CU_ASSERT(!', $name, '_set_', $field->{name}, '(object, ', uc($name.'_'.$field->{name}), '_', $enum->{name}, '));
';
print SOURCE '    CU_ASSERT(!', $name, '_set_', $field->{name}, '_text(object, "', $enum->{text}, '"));
';
            last;
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT(!', $name, '_set_', $field->{name}, '(object, "', $field->{name}, ' 2"));
';
        next;
    }
print SOURCE '    CU_ASSERT(!', $name, '_set_', $field->{name}, '(object, 2));
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
print SOURCE '    db_value_reset(&', $field->{name}, ');
';
}
print SOURCE '}

static void test_', $name, '_update(void) {
';
    if (scalar @{$object->{fields}} > 1) {
print SOURCE '    CU_ASSERT_FATAL(!', $name, '_update(object));
';
    }
print SOURCE '}

static void test_', $name, '_read2(void) {
    CU_ASSERT_FATAL(!', $name, '_get_by_id(object, &id));
}

static void test_', $name, '_verify2(void) {
';
my $ret = 0;
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if (!$ret) {
print SOURCE '    int ret;
';
        $ret = 1;
    }
print SOURCE '    db_value_t ', $field->{name}, ' = DB_VALUE_EMPTY;
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT(!db_value_from_text(&', $field->{name}, ', "', $field->{name}, ' 2");
';
        next;
    }
print SOURCE '    CU_ASSERT(!db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(&', $field->{name}, ', 2));
';
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{foreign}) {
print SOURCE '    CU_ASSERT(!db_value_cmp(', $name, '_', $field->{name}, '(object), &', $field->{name}, ', &ret));
    CU_ASSERT(!ret);
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        foreach my $enum (@{$field->{enum}}) {
print SOURCE '    CU_ASSERT(', $name, '_', $field->{name}, '(object) == ', uc($name.'_'.$field->{name}), '_', $enum->{name}, ');
';
print SOURCE '    CU_ASSERT_PTR_NOT_NULL_FATAL(', $name, '_', $field->{name}, '_text(object));
';
print SOURCE '    CU_ASSERT(!strcmp(', $name, '_', $field->{name}, '_text(object), "', $enum->{text}, '"));
';
            last;
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT_PTR_NOT_NULL_FATAL(', $name, '_', $field->{name}, '(object));
';
print SOURCE '    CU_ASSERT(!strcmp(', $name, '_', $field->{name}, '(object), "', $field->{name}, ' 2"));
';
        next;
    }
print SOURCE '    CU_ASSERT(', $name, '_', $field->{name}, '(object) == 2);
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
print SOURCE '    db_value_reset(&', $field->{name}, ');
';
}
print SOURCE '}

static void test_', $name, '_cmp(void) {
    ', $name, '_t* local_object;

    CU_ASSERT_PTR_NOT_NULL_FATAL((local_object = ', $name, '_new(connection)));
    CU_ASSERT(', $name, '_cmp(object, local_object));
}

';
foreach my $field (@{$object->{fields}}) {
    if (!$field->{unique}) {
        next;
    }
print SOURCE 'static void test_', $name, '_read_by_', $field->{name}, '2(void) {
';
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT_FATAL(!', $name, '_get_by_', $field->{name}, '(object, "', $field->{name}, ' 2"));
';
    }
    else {
print SOURCE '    CU_ASSERT_FATAL(!', $name, '_get_by_', $field->{name}, '(object, 2));
';
    }
print SOURCE '}

static void test_', $name, '_verify_', $field->{name}, '2(void) {
';
my $ret = 0;
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if (!$ret) {
print SOURCE '    int ret;
';
        $ret = 1;
    }
print SOURCE '    db_value_t ', $field->{name}, ' = DB_VALUE_EMPTY;
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT(!db_value_from_text(&', $field->{name}, ', "', $field->{name}, ' 2");
';
        next;
    }
print SOURCE '    CU_ASSERT(!db_value_from_', $DB_TYPE_TO_FUNC{$field->{type}}, '(&', $field->{name}, ', 2));
';
}
foreach my $field (@{$object->{fields}}) {
    if ($field->{type} eq 'DB_TYPE_PRIMARY_KEY' or $field->{type} eq 'DB_TYPE_REVISION') {
        next;
    }
    if ($field->{foreign}) {
print SOURCE '    CU_ASSERT(!db_value_cmp(', $name, '_', $field->{name}, '(object), &', $field->{name}, ', &ret));
    CU_ASSERT(!ret);
';
        next;
    }
    if ($field->{type} eq 'DB_TYPE_ENUM') {
        foreach my $enum (@{$field->{enum}}) {
print SOURCE '    CU_ASSERT(', $name, '_', $field->{name}, '(object) == ', uc($name.'_'.$field->{name}), '_', $enum->{name}, ');
';
print SOURCE '    CU_ASSERT_PTR_NOT_NULL_FATAL(', $name, '_', $field->{name}, '_text(object));
';
print SOURCE '    CU_ASSERT(!strcmp(', $name, '_', $field->{name}, '_text(object), "', $enum->{text}, '"));
';
            last;
        }
        next;
    }
    if ($field->{type} eq 'DB_TYPE_TEXT') {
print SOURCE '    CU_ASSERT_PTR_NOT_NULL_FATAL(', $name, '_', $field->{name}, '(object));
';
print SOURCE '    CU_ASSERT(!strcmp(', $name, '_', $field->{name}, '(object), "', $field->{name}, ' 2"));
';
        next;
    }
print SOURCE '    CU_ASSERT(', $name, '_', $field->{name}, '(object) == 2);
';
}
foreach my $field (@{$object->{fields}}) {
    if (!$field->{foreign}) {
        next;
    }
print SOURCE '    db_value_reset(&', $field->{name}, ');
';
}
print SOURCE '}

';
}
print SOURCE 'static void test_', $name, '_delete(void) {
    CU_ASSERT_FATAL(!', $name, '_delete(object));
}

static void test_', $name, '_list2(void) {
    CU_ASSERT_FATAL(!', $name, '_list_get(object_list));
    CU_ASSERT_PTR_NULL(', $name, '_list_begin(object_list));
}

static void test_', $name, '_end(void) {
    if (object) {
        ', $name, '_free(object);
        CU_PASS("', $name, '_free");
    }
    if (object_list) {
        ', $name, '_list_free(object_list);
        CU_PASS("', $name, '_list_free");
    }
}

static int test_', $name, '_add_tests(CU_pSuite pSuite) {
    if (!CU_add_test(pSuite, "new object", test_', $name, '_new)
        || !CU_add_test(pSuite, "set fields", test_', $name, '_set)
        || !CU_add_test(pSuite, "get fields", test_', $name, '_get)
        || !CU_add_test(pSuite, "create object", test_', $name, '_create)
        || !CU_add_test(pSuite, "object clauses", test_', $name, '_clauses)
        || !CU_add_test(pSuite, "list objects", test_', $name, '_list)
        || !CU_add_test(pSuite, "read object by id", test_', $name, '_read)
        || !CU_add_test(pSuite, "verify fields", test_', $name, '_verify)
';
foreach my $field (@{$object->{fields}}) {
    if (!$field->{unique}) {
        next;
    }
print SOURCE '        || !CU_add_test(pSuite, "read object by ', $field->{name}, '", test_', $name, '_read_by_', $field->{name}, ')
        || !CU_add_test(pSuite, "verify fields (', $field->{name}, ')", test_', $name, '_verify_', $field->{name}, ')
';
}
print SOURCE '        || !CU_add_test(pSuite, "change object", test_', $name, '_change)
        || !CU_add_test(pSuite, "update object", test_', $name, '_update)
        || !CU_add_test(pSuite, "reread object by id", test_', $name, '_read2)
        || !CU_add_test(pSuite, "verify fields after update", test_', $name, '_verify2)
        || !CU_add_test(pSuite, "compare objects", test_', $name, '_cmp)
';
foreach my $field (@{$object->{fields}}) {
    if (!$field->{unique}) {
        next;
    }
print SOURCE '        || !CU_add_test(pSuite, "reread object by ', $field->{name}, '", test_', $name, '_read_by_', $field->{name}, '2)
        || !CU_add_test(pSuite, "verify fields after update (', $field->{name}, ')", test_', $name, '_verify_', $field->{name}, '2)
';
}
print SOURCE '        || !CU_add_test(pSuite, "delete object", test_', $name, '_delete)
        || !CU_add_test(pSuite, "list objects to verify delete", test_', $name, '_list2)
        || !CU_add_test(pSuite, "end test", test_', $name, '_end))
    {
        return CU_get_error();
    }
    return 0;
}

int test_', $name, '_add_suite(void) {
    CU_pSuite pSuite = NULL;
    int ret;

#if defined(ENFORCER_DATABASE_SQLITE3)
    pSuite = CU_add_suite("Test of ', $tname, ' (SQLite)", test_', $name, '_init_suite_sqlite, test_', $name, '_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_', $name, '_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
#if defined(ENFORCER_DATABASE_COUCHDB)
    pSuite = CU_add_suite("Test of ', $tname, ' (CouchDB)", test_', $name, '_init_suite_couchdb, test_', $name, '_clean_suite);
    if (!pSuite) {
        return CU_get_error();
    }
    ret = test_', $name, '_add_tests(pSuite);
    if (ret) {
        return ret;
    }
#endif
    return 0;
}
';
close(SOURCE);

}
