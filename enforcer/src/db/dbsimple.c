/*
 * Copyright (c) 2021 A.W. van Halderen
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <setjmp.h>

#include "utilities.h"
#include "tree.h"
#include "dbsimple.h"
#include "dbsimplebase.h"

int dbsimple_initialize(void) {
    return 0;
}

int dbsimple_finalize(void) {
    return 0;
}

struct dbsimple_connection_struct {
    struct dbsimple_connectionbase baseconnection;
};

struct dbsimple_session_struct {
    struct dbsimple_sessionbase basesession;
};

static int nmodules = 0;
static const struct dbsimple_module** modules = NULL;

int
dbsimple_registermodule(const struct dbsimple_module* bindings)
{
    if(!alloc(&modules, sizeof(struct dbsimple_module*), &nmodules, nmodules + 1)) {
        modules[nmodules - 1] = bindings;
        return 0;
    } else
        return -1;
}

int
dbsimple_fetchplan(dbsimple_fetchplan_type* fetchplan, dbsimple_connection_type connection, char* modulename, const char* const* queries)
{
    int definitionindex = 0;
    struct dbsimple_definitionimpl** definitions;
    if(strcmp(modulename, connection->baseconnection.module->identifier))
        return 0;
    *fetchplan = malloc(sizeof(struct dbsimple_fetchplan_struct));
    (*fetchplan)->queries = queries;
    (*fetchplan)->ndefinitions = connection->baseconnection.ndefinitions;
    (*fetchplan)->definitions = definitions = malloc(sizeof(struct dbsimple_definitionimpl*) * (*fetchplan)->ndefinitions);
    for(int i=0; i<(*fetchplan)->ndefinitions; i++) {
        struct dbsimple_definition* d = connection->baseconnection.definitions[i];
        definitions[i] = malloc(sizeof(struct dbsimple_definitionimpl));
        definitions[i]->name    = strdup(d->name);
        definitions[i]->nfields = d->nfields;
        definitions[i]->fields  = malloc(sizeof(struct dbsimple_fieldimpl) * d->nfields);;
        definitions[i]->flags   = d->flags;
        definitions[i]->size    = d->size;
        for(int j=0; j<d->nfields; j++) {
            if(d->fields[j].def) {
                for(definitionindex = connection->baseconnection.ndefinitions - 1; definitionindex > 0; definitionindex--) {
                    if(connection->baseconnection.definitions[definitionindex] == d->fields[j].def)
                        break;
                }
                assert(definitionindex >= 0);
            } else
                definitionindex = -1;
            definitions[i]->fields[j].type        = d->fields[j].type;
            definitions[i]->fields[j].fieldoffset = d->fields[j].fieldoffset;
            definitions[i]->fields[j].countoffset = d->fields[j].countoffset;
            definitions[i]->fields[j].def         = (definitionindex >= 0 ? &(definitions[definitionindex]) : NULL);
        }
    }
    return 0;
}

int
dbsimple_openconnection(char* location,
                        int nplans, dbsimple_fetchplan_array plans,
                        int ndefinitions, struct dbsimple_definition** definitions,
                        dbsimple_connection_type* connectionPtr)
{
    int returnCode = 0;
    int count;
    dbsimple_connection_type connection;
    const struct dbsimple_module* module = NULL;

    if(nplans < 0) {
        for(count=0; plans[count]; count++)
            ;
        nplans = count;
    }
    if(ndefinitions < 0) {
        for(count=0; definitions[count]; count++)
            ;
        ndefinitions = count;
    }

    for (int i=0; i<nmodules; i++) {
        if (!strncasecmp(location, modules[i]->identifier, strlen(modules[i]->identifier)) &&
           location[strlen(modules[i]->identifier)] == ':') {
            module = modules[i];
            location = &location[strlen(modules[i]->identifier) + 1];
            break;
        } else if (modules[i]->identifier == NULL) {
            module = modules[i];
        }
    }
    if (!module) {
        return -1;
    }

    returnCode = module->openconnection(location, nplans, plans, connectionPtr);
    connection = *connectionPtr;
    connection->baseconnection.module       = module;
    connection->baseconnection.location     = strdup(location);
    connection->baseconnection.nplans       = nplans;
    connection->baseconnection.plans        = plans;
    connection->baseconnection.ndefinitions = ndefinitions;
    connection->baseconnection.definitions  = definitions;
    return returnCode;
}

int
dbsimple_closeconnection(dbsimple_connection_type connection)
{
    free(connection->baseconnection.location);
    connection->baseconnection.location = NULL;
    connection->baseconnection.module->closeconnection(connection);
    return 0;
}

int
dbsimple_opensession(dbsimple_connection_type connection, dbsimple_session_type* sessionPtr)
{  
    int returnCode = 0;
    dbsimple_session_type session;
    if(!connection) {
        sessionPtr = NULL;
        return -1;
    }
    returnCode = connection->baseconnection.module->opensession(connection, sessionPtr);
    session = *sessionPtr;
    session->basesession.connection = &(connection->baseconnection);
    session->basesession.module        = connection->baseconnection.module;
    session->basesession.firstmodified = NULL;
    session->basesession.objectmap     = NULL;
    session->basesession.pointermap    = NULL;
    return returnCode;
}

int
dbsimple_closesession(dbsimple_session_type session)
{
    int returnCode = 0;
    if(!setjmp(session->basesession.exceptionstate)) {
        returnCode = session->basesession.module->closesession(session);
    } else {
        returnCode = 1;
    }
    return returnCode;
}

int
dbsimple_sync(dbsimple_session_type session, dbsimple_fetchplan_reference plan, void* data)
{
    int returnCode = 0;
    int index;
    if(!setjmp(session->basesession.exceptionstate)) {
        index = plan - session->basesession.connection->plans;
        if(index >= 0 && index < session->basesession.connection->nplans) {
            returnCode = session->basesession.module->syncdata(session, **plan, data);
        }
    } else {
        returnCode = 1;   
    }
    return returnCode;
}

void*
dbsimple_fetch(dbsimple_session_type session, dbsimple_fetchplan_reference plan, ...)
{
    va_list args;
    void* returnValue = NULL;
    int index;
    index = plan - session->basesession.connection->plans;
    if(index >= 0 && index < session->basesession.connection->nplans) {
        va_start(args, plan);
        returnValue = session->basesession.module->fetchdata(session, **plan, args);
        va_end(args);
    }
else abort(); // BERRY
    return returnValue;
}

int
dbsimple_commit(dbsimple_session_type session)
{
    int returnCode = 0;
    if(!setjmp(session->basesession.exceptionstate)) {
        returnCode = session->basesession.module->commitdata(session);
    } else {
        returnCode = 1;
    }
    return returnCode;
}
