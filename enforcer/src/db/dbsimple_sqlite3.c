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
#if !defined(HAVE_SQLITE3) || defined(DYNAMIC_SQLITE3)
#include <dlfcn.h>
#endif
#if (defined(HAVE_SQLITE3_H) || defined(HAVE_SQLITE3))
#include <sqlite3.h>
#endif

#include "utilities.h"
#include "tree.h"
#include "dbsimple.h"
#include "dbsimplebase.h"
#include "logging.h"

static int initialize(void);
static void reportError(sqlite3* handle, const char* message);

static logger_cls_type logger = LOGGER_INITIALIZE(__FILE__);        

#if !(defined(HAVE_SQLITE3_H) || defined(HAVE_SQLITE3))

int dbsimple_sqlite3_initialize(char* hint) {
    return -1;
}

int dbsimple_sqlite3_finalize(void) {
    return -1;
}

#else

#if !defined(HAVE_SQLITE3) || defined(DYNAMIC_SQLITE3)

#define sqlite3_errmsg           dynamicsqlite3_errmsg
#define sqlite3_errcode          dynamicsqlite3_errcode
#define sqlite3_open_v2          dynamicsqlite3_open_v2
#define sqlite3_close            dynamicsqlite3_close
#define sqlite3_free             dynamicsqlite3_free
#define sqlite3_threadsafe       dynamicsqlite3_threadsafe
#define sqlite3_config           dynamicsqlite3_config
#define sqlite3_step             dynamicsqlite3_step
#define sqlite3_column_int       dynamicsqlite3_column_int
#define sqlite3_column_text      dynamicsqlite3_column_text
#define sqlite3_column_type      dynamicsqlite3_column_type
#define sqlite3_bind_int         dynamicsqlite3_bind_int
#define sqlite3_bind_null        dynamicsqlite3_bind_null
#define sqlite3_bind_text        dynamicsqlite3_bind_text
#define sqlite3_changes          dynamicsqlite3_changes
#define sqlite3_clear_bindings   dynamicsqlite3_clear_bindings
#define sqlite3_exec             dynamicsqlite3_exec
#define sqlite3_extended_errcode dynamicsqlite3_extended_errcode
#define sqlite3_finalize         dynamicsqlite3_finalize
#define sqlite3_prepare_v2       dynamicsqlite3_prepare_v2
#define sqlite3_reset            dynamicsqlite3_reset

const char* (*sqlite3_errmsg)(sqlite3*);
int (*sqlite3_errcode)(sqlite3*);
int (*sqlite3_open_v2)(const char*, sqlite3**, int, const char*);
int (*sqlite3_close)(sqlite3*);
void (*sqlite3_free)(void*);
int (*sqlite3_threadsafe)(void);
int (*sqlite3_config)(int, ...);
int (*sqlite3_step)(sqlite3_stmt*);
int (*sqlite3_column_int)(sqlite3_stmt*, int);
char* (*sqlite3_column_text)(sqlite3_stmt*, int);
int (*sqlite3_column_type)(sqlite3_stmt*, int);
int (*sqlite3_bind_int)(sqlite3_stmt*, int, int);
int (*sqlite3_bind_null)(sqlite3_stmt*, int);
int (*sqlite3_bind_text)(sqlite3_stmt*,int,const char*,int,void(*)(void*));
int (*sqlite3_changes)(sqlite3*);
int (*sqlite3_clear_bindings)(sqlite3_stmt*);
int (*sqlite3_exec)(sqlite3*,const char*,int(*)(void*,int,char**,char**),void*,char**);
int (*sqlite3_extended_errcode)(sqlite3*);
int (*sqlite3_finalize)(sqlite3_stmt*);
int (*sqlite3_prepare_v2)(sqlite3*,const char*,int,sqlite3_stmt**,const char**);
int (*sqlite3_reset)(sqlite3_stmt*);

int
dbsimple_sqlite3_initialize(void)
{
    void* dlhandle = NULL;
    sqlite3_errmsg           = (const char* (*)(sqlite3*))functioncast(dlsym(dlhandle, "sqlite3_errmsg"));
    sqlite3_errcode          = (int (*)(sqlite3*))functioncast(dlsym(dlhandle, "sqlite3_errcode"));
    sqlite3_open_v2          = (int(*)(const char *, sqlite3 **, int, const char*))functioncast(dlsym(dlhandle, "sqlite3_open_v2"));
    sqlite3_close            = (int (*)(sqlite3*))functioncast(dlsym(dlhandle, "sqlite3_close"));
    sqlite3_free             = (void (*)(void*))functioncast(dlsym(dlhandle, "sqlite3_free"));
    sqlite3_threadsafe       = (int (*)())functioncast(dlsym(dlhandle, "sqlite3_threadsafe"));
    sqlite3_config           = (int (*)(int,...))functioncast(dlsym(dlhandle, "sqlite3_config"));
    sqlite3_step             = (int (*)(sqlite3_stmt*))functioncast(dlsym(dlhandle, "sqlite3_step"));
    sqlite3_column_int       = (int (*)(sqlite3_stmt*,int))functioncast(dlsym(dlhandle, "sqlite3_column_int"));
    sqlite3_column_text      = (char* (*)(sqlite3_stmt*,int))functioncast(dlsym(dlhandle, "sqlite3_column_text"));

    sqlite3_column_type      = (int (*)(sqlite3_stmt*, int))functioncast(dlsym(dlhandle, "sqlite3_column_type"));
    sqlite3_bind_int         = (int (*)(sqlite3_stmt*, int, int))functioncast(dlsym(dlhandle, "sqlite3_bind_int"));
    sqlite3_bind_null        = (int (*)(sqlite3_stmt*, int))functioncast(dlsym(dlhandle, "sqlite3_bind_null"));
    sqlite3_bind_text        = (int (*)(sqlite3_stmt*,int,const char*,int,void(*)(void*)))functioncast(dlsym(dlhandle, "sqlite3_bind_text"));
    sqlite3_changes          = (int (*)(sqlite3*))functioncast(dlsym(dlhandle, "sqlite3_changes"));
    sqlite3_clear_bindings   = (int (*)(sqlite3_stmt*))functioncast(dlsym(dlhandle, "sqlite3_clear_bindings"));
    sqlite3_exec             = (int (*)(sqlite3*,const char*,int(*)(void*,int,char**,char**),void*,char**))functioncast(dlsym(dlhandle, "sqlite3_exec"));
    sqlite3_extended_errcode = (int (*)(sqlite3*))functioncast(dlsym(dlhandle, "sqlite3_extended_errcode"));

    sqlite3_finalize         = (int (*)(sqlite3_stmt*))functioncast(dlsym(dlhandle, "sqlite3_finalize"));
    sqlite3_prepare_v2       = (int (*)(sqlite3*,const char*,int,sqlite3_stmt**,const char**))functioncast(dlsym(dlhandle, "sqlite3_prepare_v2"));
    sqlite3_reset            = (int (*)(sqlite3_stmt*))functioncast(dlsym(dlhandle, "sqlite3_reset"));
    return initialize();
}

int
dbsimple_sqlite3_finalize(void)
{
    sqlite3_errmsg           = NULL;
    sqlite3_errcode          = NULL;
    sqlite3_open_v2          = NULL;
    sqlite3_close            = NULL;
    sqlite3_free             = NULL;
    sqlite3_threadsafe       = NULL;
    sqlite3_config           = NULL;
    sqlite3_step             = NULL;
    sqlite3_column_int       = NULL;
    sqlite3_column_text      = NULL;
    sqlite3_column_type      = NULL;
    sqlite3_bind_int         = NULL;
    sqlite3_bind_null        = NULL;
    sqlite3_bind_text        = NULL;
    sqlite3_changes          = NULL;
    sqlite3_clear_bindings   = NULL;
    sqlite3_exec             = NULL;
    sqlite3_extended_errcode = NULL;
    sqlite3_finalize         = NULL;
    sqlite3_prepare_v2       = NULL;
    sqlite3_reset            = NULL;
    return 0;
}

#else

int
dbsimple_sqlite3_initialize()
{
    return initialize();
}

int
dbsimple_sqlite3_finalize(void)
{
    return 0;
}

struct dbsimple_connection_struct {
    struct dbsimple_connectionbase baseconnection;
    sqlite3* handle;
};

struct dbsimple_session_struct {
    struct dbsimple_sessionbase basesession;
    dbsimple_connection_type connection;
    sqlite3* handle;
    sqlite3_stmt* beginStmt;
    sqlite3_stmt* commitStmt;
    sqlite3_stmt* rollbackStmt;
    dbsimple_fetchplan_type currentPlan;
    sqlite3_stmt** currentStmts;
};

static int openconnection(char* location, int nplans,  dbsimple_fetchplan_array plans, dbsimple_connection_type* connectionPtr);
static int closeconnection(dbsimple_connection_type connection);
static int opensession(dbsimple_connection_type connection, dbsimple_session_type* sessionPtr);
static int closesession(dbsimple_session_type session);
static int syncdata(dbsimple_session_type session, struct dbsimple_fetchplan_struct*, void* data);
static void* fetchdata(dbsimple_session_type session, struct dbsimple_fetchplan_struct*, va_list args);
static int commitdata(dbsimple_session_type session);
static void fetchobject(struct dbsimple_definitionimpl** def, dbsimple_session_type session);
static int persistobject(struct object* object, dbsimple_session_type session);

static void errorcallback(__attribute__((unused)) void *data, __attribute__((unused)) int errorCode, __attribute__((unused)) const char *errorMessage) {
    //fprintf(stderr, "ERROR %s (%d)\n", errorMessage, errorCode);
}

static const struct dbsimple_module module1 = {
    "sqlite", openconnection, closeconnection, opensession, closesession, syncdata, fetchdata, commitdata, fetchobject, persistobject
};
static const struct dbsimple_module module2 = {
    "sqlite3", openconnection, closeconnection, opensession, closesession, syncdata, fetchdata, commitdata, fetchobject, persistobject
};

static int initialize(void)
{
    if(!sqlite3_threadsafe()) {
        dbsimple_finalize();
        return -1;
    }
    sqlite3_config(SQLITE_CONFIG_SERIALIZED);
    sqlite3_config(SQLITE_CONFIG_LOG, errorcallback, NULL);

    dbsimple_registermodule(&module1);
    dbsimple_registermodule(&module2);
    
    return 0;
}

static void reportError(sqlite3* handle, const char* message)
{
    logger_message(&logger,logger_noctx,logger_DEBUG, "%s%s %s (%d, %d)\n",
                   (message?message:""), ((message&&*message)?":":""), sqlite3_errmsg(handle), sqlite3_errcode(handle), sqlite3_extended_errcode(handle));
}

int gobbleResult(void* a, int b, char**c, char**d)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    return 0;
}

static int eatResult(sqlite3* handle, sqlite3_stmt* stmt, void* data)
{
    int status;
    int column;
    int affected = 0;
    logger_message(&logger,logger_noctx,logger_DEBUG, "statement \"%s\"\n",sqlite3_expanded_sql(stmt));
    do {
        switch ((status = sqlite3_step(stmt))) {
            case SQLITE_ROW:
                ++affected;
                column = 0;
                if(data) {
                    *((int*) data) = sqlite3_column_int(stmt, column++);
                }
                break;
            case SQLITE_DONE:
                affected = sqlite3_changes(handle);
                return affected;
            case SQLITE_BUSY:
                sleep(1);
                break;
            case SQLITE_ERROR:
                reportError(handle, "error");
                return -1;
            case SQLITE_MISUSE:
                reportError(handle, "misuse");
                return -1;
            default:
                break;
        }
    } while(status == SQLITE_BUSY || status == SQLITE_ROW);
    return affected;
}

#endif

static sqlite3_stmt*
getStmtFetch(dbsimple_session_type session, struct dbsimple_definitionimpl** def)
{
    int index = (def - session->currentPlan->definitions);
    return session->currentStmts[index*3+0];
}

static sqlite3_stmt*
getStmtInsert(dbsimple_session_type session, struct dbsimple_definitionimpl** def)
{
    int index = (def - session->currentPlan->definitions);
    return session->currentStmts[index*3+1];
}

static sqlite3_stmt*
getStmtDelete(dbsimple_session_type session, struct dbsimple_definitionimpl** def)
{
    int index = (def - session->currentPlan->definitions);
    return session->currentStmts[index*3+2];
}

static void
fetchobject(struct dbsimple_definitionimpl** def, dbsimple_session_type session)
{
    int status;
    int column;
    long targetkeyid;
    const char* targetkeystr;
    struct object* object = NULL;
    int intvalue;
    long longvalue;
    char* cstrvalue;
    sqlite3* handle = session->connection->handle;
    sqlite3_stmt* stmt = getStmtFetch(session, def);
    sqlite3_reset(stmt);
    logger_message(&logger,logger_noctx,logger_DEBUG, "statement \"%s\"\n",sqlite3_expanded_sql(stmt));

    do {
        switch((status = sqlite3_step(stmt))) {
            case SQLITE_ROW:
                column = 0;
                for(int i = 0; i<(*def)->nfields; i++) {
                    struct dbsimple_fieldimpl* field = &((*def)->fields[i]);
                    struct dbsimple_definitionimpl* targetdef = (field->def ? *(field->def) : NULL);
                    int isRevision = (i==1 && ((*def)->flags & dbsimple_FLAG_HASREVISION));
                    switch(field->type) {
                        case dbsimple_INT:
                        case dbsimple_UINT:
                            assert(sqlite3_column_type(stmt, column) == SQLITE_INTEGER);
                            intvalue = sqlite3_column_int(stmt, column++);
                            if (i==0) {
                                object = dbsimple__getobject(&session->basesession, OBJCLEAN, field->def, intvalue, NULL);
                            } else if(isRevision) {
                                object->revision = intvalue;
                            }
                            if(field->fieldoffset >= 0)
                                *(int*)&(object->data[field->fieldoffset]) = intvalue;
                            break;
                        case dbsimple_LONGINT:
                        case dbsimple_ULONGINT:
                            assert(sqlite3_column_type(stmt, column) == SQLITE_INTEGER);
                            longvalue = sqlite3_column_int64(stmt, column++);
                            if (i==0) {
                                object = dbsimple__getobject(&session->basesession, OBJCLEAN, field->def, longvalue, NULL);
                            } else if(isRevision) {
                                object->revision = longvalue;
                            }
                            if(field->fieldoffset >= 0)
                                *(long*)&(object->data[field->fieldoffset]) = longvalue;
                            break;
                        case dbsimple_STRING:
                            assert(sqlite3_column_type(stmt, column) == SQLITE_TEXT);
                            cstrvalue = (char*)sqlite3_column_text(stmt, column++);
                            if(cstrvalue)
                                cstrvalue = strdup(cstrvalue);
                            if (i==0) {
                                object = dbsimple__getobject(&session->basesession, OBJCLEAN, field->def, 0, cstrvalue);
                            }
                            if(field->fieldoffset >= 0)
                                *(char**)&(object->data[field->fieldoffset]) = cstrvalue;
                            break;
                        case dbsimple_REFERENCE:
                            targetkeyid = 0;
                            targetkeystr = NULL;
                            if(sqlite3_column_type(stmt, column) != SQLITE_NULL) {
                                if((targetdef->flags & dbsimple_FLAG_SINGLETON) != dbsimple_FLAG_SINGLETON) {
                                    switch(targetdef->fields[0].type) {
                                        case dbsimple_INT:
                                        case dbsimple_UINT:
                                            assert(sqlite3_column_type(stmt, column) == SQLITE_INTEGER);
                                            targetkeyid = sqlite3_column_int(stmt, column++);
                                            break;
                                        case dbsimple_LONGINT:
                                        case dbsimple_ULONGINT:
                                            assert(sqlite3_column_type(stmt, column) == SQLITE_INTEGER);
                                            targetkeyid = sqlite3_column_int64(stmt, column++);
                                            break;
                                        case dbsimple_STRING:
                                            assert(sqlite3_column_type(stmt, column) == SQLITE_TEXT);
                                            targetkeystr = strdup((char*)sqlite3_column_text(stmt, column++));
                                            break;
                                        default:
                                            abort();
                                    }
                                } else
                                    abort();
                                dbsimple__assignreference(&session->basesession, field, targetkeyid, targetkeystr, object);
                            } else {
                                ++column;
                                *(void**)&(object->data[field->fieldoffset]) = NULL;
                            }
                            break;
                        case dbsimple_BACKREFERENCE:
                            targetkeyid = 0;
                            targetkeystr = NULL;
                            if((targetdef->flags & dbsimple_FLAG_SINGLETON) != dbsimple_FLAG_SINGLETON) {
                                if(sqlite3_column_type(stmt, column) != SQLITE_NULL) {
                                    switch(targetdef->fields[0].type) {
                                        case dbsimple_INT:
                                        case dbsimple_UINT:
                                            assert(sqlite3_column_type(stmt, column) == SQLITE_INTEGER);
                                            targetkeyid = sqlite3_column_int(stmt, column++);
                                            break;
                                        case dbsimple_LONGINT:
                                        case dbsimple_ULONGINT:
                                            assert(sqlite3_column_type(stmt, column) == SQLITE_INTEGER);
                                            targetkeyid = sqlite3_column_int64(stmt, column++);
                                            break;
                                        case dbsimple_STRING:
                                            assert(sqlite3_column_type(stmt, column) == SQLITE_TEXT);
                                            targetkeystr = strdup((char*)sqlite3_column_text(stmt, column++));
                                            break;
                                        default:
                                            abort();
                                    }
                                    dbsimple__assignbackreference(&session->basesession, field->def, targetkeyid, targetkeystr, &(*def)->fields[i], object);
                                } else {
                                    ++column;
                                }
                            } else {
                                dbsimple__assignbackreference(&session->basesession, field->def, targetkeyid, targetkeystr, &(*def)->fields[i], object);
                            }
                            break;
                        case dbsimple_MASTERREFERENCES:
                        case dbsimple_STUBREFERENCES:
                        case dbsimple_OPENREFERENCES:
                            break;
                        default:
                            abort();
                    }
                }
                break;
            case SQLITE_DONE:
                return;
            case SQLITE_BUSY:
                sleep(1);
                break;
            case SQLITE_ERROR:
                reportError(handle, "error");
                return;
            case SQLITE_MISUSE:
                reportError(handle, "misuse");
                return;
            default:
                break;
        }
    } while(status==SQLITE_BUSY||status==SQLITE_ROW);
    sqlite3_reset(stmt);
}

static int
bindstatement(dbsimple_session_type session, sqlite3_stmt* stmt, struct object* object, int style)
{
    int column = 0;
    int intvalue;
    long longvalue;
    const char* cstrvalue;
    struct object* targetobj;
    void* targetptr;
    struct dbsimple_fieldimpl* field;
    struct dbsimple_definitionimpl* type;

    sqlite3_clear_bindings(stmt);
    sqlite3_reset(stmt);
    column = 0;
    type = *(object->type);
    for(int i = 0; i<type->nfields; i++) {
        if(style == 0) {
            if((type->flags & dbsimple_FLAG_HASREVISION) ? i>=2 : i>=1)
                break;
            field = &type->fields[i];
        } else if(style == -1) {
            if(i+2<type->nfields)
                field = &type->fields[i+2];
            else
                field = &type->fields[i-(type->nfields-2)];
        } else {
            field = &type->fields[i];
        }
        switch(field->type) {
            case dbsimple_INT:
            case dbsimple_UINT:
                switch(i) {
                    case 0:
                        intvalue = object->keyid;
                        break;
                    case 1:
                        if(type->flags & dbsimple_FLAG_HASREVISION) {
                            intvalue = object->revision;
                            break;
                        }
                        /* else deliberate fall through */
                        // fall through
                    default:
                        intvalue = *(int*)&(object->data[field->fieldoffset]);
                }
                sqlite3_bind_int(stmt, ++column, intvalue);
                break;
            case dbsimple_LONGINT:
            case dbsimple_ULONGINT:
                switch(i) {
                    case 0:
                        longvalue = object->keyid;
                        break;
                    case 1:
                        if(type->flags & dbsimple_FLAG_HASREVISION) {
                            longvalue = object->revision;
                            break;
                        }
                        /* else deliberate fall through */
                        // fall through
                    default:
                        longvalue = *(long*)&(object->data[field->fieldoffset]);
                }
                sqlite3_bind_int64(stmt, ++column, longvalue);
                break;
            case dbsimple_STRING:
                switch(i) {
                    case 0:
                        cstrvalue = object->keyname;
                        break;
                    default:
                        cstrvalue = *(char**)&(object->data[field->fieldoffset]);
                }
                sqlite3_bind_text(stmt, ++column, cstrvalue, -1, SQLITE_STATIC);
                break;
            case dbsimple_REFERENCE:
                targetptr = *(void**)&(object->data[field->fieldoffset]);
                if(targetptr != NULL) {
                    targetobj = dbsimple__referencebyptr(&session->basesession, field->def, targetptr);
                    if(targetobj->keyname) {
                        cstrvalue = targetobj->keyname;
                        sqlite3_bind_text(stmt, ++column, cstrvalue, -1, SQLITE_STATIC);
                    } else {
                        intvalue = targetobj->keyid;
                        sqlite3_bind_int(stmt, ++column, intvalue);
                    }
                } else {
                    sqlite3_bind_null(stmt, ++column);
                }
                break;
            case dbsimple_BACKREFERENCE:
                break;
            case dbsimple_MASTERREFERENCES:
            case dbsimple_STUBREFERENCES:
            case dbsimple_OPENREFERENCES:
                break;
        }
    }
    return 0;
}

static int
persistobject(struct object* object, dbsimple_session_type session)
{
    int affected = -1;
    sqlite3_stmt* insertStmt = getStmtInsert(session, object->type);
    sqlite3_stmt* deleteStmt = getStmtDelete(session, object->type);
    switch(object->state) {
        case OBJNULL:
            assert(!"internal error");
        case OBJUNKNOWN:
            if(object->data) {
                assert(!"internal error");
            }
            break;
        case OBJCLEAN:
            break;
        case OBJNEW:
            object->revision = 1;
            object->keyid = random();
            bindstatement(session, insertStmt, object, 1);
            affected = eatResult(session->handle, insertStmt, NULL);
            break;
        case OBJMODIFIED:
            bindstatement(session, deleteStmt, object, 0);
            affected = eatResult(session->handle, deleteStmt, NULL);
            object->revision += 1;
            bindstatement(session, insertStmt, object, 1);
            eatResult(session->handle, insertStmt, NULL);
            break;
        case OBJREMOVED:
            bindstatement(session, deleteStmt, object, 0);
            affected = eatResult(session->handle, deleteStmt, NULL);
            object->data = NULL;
            if(affected != 1)
                return -1;
            break;
    }
    return 0; /* continue */
}

static int
commitdata(dbsimple_session_type session)
{
    int affected;
    struct object* object;
    sqlite3_reset(session->beginStmt);
    eatResult(session->handle, session->beginStmt, NULL);

    for(int i=0; i<session->currentPlan->ndefinitions; i++) {
        if((session->currentPlan->definitions[i]->flags & dbsimple_FLAG_SINGLETON) == dbsimple_FLAG_SINGLETON) {
            object = dbsimple__getobject(&session->basesession, OBJNULL, &(session->currentPlan->definitions[i]), 0, NULL);
            assert(object && object->data);
            dbsimple__committraverse(&session->basesession, object);
        }
    }
    dbsimple__commit(&session->basesession);

    sqlite3_reset(session->commitStmt);
    affected = eatResult(session->handle, session->commitStmt, NULL);

    return 0;
}

static void
disposecurrent(dbsimple_session_type session)
{
    if(session->currentStmts) {
        for(int i=0; i<(session->currentPlan->ndefinitions+1)*3; i++) {
            if(session->currentStmts[i])
                sqlite3_finalize(session->currentStmts[i]);
        }
        free(session->currentStmts);
        session->currentStmts = NULL;
    }
}

static int
openconnection(char* location, int nfetchplans, dbsimple_fetchplan_array fetchplans, dbsimple_connection_type* connectionPtr)
{
    int returnCode = 0;
    int errorCode;
    sqlite3* handle;
    /* :memory: */
    if (SQLITE_OK != (errorCode = sqlite3_open_v2(location, &handle, SQLITE_OPEN_READWRITE|SQLITE_OPEN_URI|SQLITE_OPEN_CREATE, NULL))) {
        reportError(handle, "error opening database");
        connectionPtr = NULL;
        returnCode = -2;
        if(errorCode != SQLITE_CANTOPEN)
            return -3;
    }
    (void)fetchplans;
    (void)nfetchplans;

    *connectionPtr = malloc(sizeof(struct dbsimple_connection_struct));
    (*connectionPtr)->handle = handle;
    return returnCode;
}

static int
closeconnection(dbsimple_connection_type connection)
{
    sqlite3_db_release_memory(connection->handle);
    sqlite3_close(connection->handle);
    free(connection);
    return 0;
}

static int
opensession(dbsimple_connection_type connection, dbsimple_session_type* sessionPtr)
{
    int returnCode = 0;
    int errorCode;
    sqlite3_stmt* beginStmt;
    sqlite3_stmt* commitStmt;
    sqlite3_stmt* rollbackStmt;
    const char* beginQuery = "BEGIN TRANSACTION";
    const char* commitQuery = "COMMIT";
    const char* rollbackQuery = "ROLLBACK";

    if(SQLITE_OK != (errorCode = sqlite3_prepare_v2(connection->handle, beginQuery, strlen(beginQuery)+1, &beginStmt, NULL))) {
        reportError(connection->handle, "");
        returnCode = 1;
    }
    if(SQLITE_OK != (errorCode = sqlite3_prepare_v2(connection->handle, commitQuery, strlen(commitQuery)+1, &commitStmt, NULL))) {
        reportError(connection->handle, "");
        returnCode = 1;
    }
    if(SQLITE_OK != (errorCode = sqlite3_prepare_v2(connection->handle, rollbackQuery, strlen(rollbackQuery)+1, &rollbackStmt, NULL))) {
        reportError(connection->handle, "");
        returnCode = 1;
    }

    *sessionPtr = malloc(sizeof(struct dbsimple_session_struct));
    (*sessionPtr)->connection = connection;
    (*sessionPtr)->handle = connection->handle;
    (*sessionPtr)->beginStmt = beginStmt;
    (*sessionPtr)->commitStmt = commitStmt;
    (*sessionPtr)->rollbackStmt = rollbackStmt;
    (*sessionPtr)->currentStmts = NULL;
    return returnCode;
}

static int
closesession(dbsimple_session_type session)
{
    disposecurrent(session);
    sqlite3_finalize(session->beginStmt);
    sqlite3_finalize(session->commitStmt);
    sqlite3_finalize(session->rollbackStmt);
    free(session);
    return 0;
}

static int
syncdata(dbsimple_session_type session, struct dbsimple_fetchplan_struct* fetchplan, void* data)
{
    int qindex;
    int nqueries = 0;
    sqlite3_stmt* stmt;
    while(fetchplan->queries[nqueries])
        ++nqueries;
    session->currentPlan  = fetchplan;
    disposecurrent(session);
    session->currentStmts = malloc(sizeof(sqlite3_stmt*) * (fetchplan->ndefinitions+1) * 3);
    session->currentStmts[0] = NULL;
    session->currentStmts[1] = NULL;
    session->currentStmts[2] = NULL;
    qindex = 3; // skip the first set
    for(int i=0; i<nqueries && qindex<(fetchplan->ndefinitions+1)*3; i++,qindex++) {
        if(SQLITE_OK != sqlite3_prepare_v2(session->handle, fetchplan->queries[i], strlen(fetchplan->queries[i])+1, &stmt, NULL)) {
            reportError(session->handle, "");
            while(qindex-- > 0) {
                if(session->currentStmts[qindex])
                    sqlite3_finalize(session->currentStmts[qindex]);
            }
            free(session->currentStmts);
            session->currentStmts = NULL;
            return -1;
        } else {
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
            // sqlite3_bind_text(stmt, 1, arg, -1, SQLITE_STATIC);
            session->currentStmts[qindex] = stmt;
            eatResult(session->handle, session->currentStmts[qindex], data);
        }
    }
    for(; qindex < (fetchplan->ndefinitions+1)*3; qindex++)
            session->currentStmts[qindex] = NULL;
    return 0;
}

static void*
fetchdata(dbsimple_session_type session, struct dbsimple_fetchplan_struct* fetchplan, __attribute__((unused))  va_list args)
{
    int qindex;
    int nqueries = 0;
    sqlite3_stmt* stmt;
    while(fetchplan->queries[nqueries])
        ++nqueries;
    disposecurrent(session);
    session->currentPlan  = fetchplan;
    session->currentStmts = malloc(sizeof(sqlite3_stmt*) * (fetchplan->ndefinitions+1) * 3);
    session->currentStmts[0] = NULL;
    session->currentStmts[1] = NULL;
    session->currentStmts[2] = NULL;
    qindex = 3; // skip the first set
    if(nqueries > fetchplan->ndefinitions * 3)
        nqueries = fetchplan->ndefinitions * 3;
    for(int i=0; i<nqueries; i++,qindex++) {
        if(SQLITE_OK != sqlite3_prepare_v2(session->handle, fetchplan->queries[i], strlen(fetchplan->queries[i])+1, &stmt, NULL)) {
            reportError(session->handle, "Unable to build query");
            while(i-- > 0) {
                if(session->currentStmts[qindex])
                    sqlite3_finalize(session->currentStmts[qindex]);
            }
            free(session->currentStmts);
            session->currentStmts = NULL;
            return NULL;
        } else {
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
            session->currentStmts[qindex] = stmt;
        }
    }
    for(; qindex < (fetchplan->ndefinitions+1)*3; qindex++)
            session->currentStmts[qindex] = NULL;
    return dbsimple__fetch(&session->basesession, fetchplan->ndefinitions, fetchplan->definitions);
}

#endif
