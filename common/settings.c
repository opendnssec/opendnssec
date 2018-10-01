/*
 * Copyright (c) 2018 NLNet Labs.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <yaml.h>
#include "duration.h"
#include "settings.h"

static ods_cfg_handle defaulthandle = NULL;

static yaml_node_t*
parselocate(yaml_document_t *document, yaml_node_t *node, const char* fmt, va_list ap, const char** lastp)
{
    char* arg;
    yaml_node_pair_t* nodepair;
    yaml_node_item_t* nodeitem;
    yaml_node_t* child;
    if (fmt == NULL) {
        do {
            arg = va_arg(ap, char*);
            *lastp = arg;
            if (arg != NULL) {
                if (node && node->type == YAML_MAPPING_NODE) {
                    for (nodepair = node->data.mapping.pairs.start; nodepair < node->data.mapping.pairs.top; nodepair++) {
                        child = yaml_document_get_node(document, nodepair->key);
                        if (child && child->type == YAML_SCALAR_NODE) {
                            if (!strncmp(arg, child->data.scalar.value, child->data.scalar.length) && child->data.scalar.length == strlen(arg)) {
                                break;
                            }
                        }
                    }
                    if (nodepair < node->data.mapping.pairs.top) {
                        child = yaml_document_get_node(document, nodepair->value);
                        if (child) {
                            node = child;
                        } else {
                            return NULL;
                        }
                    } else {
                        return NULL;
                    }
                }
            }
        } while (arg != NULL);
        return node;
    }
    return NULL;
}

static int
parsefunclong(void* user, const char* str, void* resultvalue)
{
    char* end;
    long* resultlong = (long*) resultvalue;
    errno = 0;
    *resultlong = strtol(str, &end, 0);
    if (errno) {
        return 1;
    } else {
        return 0;
    }
}


static int
parsefunccount(void* user, const char* str, void* resultvalue)
{
    char* end;
    long* resultlong = (long*) resultvalue;
    errno = 0;
    if(*str == '#') {
        ++str;
        while(isspace(*str))
            ++str;
    }
    *resultlong = strtol(str, &end, 0);
    if (errno) {
        return 1;
    } else {
        return 0;
    }
}


static int
parsefuncperiod(void* user, const char* str, void* resultvalue)
{
    duration_type* duration = duration_create_from_string(str);
    if (duration) {
        time_t period = duration2time(duration);
        duration_cleanup(duration);
        *(time_t*)resultvalue = period;
        return 0;
    } else
        return 1;
}

static int
parsescalar(yaml_document_t *document, size_t resultsize, void* resultvalue, void* defaultvalue, int (*parsefunc)(void*,const char*,void*), void* parsedata, const char* fmt, va_list ap)
{
    int len;
    const char* last = "unknown";
    const char* str;
    int result;
    yaml_node_t* root;
    yaml_node_t* node;
    root = (document ? yaml_document_get_root_node(document) : NULL);
    node = parselocate(document, root, fmt, ap, &last);
    if (node) {
        if (node->type == YAML_SCALAR_NODE) {
            str = (const char*)node->data.scalar.value;
            for (len = 0; len < node->data.scalar.length && isspace(str[len]); len++)
                ;
            str = &str[len];
            len = node->data.scalar.length - len;
            while(len > 0 && isspace(str[len]))
                --len;
            str = strndup(str, len);
            if(parsefunc(parsedata,str,resultvalue)) {
                if (defaultvalue)
                    memcpy(resultvalue,defaultvalue,resultsize);
                fprintf(stderr,"in configuration parameter %s unable unparseable input %s\n",last,str);
                result = -1;
            } else {
                result = 0;
            }
            free(str);
        } else {
            fprintf(stderr,"in configuration parameter %s unable to parse argument\n",last);
            if (defaultvalue)
                memcpy(resultvalue,defaultvalue,resultsize);
            result = -1;
        }
    } else {
        if (defaultvalue) {
            memcpy(resultvalue,defaultvalue,resultsize);
            result = 0;
        } else {
            fprintf(stderr,"in configuration parameter %s argument not found\n",last);
            result = 1;
        }
    }
    return result;
}

int
ods_cfg_access(ods_cfg_handle* handleptr, const char* filename)
{
    FILE *input;
    yaml_parser_t parser;
    yaml_document_t* document;
    if(handleptr == NULL) {
        if(defaulthandle) {
            yaml_document_delete((yaml_document_t*)defaulthandle);
            free((void*)defaulthandle);
            defaulthandle = NULL;
        }
        handleptr = &defaulthandle;
    } else if(filename == NULL && *handleptr == NULL) {
        yaml_document_delete((yaml_document_t*)*handleptr);
    }
    
    yaml_parser_initialize(&parser);
    input = fopen(filename, "r");
    if(input) {
        yaml_parser_set_input_file(&parser, input);
        document = malloc(sizeof(yaml_document_t));
        yaml_parser_load(&parser, document);
        yaml_parser_delete(&parser);
        fclose(input);
    } else
        document = NULL;
    *handleptr = document;
    return 0;
}

int
ods_cfg_getlong(ods_cfg_handle handle, long* resultvalue, long* defaultvalue, const char* fmt, ...)
{
    int rc;
    va_list ap;
    yaml_document_t* document = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(document, sizeof(long), resultvalue, defaultvalue, parsefunclong, NULL, fmt, ap);
    va_end(ap);
    return rc;
}

int
ods_cfg_getcount(ods_cfg_handle handle, long* resultvalue, long* defaultvalue, const char* fmt, ...)
{
    int rc;
    va_list ap;
    yaml_document_t* document = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(document, sizeof(long), resultvalue, defaultvalue, parsefunccount, NULL, fmt, ap);
    va_end(ap);
    return rc;
}

int
ods_cfg_getperiod(ods_cfg_handle handle, long* resultvalue, long* defaultvalue, const char* fmt, ...)
{
    int rc;
    va_list ap;
    yaml_document_t* document = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(document, sizeof(long), resultvalue, defaultvalue, parsefunccount, NULL, fmt, ap);
    va_end(ap);
    return rc;
}
