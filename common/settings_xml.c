#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <libxml/xpath.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>
#include "utilities.h"
#define settings__INTERNAL
typedef xmlDocPtr document_type;
typedef xmlXPathObjectPtr node_type;
#include "settings.h"

static void
composestr(char*staticstr, int staticlen, char** str, int* len, const char* appendstr)
{
    int appendlen;
    int newlen;

    if(*str == NULL) {
        *str = staticstr;
        *len = 0;
        **str = '\0';
    } else if(len == NULL) {
        free(*str);
        return;
    } else if(!appendstr) {
        return;
    }

    appendlen = strlen(appendstr);
    if((*len / staticlen) * staticlen + appendlen + 1 >= staticlen) {
        newlen = *len + appendlen + staticlen;
        newlen = (newlen / staticlen) * staticlen;
        if(alloc(str, 1, NULL, newlen))
            abort();
    }
    strncat(*str, appendstr, appendlen+1);
    *len += appendlen;
}

static void
composenstr(char*staticstr, int staticlen, char** str, int* len, const char* appendstr, int appendlen)
{
    int newlen;

    if(*str == NULL) {
        *str = staticstr;
        *len = 0;
        **str = '\0';
    } else if(len == NULL) {
        free(*str);
        return;
    } else if(!appendstr) {
        return;
    }

    if((*len / staticlen) * staticlen + appendlen + 1 >= staticlen) {
        newlen = *len + appendlen + staticlen;
        newlen = (newlen / staticlen) * staticlen;
        if(alloc(str, 1, NULL, newlen))
            abort();
    }
    strncat(*str, appendstr, appendlen);
    *len += appendlen;
}

static void
composestrf(char*staticstr, int staticlen, char** str, int* len, const char* fmt, ...)
{
    va_list ap;
    int appendlen;
    int newlen;

    if(*str == NULL) {
        *str = staticstr;
        *len = 0;
        **str = '\0';
    } else if(len == NULL) {
        free(*str);
        return;
    } else if(!fmt) {
        return;
    }

    va_start(ap, fmt);
    appendlen = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if((*len / staticlen) * staticlen + appendlen + 1 >= staticlen) {
        newlen = *len + appendlen + staticlen;
        newlen = (newlen / staticlen) * staticlen;
        if(alloc(str, 1, NULL, newlen))
            abort();
    }
    va_start(ap, fmt);
    vsnprintf(&(*str)[*len], appendlen+1, fmt, ap);
    va_end(ap);
    *len += appendlen;
}

node_type
settings__parselocate_xml(document_type document, node_type node, const char* fmt, va_list ap, const char** lastp)
{
    int len;
    int intvalue;
    char* strvalue;
    char strbuf[1024];
    char* path = NULL;
    int pathlen;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    enum { START, NEXT } state = START;
    composestr(strbuf, sizeof(strbuf), &path, &pathlen, "");
    if (fmt == NULL) {
        if((strvalue = va_arg(ap, char*))) {
            composestr(strbuf, sizeof(strbuf), &path, &pathlen, "//");
            composestr(strbuf, sizeof(strbuf), &path, &pathlen, strvalue);
            while((strvalue = va_arg(ap, char*))) {
                composestr(strbuf, sizeof(strbuf), &path, &pathlen, "/");
                composestr(strbuf, sizeof(strbuf), &path, &pathlen, strvalue);
            }
        } else {
            return NULL;
        }
    } else if (fmt[0] == '/') {
        vasprintf(&path, fmt, ap);
    } else {
        if(node == NULL)
            composestr(strbuf, sizeof(strbuf), &path, &pathlen, "/");
        while(*fmt) {
            if(*fmt == '.' || *fmt == '/') {
                ++fmt;
            } else if (!strncmp(fmt, "%s", 2)) {
                strvalue = va_arg(ap, char*);
                if (strvalue != NULL) {
                    if(state == NEXT)
                        composestr(strbuf, sizeof(strbuf), &path, &pathlen, "/");
                    composestr(strbuf, sizeof(strbuf), &path, &pathlen, strvalue);
                    state = NEXT;
                }
                fmt += 2;
            } else if (!strncmp(fmt, "%d", 2)) {
                intvalue = va_arg(ap, int);
                composestrf(strbuf, sizeof(strbuf), &path, &pathlen, "[%d]", intvalue + 1);
                state = NEXT;
                fmt += 2;
            } else {
                for (len=0; fmt[len]; len++)
                    if (fmt[len] == '.' || fmt[len] == '/')
                        break;
                if(state == NEXT)
                    composestr(strbuf, sizeof(strbuf), &path, &pathlen, "/");
                composenstr(strbuf, sizeof(strbuf), &path, &pathlen, fmt, len);
                state = NEXT;
                fmt += len;
            }
        }
    }

    xpathCtx = xmlXPathNewContext(document);
    xpathObj = xmlXPathEvalExpression((unsigned char*)path, xpathCtx);
    if (xpathObj == NULL || xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr <= 0) {
        node = NULL;
    } else {
        node = xpathObj;
    }
    if(xpathCtx)
        xmlXPathFreeContext(xpathCtx);
    *lastp = NULL;
    return node;
}

char*
settings__getscalar_xml(node_type node)
{
    return strdup((const char*) xmlXPathCastToString(node));
}

int
settings__nodecount_xml(node_type node)
{
    return node->nodesetval->nodeNr;
}

document_type
settings__access_xml(document_type olddocument, int fd)
{
    xmlDocPtr document = NULL;
    if(olddocument) {
        xmlFreeDoc(olddocument);
    }
    document = xmlReadFd(fd, "xml", NULL, 0);
    return document;
}
