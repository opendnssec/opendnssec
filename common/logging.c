/*
 * Copyright (c) 2016 NLNet Labs. All rights reserved.
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
 *
 */

/*
 * class: a logging category or class, a logical container.  Often synonimous with source code module.
 * level: logging level
 * message: a human consumable message
 * 
 * source file
source line
source function
source operation
result status
result description
logical resource
logical operation

*/

#include <stdio.h>
#include <stdarg.h>
#include <limits.h>

static char* alertbuffer[1024];

static void alertinteger(unsigned long value, int base);
void alert(const char *format, ...);

static void
alertinteger(unsigned long value, int base)
{
    char ch;
    if (value > base - 1)
        alertinteger(value / base, base);
    ch = "0123456789abcdef"[value % base];
    (void) write(2, &ch, 1);
}

void
alert(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int startidx, currentidx, len;
    const char* stringarg;
    void* pointerarg;
    int integerarg;
    long longarg;
    startidx = 0;
    while (format[startidx]) {
        currentidx = startidx;
        while (format[currentidx] && format[currentidx] != '%')
            ++currentidx;
        if (currentidx - startidx > 0)
            (void)write(2, &format[startidx], currentidx - startidx);
        if (format[currentidx] == '%') {
            switch (format[currentidx + 1]) {
                case '%':
                    (void) write(2, "%", 1);
                    currentidx += 2;
                    break;
                case 's':
                    stringarg = va_arg(args, char*);
                    if (stringarg == NULL)
                        stringarg = "(null)";
                    len = strlen(stringarg);
                    (void) write(2, stringarg, len);
                    currentidx += 2;
                    break;
                case 'p':
                    pointerarg = va_arg(args, void*);
                    if (pointerarg == NULL) {
                        stringarg = "(null)";
                        len = strlen(stringarg);
                        (void) write(2, stringarg, len);
                    } else {
                        (void) write(2, "0x", 2);
                        alertinteger((unsigned long) pointerarg, 16);
                    }
                    currentidx += 2;
                    break;
                case 'l':
                    switch (format[currentidx + 2]) {
                        case 'd':
                            longarg = va_arg(args, long);
                            if (longarg < 0) {
                                (void) write(2, "-", 1);
                                alertinteger(1UL + ~((unsigned long) longarg), 10);
                            } else
                                alertinteger(longarg, 10);
                            currentidx += 3;
                            break;
                        default:
                            (void) write(2, &format[startidx], 2);
                            currentidx += 2;
                    }
                    break;
                case 'd':
                    integerarg = va_arg(args, int);
                    alertinteger((long) integerarg, 10);
                    currentidx += 2;
                    break;
                case '\0':
                    (void) write(2, "%", 1);
                    currentidx += 1;
                    break;
                default:
                    (void) write(2, &format[startidx], 2);
                    currentidx += 2;
            }
        }
        startidx = currentidx;
    }
    va_end(args);
}

#ifdef NOTDEFINED
LOG_CONS

struct { const char* facilityname, facilityid } syslogfacilities[] = {
{ "auth", LOG_AUTH },
{ "authpriv", LOG_AUTHPRIV },
{ "cron", LOG_CRON },
{ "daemon", LOG_DAEMON },
{ "ftp", LOG_FTP },
{ "kern", LOG_KERN },
{ "local0", LOG_LOCAL0 },
{ "local1", LOG_LOCAL1 },
{ "local2", LOG_LOCAL2 },
{ "local3", LOG_LOCAL3 },
{ "local4", LOG_LOCAL4 },
{ "local5", LOG_LOCAL5 },
{ "local6", LOG_LOCAL6 },
{ "local7", LOG_LOCAL7 },
{ "lpr", LOG_LPR },
{ "mail", LOG_MAIL },
{ "news", LOG_NEWS },
{ "syslog", LOG_SYSLOG },
{ "user", LOG_USER },
{ "uucp", LOG_UUCP },
{ NULL, -1 }
};

int[] sysloglevels = {
LOG_EMERG
LOG_ALERT
LOG_CRIT
LOG_ERR
LOG_WARNING
LOG_NOTICE
LOG_INFO
LOG_DEBUG
#endif

struct salertbuffer {
    char buffer[1024];
    int index;
};

static int inline
salertbuffer(struct salertbuffer* buffer, int ch)
{
    return 0;
}

static void
salertinteger(struct salertbuffer* buffer, int** left, unsigned long value, int base)
{
    char ch;
    if (value > base - 1)
        alertinteger(value / base, base);
    ch = "0123456789abcdef"[value % base];
    (void) write(2, &ch, 1);
}

void
salert(char** buffer, int** left, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int idx, len;
    const char* stringarg;
    void* pointerarg;
    int integerarg;
    long longarg;
    idx = 0;
    while (format[idx]) {
        if (format[idx] == '%') {
            switch (format[idx + 1]) {
                case '%':
                    output(buffer, '%');
                    idx += 2;
                    break;
                case 's':
                    stringarg = va_arg(args, char*);
                    if (stringarg == NULL)
                        stringarg = "(null)";
                    while(stringarg)
                        if(output(buffer, *(stringarg++)))
                            break;
                    idx += 2;
                    break;
                case 'p':
                    pointerarg = va_arg(args, void*);
                    if (pointerarg == NULL) {
                        stringarg = "(null)";
                        while(stringarg)
                            (void)output(buffer, *(stringarg++));
                    } else {
                        (void)output('0');
                        (void)output('x');
                        alertinteger((unsigned long) pointerarg, 16);
                    }
                    idx += 2;
                    break;
                case 'l':
                    switch (format[idx + 2]) {
                        case 'd':
                            longarg = va_arg(args, long);
                            if (longarg < 0) {
                                (void)output(buffer,'-');
                                alertinteger(1UL + ~((unsigned long) longarg), 10);
                            } else
                                alertinteger(longarg, 10);
                            idx += 3;
                            break;
                        case '\0':
                            (void)output(buffer,format[idx++]);
                            break;
                        default:
                            (void)output(buffer,format[idx++]);
                            (void)output(buffer,format[idx++]);
                    }
                    break;
                case 'd':
                    integerarg = va_arg(args, int);
                    alertinteger((long) integerarg, 10);
                    idx += 2;
                    break;
                case '\0':
                    (void)output(buffer,'%');
                    idx += 1;
                    break;
                default:
                    (void)output(buffer,format[idx++]);
                    (void)output(buffer,format[idx++]);
                    idx += 2;
            }
        } else {
            output(buffer, &format[idx++]);
        }
    }
    va_end(args);
}
