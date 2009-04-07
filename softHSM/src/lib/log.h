/* $Id$ */

/*
 * Copyright (c) 2008-2009 .SE (The Internet Infrastructure Foundation).
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

#ifndef SOFTHSM_LOG_H
#define SOFTHSM_LOG_H 1

// The log levels
#define SOFTERROR 1
#define SOFTWARNING 2
#define SOFTINFO 3
#define SOFTDEBUG 4

#if SOFTLOGLEVEL >= SOFTERROR
#define ERROR_MSG(func, text) logError(func, text);
#else
#define ERROR_MSG(func, text)
#endif

#if SOFTLOGLEVEL >= SOFTWARNING
#define WARNING_MSG(func, text) logWarning(func, text);
#else
#define WARNING_MSG(func, text)
#endif

#if SOFTLOGLEVEL >= SOFTINFO
#define INFO_MSG(func, text) logInfo(func, text);
#else
#define INFO_MSG(func, text)
#endif

#if SOFTLOGLEVEL >= SOFTDEBUG
#define DEBUG_MSG(func, text) logDebug(func, text);
#else
#define DEBUG_MSG(func, text)
#endif

#define CHECK_DEBUG_RETURN(exp, func, text, retVal) \
  if(exp) { \
    DEBUG_MSG(func, text); \
    return retVal; \
  }

void logError(const char *functionName, const char *text);
void logWarning(const char *functionName, const char *text);
void logInfo(const char *functionName, const char *text);
void logDebug(const char *functionName, const char *text);

#endif /* SOFTHSM_LOG_H */
