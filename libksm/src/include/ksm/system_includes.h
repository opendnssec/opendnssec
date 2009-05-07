/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

#ifndef SYSTEM_INCLUDES_H
#define SYSTEM_INCLUDES_H

/*+
 * Filename: system_includes.h
 *
 * Description:
 *      Between the Sun and Linux boxes, some definitions are in different
 *      files.  This includes file includes the set of system includes files
 *      used by the DAC/Whois programs that differ between the Sun and Linux
 *      systems.
-*/

#include <sys/socket.h>

#ifdef __sun

#include <sys/types.h>
#include <limits.h>
#include <xti_inet.h>

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif



#elif __APPLE__

#include <sys/types.h>
#include <limits.h>



#else   /* ... for Linux */

#include <stdint.h>

#ifndef AF_UNIX
#define AF_UNIX AF_LOCAL
#endif

#endif  /* __sun */

#endif  /* SYSTEM_INCLUDES_H */
