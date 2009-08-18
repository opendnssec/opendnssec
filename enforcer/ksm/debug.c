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

/*+
 * debug.c - Debug Routines
 *
 * Description:
 *      Contains functions used to produce debug output.
 *
 *      Debug information is controlled by the debug bitmask.  Different items
 *      of debug information are controlled by the different bits, so setting or
 *      clearing those bits controls what information is output.
-*/

#include <stdarg.h>
#include <stdio.h>

#include "ksm/debug.h"
#include "ksm/message.h"

/* Bitmask of debug flags */

static unsigned int m_debug = 0;

/*+
 * DbgGet - Get Debug Bitmask
 *
 * Description:
 *      Returns the current value of the debug bitmask.
 *
 * Returns:
 *      unsigned int
 *          Current value of the debug bitmask.
-*/

unsigned int DbgGet(void)
{
    return m_debug;
}



/*+
 * DbgSet - Set Debug Bitmask
 *
 * Description:
 *      Sets the debug bitmask to the given value.
 *
 * Input:
 *      unsigned int mask
 *          New bitmask value.
 *
 * Returns:
 *      unsigned int
 *          Previous setting of the debug bitmask.
-*/

unsigned int DbgSet(unsigned int mask)
{
    unsigned int oldmask;
    
    oldmask = m_debug;
    m_debug = mask;
    return oldmask;
}


/*+
 * DbgIsSet - Is Debug Bit Set?
 *
 * Description:
 *      Checks if any of the bits in the passed bitmask are also set in the
 *      current debug bitmask.
 *
 * Arguments:
 *      unsigned int mask
 *          Bitmask to test.
 *
 * Returns:
 *      int
 *          1 if any of the bits in the mask are set.
 *          0 if none of them are set.
-*/

int DbgIsSet(unsigned int flags)
{
    return (flags & m_debug);
}



/*+
 * DbgOutput - Output Debug Message
 *
 * Description:
 *      Outputs a debug message to stdout if one or more of the bits in the
 *      given bitmask is also set in the debug bit mask.  If no bits are set,
 *      the function is a no-op.
 *
 * Arguments:
 *      unsigned int mask
 *          Only output the text if one or more of the bits in this bitmask is
 *          also set in the debug bitmask.
 *
 *      const char* format
 *          printf()-style format string for the message.
 *
 *      ...
 *          Arguments for the format string
-*/

void DbgOutput(unsigned int mask, const char* format, ...)
{
    va_list ap;

    if (DbgIsSet(mask)) {
        va_start(ap, format);
        printf("DEBUG: ");
        vprintf(format, ap);
        va_end(ap);
    }

    return;
}


/*+
 * DbgLog - Output Debug Message
 *
 * Description:
 *      Outputs a debug message via MsgLog if one or more of the bits in the
 *      given bitmask is also set in the debug bit mask.  If no bits are set,
 *      the function is a no-op.
 *
 * Arguments:
 *      unsigned int mask
 *          Only output the text if one or more of the bits in this bitmask is
 *          also set in the debug bitmask.
 *
 *      int status
 *      	Status code identifying the message to output.
 *
 *      ...
 *          Arguments for the format string
-*/

void DbgLog(unsigned int mask, int status, ...)
{
	va_list	ap;		/* variable arguments */

	if (DbgIsSet(mask)) {

		/* Must output the message, so get the arguments as a va_list */

		va_start(ap, status);
		MsgLogAp(status, ap);
		va_end(ap);
	}

	return;
}



/*+
 * DbgPrint - Unconditionally Print Debug Message
 *
 * Description:
 *      Outputs a debug message on stdout.
 *
 * Arguments:
 *      const char* format
 *          printf()-style format string for the message.
 *
 *      ...
 *          Arguments for the format string
-*/

void DbgPrint(const char* format, ...)
{
    va_list ap;

    va_start(ap, format);
    printf("DEBUG: ");
    vprintf(format, ap);
    va_end(ap);

    return;
}
