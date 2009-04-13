/*+
 * debug.c - Debug Routines
 *
 * Description:
 *      Contains functions used to produce debug output.
 *
 *      Debug information is controlled by the debug bitmask.  Different items
 *      of debug information are controlled by the different bits, so setting or
 *      clearing those bits controls what information is output.
 *
 * Copyright:
 *      Copyright 2008 Nominet
 *      
 * Licence:
 *      Licensed under the Apache Licence, Version 2.0 (the "Licence");
 *      you may not use this file except in compliance with the Licence.
 *      You may obtain a copy of the Licence at
 *      
 *          http://www.apache.org/licenses/LICENSE-2.0
 *      
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the Licence is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the Licence for the specific language governing permissions and
 *      limitations under the Licence.
-*/

#include <stdarg.h>
#include <stdio.h>

#include "debug.h"
#include "message.h"

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
