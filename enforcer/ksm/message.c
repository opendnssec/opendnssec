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
 * message.c - Message Functions
 *
 * Abstract:
 *      The message module outputs error messages to the stdout.
 *
 *      Modules register their message text and message code ranges with this
 *      module.  When invoked, this module searches all the registered code
 *      ranges for one containing the status code in question, and takes the
 *      appropriate action.
-*/

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ksm/message.h"
#include "ksm/string_util.h"

#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

MSG_CODEBLOCK*  m_codeblock = NULL;
int m_numblocks = 0;        /* Count of code blocks */



/*+
 * MsgInit - Initialize Message Processing
 *
 * Description:
 * 		Initialises the message module.
 *
 * Arguments:
 * 		None.
-*/

void MsgInit(void)
{
	m_codeblock = NULL;
	m_numblocks = 0;

	return;
}



/*+
 * MsgDefaultOutput
 *
 * Description:
 *      Default output function; outputs a line of text to stdout.
 *
 * Arguments:
 *      const char* text
 *          Text to output.
-*/

void MsgDefaultOutput(const char* text)
{
    printf("%s\n", text);

    return;
}



/*+
 * MsgNoOutput - Produce No Output
 *
 * Description:
 *      Null output function; does not output anything.
 *
 * Arguments:
 *      const char* text
 *          Text (not) to output.
-*/

void MsgNoOutput(const char* text)
{
    /* Unused parameter*/
    (void)text;

    return;
}



/*+
 * MsgRegister - Register Status Codes
 *
 * Description:
 *      Registers a block of status codes (and associated text) with the message
 *      module.
 *
 * Arguments:
 *      int min
 *          Minimum status code value in the range.
 *
 *      int max
 *          Maximum status code value in the range.
 *
 *      const char** message
 *          List of messages for each code.  message[0] corresponds to
 *          a value of "min", message 1 to "min + 1" etc.  There should be
 *          (max - min + 1) entries in this list.
 *
 *          If a message entry is NULL, default text will be used.
 *
 *      MSG_OUTPUT_FUNCTION output
 *          Output function used to output the text when MsgLog is called.
 *          If NULL, the default function (which outputs to stdout) will be
 *          used.
-*/

void MsgRegister(int min, int max, const char** message,
	MSG_OUTPUT_FUNCTION output)
{
    if (m_numblocks == 0) {
        m_codeblock = MemCalloc(1, sizeof(MSG_CODEBLOCK));
    }
    else {
        m_codeblock = MemRealloc(m_codeblock,
            (m_numblocks + 1) * sizeof(MSG_CODEBLOCK));
    }

	/*
	 * Fill in the code block.  On the principle of "being liberal with what
	 * you accept", allow the caller to get max and min confused.
	 */

    m_codeblock[m_numblocks].min = MIN(min, max);
    m_codeblock[m_numblocks].max = MAX(min, max);
    m_codeblock[m_numblocks].message = message;
    m_codeblock[m_numblocks].output = output ? output : MsgDefaultOutput;

    ++m_numblocks;

    return;
}



/*+
 * MsgFindCodeBlock - Find Code Block
 *
 * Description:
 *      Local function used to locate the code block for a particular status
 *      code.
 *
 * Arguments:
 *      int status
 *          Status code for which the block is sought.
 *
 * Returns:
 *      int
 *          Index into the code block array of the appropriate block, or -1
 *          if no block contains that status code.
-*/

int MsgFindCodeBlock(int status)
{
    int block = -1; /* Returned code block */
    int i;          /* Loop counter */

    for (i = 0; i < m_numblocks; ++i) {
        if ((status >= m_codeblock[i].min) && (status <= m_codeblock[i].max)) {
            block = i;
            break;
        }
    }

    return block;
}



/*+
 * MsgText - Return Error Message Text
 *
 * Description:
 *      Returns message text associated with the status code.
 *
 * Arguments:
 *      int status
 *          Status code.  If one of the registered message codes, the
 *          corresponding text will be returned, otherwise it will be the text
 *          returned by strerror.
 *
 * Returns:
 *      const char*
 *          Pointer to the message text.  This is a pointer to internal
 *          memory, and should not be modified or freed by the caller.
 *
 *          Note that this could be NULL if strerror() felt so inclined.
-*/

const char* MsgText(int status)
{
    int block;                      /* Code block associated with the message */
    const char* text = NULL;        /* Returned message */

    block = MsgFindCodeBlock(status);
    if (block >= 0) {
        text = m_codeblock[block].message[status - m_codeblock[block].min];
    }

    if (text == NULL) {
        text = strerror(status);
    }

    return text;
}



/*+
 * MsgGetOutput - Get Current Output Function
 *
 * Description:
 *      Returns the current output function for a particular status code range.
 *
 * Arguments:
 *      int status
 *          Status code within the specified range.
 *
 * Returns:
 *      MSG_OUTPUT_FUNCTION
 *          Pointer to the current output function.  NULL if the code is not
 *          recognised.
-*/

MSG_OUTPUT_FUNCTION MsgGetOutput(int status)
{
    int block;                          /* Block number */
    MSG_OUTPUT_FUNCTION output = NULL;	/* Returned function */

    /* Locate the output function */

    block = MsgFindCodeBlock(status);
    if (block != -1) {
        output = m_codeblock[block].output;
    }

    return output;
}



/*+
 * MsgSetOutput - Set Current Output Function
 *
 * Description:
 *      Sets the current output function for a particular status code range.
 *
 * Arguments:
 *      int status
 *          Status code within the specified range.
 *
 *      MSG_OUTPUT_FUNCTION output
 *          Output function.  If NULL, the default output function (which
 *          outputs to stdout) will be used.
-*/

void MsgSetOutput(int status, MSG_OUTPUT_FUNCTION output)
{
    int     block;                              /* Block number */

    /* Locate the output function */

    block = MsgFindCodeBlock(status);
    if (block != -1) {
        m_codeblock[block].output = output ? output : MsgDefaultOutput;
    }

    return;
}



/*+
 * MsgLog - Log Message
 *
 * Description:
 *      Obtains the message text, substitutes any parameters, and uses the
 *      output function associated with that status code to output it.
 *
 *      Note that it uses an internal buffer to expand the message, so there is
 *      a 4096-byte limit on the size of the message output.
 *
 * Arguments:
 *      int status
 *          Status code used to access a format string that is the used to
 *          format the remaining arguments.
 *
 *      ...
 *          Arguments for the format string.
 *
 * Returns:
 *      int
 *          Always identical to the status passed in.  This allows constructs
 *          of the form:
 *
 *              return MsgLog(error_number...)
 *
 *          ... which both reports the stored error and returns the error number
 *          to the caller.
 */

int MsgLog(int status, ...)
{
    va_list ap;             /* Variable arguments */
	int		retstat;		/* Return status */

	va_start(ap, status);
	retstat = MsgLogAp(status, ap);
	va_end(ap);

	return retstat;
}



/*+
 * MsgLogAp - Log Message With Variable Arguments
 *
 * Description:
 * 		See MsgLog.
 *
 * 		This function is used when the variable arguments are in the form of
 * 		a variable argument list.
 *
 * Arguments:
 *      int status
 *          Status code.  This is a format string that is used to format
 *          the remaining arguments.
 *
 *      va_list ap
 *          Arguments for the format
 *
 * Returns:
 *      int
 *      	See MsgLog.
 */

int MsgLogAp(int status, va_list ap)
{
    char    buffer[4096];   /* Buffer to store the text */
    const char* message;    /* Message string */
    MSG_OUTPUT_FUNCTION output = NULL;

    /* Locate the text for the message and use it to format the text */

    message = MsgText(status);
    if (message) {
        vsnprintf(buffer, sizeof(buffer), message, ap);
        buffer[sizeof(buffer) - 1] = '\0';  /* Ensure trailing NULL */

        output = MsgGetOutput(status);
    }
    else {
        sprintf(buffer, "?????: unknown message number %d", status);
        output = MsgDefaultOutput;
    }

    /* If a function is available, use it to output the error */

    if (output) {
        (*output)(buffer);
    }

    return status;
}


/*+
 * MsgRundown - Rundown Message Module
 *
 * Description:
 * 		Frees up any resources allocated to the message module and resets it to
 *		the initial conditions.
 *
 * Arguments:
 * 		None.
-*/

void MsgRundown(void)
{
	if (m_codeblock) {
		MemFree(m_codeblock);
		m_codeblock = NULL;
	}

	m_numblocks = 0;

	return;
}
